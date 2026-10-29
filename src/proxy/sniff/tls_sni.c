#include "proxy/sniff/tls_sni.h"
#include "core/limits.h"
#include <stdlib.h>
#include <string.h>

/* 
 * ftun_sniff_tls_sni 有界解析分片 ClientHello，不启动 TLS 库。 */

#define FTUN_SNIFF_TLS_MAX_BYTES 65536u

static uint16_t ftun_tls_u16(const uint8_t *data)
{
  return (uint16_t)(((uint16_t)data[0] << 8u) | data[1]);
}

static uint32_t ftun_tls_u24(const uint8_t *data)
{
  return ((uint32_t)data[0] << 16u) | ((uint32_t)data[1] << 8u) | data[2];
}

static int ftun_tls_domain(ftun_sniff_result_t *out, const uint8_t *name,
                           size_t length)
{
  size_t index;
  size_t label = 0u;
  if (length == 0u || length >= FTUN_SNIFF_DOMAIN_BYTES ||
      name[0] == '.' || name[length - 1u] == '.') return 0;
  for (index = 0u; index < length; index++) {
    unsigned char value = name[index];
    if (value == '.') {
      if (label == 0u || label > 63u) return 0;
      label = 0u;
      out->domain_storage[index] = '.';
      continue;
    }
    if (!((value >= 'a' && value <= 'z') ||
          (value >= 'A' && value <= 'Z') ||
          (value >= '0' && value <= '9') || value == '-')) return 0;
    if ((label == 0u && value == '-') ||
        (index + 1u < length && name[index + 1u] == '.' && value == '-')) {
      return 0;
    }
    out->domain_storage[index] = value >= 'A' && value <= 'Z'
      ? (char)(value + ('a' - 'A')) : (char)value;
    label++;
  }
  if (label == 0u || label > 63u) return 0;
  out->domain_storage[length] = '\0';
  out->domain.data = out->domain_storage;
  out->domain.length = length;
  out->found = true;
  return 1;
}

static ftun_status_t ftun_tls_client_hello(const uint8_t *data, size_t length,
                                            ftun_sniff_result_t *out)
{
  size_t cursor = 0u;
  size_t end;
  if (length < 34u) return FTUN_E_PROTOCOL;
  cursor = 34u;
  if (cursor >= length || data[cursor] > 32u ||
      (size_t)data[cursor] > length - cursor - 1u) return FTUN_E_PROTOCOL;
  cursor += 1u + data[cursor];
  if (length - cursor < 2u) return FTUN_E_PROTOCOL;
  end = ftun_tls_u16(data + cursor);
  cursor += 2u;
  if (end < 2u || (end & 1u) != 0u || end > length - cursor) {
    return FTUN_E_PROTOCOL;
  }
  cursor += end;
  if (cursor >= length || data[cursor] == 0u ||
      (size_t)data[cursor] > length - cursor - 1u) return FTUN_E_PROTOCOL;
  cursor += 1u + data[cursor];
  if (cursor == length) return FTUN_OK;
  if (length - cursor < 2u) return FTUN_E_PROTOCOL;
  end = (size_t)ftun_tls_u16(data + cursor);
  cursor += 2u;
  if (end != length - cursor) return FTUN_E_PROTOCOL;
  end += cursor;
  while (cursor < end) {
    uint16_t type;
    size_t extension_length;
    size_t extension_end;
    if (end - cursor < 4u) return FTUN_E_PROTOCOL;
    type = ftun_tls_u16(data + cursor);
    extension_length = ftun_tls_u16(data + cursor + 2u);
    cursor += 4u;
    if (extension_length > end - cursor) return FTUN_E_PROTOCOL;
    extension_end = cursor + extension_length;
    if (type == 0u) {
      size_t list_end;
      if (extension_length < 2u) return FTUN_E_PROTOCOL;
      list_end = ftun_tls_u16(data + cursor);
      cursor += 2u;
      if (list_end != extension_end - cursor) return FTUN_E_PROTOCOL;
      list_end += cursor;
      while (cursor < list_end) {
        uint8_t name_type;
        size_t name_length;
        if (list_end - cursor < 3u) return FTUN_E_PROTOCOL;
        name_type = data[cursor];
        name_length = ftun_tls_u16(data + cursor + 1u);
        cursor += 3u;
        if (name_length > list_end - cursor) return FTUN_E_PROTOCOL;
        if (name_type == 0u) {
          return ftun_tls_domain(out, data + cursor, name_length)
            ? FTUN_OK : FTUN_E_PROTOCOL;
        }
        cursor += name_length;
      }
      return FTUN_OK;
    }
    cursor = extension_end;
  }
  return FTUN_OK;
}

ftun_status_t ftun_sniff_tls_sni_with_budget(ftun_budget_t *budget, ftun_bytes_t preread, ftun_sniff_result_t *out)
{
  uint8_t *handshake = NULL;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  size_t handshake_length = 0u;
  size_t cursor = 0u;
  size_t wanted = 4u;
  ftun_status_t status = FTUN_OK;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (out == NULL || (preread.length != 0u && preread.data == NULL)) {
    return FTUN_E_INVALID;
  }
  if (preread.length == 0u) {
    out->need_more = true;
    return FTUN_OK;
  }
  if (preread.length > FTUN_SNIFF_TLS_MAX_BYTES) return FTUN_E_PROTOCOL;
  if (budget != NULL) {
    status = ftun_budget_reserve(budget, FTUN_SNIFF_TLS_MAX_BYTES, &reservation);
    if (status != FTUN_OK) return status;
  }
  handshake = (uint8_t *)malloc(FTUN_SNIFF_TLS_MAX_BYTES);
  if (handshake == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  while (cursor < preread.length && handshake_length < wanted) {
    size_t record_length;
    size_t take;
    if (preread.length - cursor < 5u) {
      out->need_more = true;
      goto done;
    }
    if (preread.data[cursor] != 22u || preread.data[cursor + 1u] != 3u) {
      status = handshake_length == 0u ? FTUN_OK : FTUN_E_PROTOCOL;
      goto done;
    }
    record_length = ftun_tls_u16(preread.data + cursor + 3u);
    cursor += 5u;
    if (record_length == 0u) {
      status = FTUN_E_PROTOCOL;
      goto done;
    }
    if (record_length > preread.length - cursor) {
      out->need_more = true;
      goto done;
    }
    take = record_length;
    if (take > FTUN_SNIFF_TLS_MAX_BYTES - handshake_length) {
      status = FTUN_E_PROTOCOL;
      goto done;
    }
    memcpy(handshake + handshake_length, preread.data + cursor, take);
    handshake_length += take;
    cursor += record_length;
    if (handshake_length >= 4u && wanted == 4u) {
      if (handshake[0] != 1u) goto done;
      wanted = 4u + (size_t)ftun_tls_u24(handshake + 1u);
      if (wanted > FTUN_SNIFF_TLS_MAX_BYTES || wanted < 4u) {
        status = FTUN_E_PROTOCOL;
        goto done;
      }
    }
  }
  if (handshake_length < wanted) {
    out->need_more = true;
    goto done;
  }
  status = ftun_tls_client_hello(handshake + 4u, wanted - 4u, out);

done:
  free(handshake);
  if (ftun_reservation_release(&reservation) != FTUN_OK) status = FTUN_E_STATE_CORRUPT;
  if (status != FTUN_OK) memset(out, 0, sizeof(*out));
  return status;
}

ftun_status_t ftun_sniff_tls_sni(ftun_bytes_t preread, ftun_sniff_result_t *out)
{
  return ftun_sniff_tls_sni_with_budget(NULL, preread, out);
}
