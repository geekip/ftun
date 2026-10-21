#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "proxy/state/fakeip_snapshot.h"

#include "proxy/state/fakeip_store_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

/* 需求 REQ-PERSIST-001；任务 TASK-STATE-002；目标 0.3.0；验收 TEST-STATE-002。 */
#include <sys/stat.h>
#include <unistd.h>

#define FTUN_SNAPSHOT_HEADER_BYTES 48u
#define FTUN_SNAPSHOT_ENTRY_HEADER_BYTES 8u

static void ftun_snapshot_u16(uint8_t *out, uint16_t value)
{
  out[0] = (uint8_t)(value >> 8u);
  out[1] = (uint8_t)value;
}

static uint16_t ftun_snapshot_load_u16(const uint8_t *value)
{
  return (uint16_t)(((uint16_t)value[0] << 8u) | value[1]);
}

static void ftun_snapshot_u32(uint8_t *out, uint32_t value)
{
  out[0] = (uint8_t)(value >> 24u);
  out[1] = (uint8_t)(value >> 16u);
  out[2] = (uint8_t)(value >> 8u);
  out[3] = (uint8_t)value;
}

static uint32_t ftun_snapshot_load_u32(const uint8_t *value)
{
  return ((uint32_t)value[0] << 24u) |
         ((uint32_t)value[1] << 16u) |
         ((uint32_t)value[2] << 8u) |
         (uint32_t)value[3];
}

static void ftun_snapshot_u64(uint8_t *out, uint64_t value)
{
  size_t index;
  for (index = 0u; index < 8u; index++) {
    out[index] = (uint8_t)(value >> (56u - index * 8u));
  }
}

static uint64_t ftun_snapshot_load_u64(const uint8_t *value)
{
  uint64_t result = 0u;
  size_t index;
  for (index = 0u; index < 8u; index++) result = (result << 8u) | value[index];
  return result;
}

static uint64_t ftun_snapshot_checksum_parts(const uint8_t *header,
                                             const uint8_t *body,
                                             size_t body_length)
{
  uint64_t value = UINT64_C(1469598103934665603);
  static const uint8_t prefix[] = {'F', 'T', 'H', 1u};
  size_t index;
  for (index = 0u; index < sizeof(prefix); index++) {
    value ^= prefix[index];
    value *= UINT64_C(1099511628211);
  }
  for (index = 0u; index < 40u; index++) {
    value ^= header[index];
    value *= UINT64_C(1099511628211);
  }
  for (index = 0u; index < body_length; index++) {
    value ^= body[index];
    value *= UINT64_C(1099511628211);
  }
  return value;
}

static int ftun_snapshot_domain_valid(ftun_string_t domain)
{
  size_t start = 0u;
  size_t index;
  if (domain.data == NULL || domain.length == 0u || domain.length > 253u ||
      domain.data[domain.length - 1u] == '.' ||
      memchr(domain.data, '\0', domain.length) != NULL) return 0;
  for (index = 0u; index <= domain.length; index++) {
    if (index == domain.length || domain.data[index] == '.') {
      size_t length = index - start;
      size_t cursor;
      if (length == 0u || length > 63u || domain.data[start] == '-' ||
          domain.data[index - 1u] == '-') return 0;
      for (cursor = start; cursor < index; cursor++) {
        unsigned char byte = (unsigned char)domain.data[cursor];
        if (!((byte >= (unsigned char)'a' && byte <= (unsigned char)'z') ||
              (byte >= (unsigned char)'0' && byte <= (unsigned char)'9') ||
              byte == (unsigned char)'-')) return 0;
      }
      start = index + 1u;
    }
  }
  return 1;
}

static int ftun_snapshot_domain_equal(ftun_string_t left, ftun_string_t right)
{
  return left.length == right.length &&
         memcmp(left.data, right.data, left.length) == 0;
}

static ftun_status_t ftun_snapshot_validate(
  const ftun_fakeip_snapshot_t *snapshot,
  const ftun_fakeip_store_info_t *info, size_t *out_bytes)
{
  size_t total = FTUN_SNAPSHOT_HEADER_BYTES;
  size_t index;
  size_t previous;
  if (out_bytes != NULL) *out_bytes = 0u;
  if (snapshot == NULL || info == NULL || out_bytes == NULL ||
      memcmp(snapshot->uuid, info->identity.uuid, FTUN_FAKEIP_UUID_BYTES) != 0 ||
      snapshot->sequence > info->sequence ||
      (snapshot->mapping_count != 0u && snapshot->mappings == NULL) ||
      snapshot->mapping_count > UINT32_MAX) return FTUN_E_INVALID;
  for (index = 0u; index < snapshot->mapping_count; index++) {
    const ftun_fakeip_mapping_t *mapping = &snapshot->mappings[index];
    if (mapping->address < info->identity.first_address ||
        mapping->address >= info->reserved_end ||
        !ftun_snapshot_domain_valid(mapping->domain)) return FTUN_E_INVALID;
    if (mapping->domain.length > SIZE_MAX - FTUN_SNAPSHOT_ENTRY_HEADER_BYTES ||
        total > SIZE_MAX - FTUN_SNAPSHOT_ENTRY_HEADER_BYTES -
                mapping->domain.length) return FTUN_E_LIMIT;
    total += FTUN_SNAPSHOT_ENTRY_HEADER_BYTES + mapping->domain.length;
    for (previous = 0u; previous < index; previous++) {
      if (snapshot->mappings[previous].address == mapping->address ||
          ftun_snapshot_domain_equal(snapshot->mappings[previous].domain,
                                     mapping->domain)) return FTUN_E_INVALID;
    }
  }
  *out_bytes = total;
  return FTUN_OK;
}

static void ftun_snapshot_encode(const ftun_fakeip_snapshot_t *snapshot,
                                 uint8_t *data, size_t length)
{
  size_t cursor = FTUN_SNAPSHOT_HEADER_BYTES;
  size_t index;
  memset(data, 0, length);
  memcpy(data, "FTMP", 4u);
  ftun_snapshot_u32(data + 4u, 1u);
  memcpy(data + 8u, snapshot->uuid, FTUN_FAKEIP_UUID_BYTES);
  ftun_snapshot_u64(data + 24u, snapshot->sequence);
  ftun_snapshot_u32(data + 32u, (uint32_t)snapshot->mapping_count);
  for (index = 0u; index < snapshot->mapping_count; index++) {
    const ftun_fakeip_mapping_t *mapping = &snapshot->mappings[index];
    ftun_snapshot_u32(data + cursor, mapping->address);
    ftun_snapshot_u16(data + cursor + 4u, (uint16_t)mapping->domain.length);
    memcpy(data + cursor + FTUN_SNAPSHOT_ENTRY_HEADER_BYTES,
           mapping->domain.data, mapping->domain.length);
    cursor += FTUN_SNAPSHOT_ENTRY_HEADER_BYTES + mapping->domain.length;
  }
  ftun_snapshot_u64(data + 40u,
    ftun_snapshot_checksum_parts(data, data + FTUN_SNAPSHOT_HEADER_BYTES,
                                 length - FTUN_SNAPSHOT_HEADER_BYTES));
}

ftun_status_t ftun_fakeip_snapshot_save(ftun_fakeip_store_t *store,
                                        const ftun_fakeip_snapshot_t *snapshot,
                                        ftun_operation_t **out)
{
  ftun_fakeip_store_info_t info;
  ftun_budget_t *budget = NULL;
  const char *path = NULL;
  ftun_reservation_t *reservation = NULL;
  uint8_t *serialized;
  size_t length;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (store == NULL || snapshot == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_fakeip_store_snapshot_state(store, &path, &budget, &info);
  if (status != FTUN_OK) return status;
  (void)path;
  status = ftun_snapshot_validate(snapshot, &info, &length);
  if (status != FTUN_OK) return status;
  status = ftun_budget_reserve(budget, length, &reservation);
  if (status != FTUN_OK) return status;
  serialized = (uint8_t *)malloc(length);
  if (serialized == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  ftun_snapshot_encode(snapshot, serialized, length);
  status = ftun_fakeip_store_submit_snapshot(
    store, (ftun_bytes_t){serialized, length}, snapshot->sequence, out);
  free(serialized);
  if (ftun_reservation_release(&reservation) != FTUN_OK && status == FTUN_OK) {
    return FTUN_E_STATE_CORRUPT;
  }
  return status;
}

static ftun_status_t ftun_snapshot_read(const char *path, size_t maximum,
                                        ftun_budget_t *budget, uint8_t **out,
                                        size_t *out_length,
                                        ftun_reservation_t **out_reservation)
{
  struct stat info;
  ftun_reservation_t *reservation = NULL;
  uint8_t *data;
  size_t offset = 0u;
  int descriptor;
  ftun_status_t status;
  *out = NULL;
  *out_length = 0u;
  *out_reservation = NULL;
  descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0 || fstat(descriptor, &info) != 0 ||
      !S_ISREG(info.st_mode) || info.st_size < 0 ||
      (uint64_t)info.st_size > (uint64_t)maximum) {
    if (descriptor >= 0) (void)close(descriptor);
    return FTUN_E_STATE_CORRUPT;
  }
  status = ftun_budget_reserve(budget, (size_t)info.st_size, &reservation);
  if (status != FTUN_OK) {
    (void)close(descriptor);
    return status;
  }
  data = (uint8_t *)malloc((size_t)info.st_size);
  if (data == NULL) {
    (void)close(descriptor);
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  while (offset < (size_t)info.st_size) {
    ssize_t result = read(descriptor, data + offset,
                          (size_t)info.st_size - offset);
    if (result < 0 && errno == EINTR) continue;
    if (result <= 0) {
      free(data);
      (void)close(descriptor);
      (void)ftun_reservation_release(&reservation);
      return FTUN_E_STATE_CORRUPT;
    }
    offset += (size_t)result;
  }
  if (close(descriptor) != 0) {
    free(data);
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_IO;
  }
  *out = data;
  *out_length = offset;
  *out_reservation = reservation;
  return FTUN_OK;
}

ftun_status_t ftun_fakeip_snapshot_load(ftun_fakeip_store_t *store,
                                        size_t max_mappings,
                                        ftun_fakeip_snapshot_t **out)
{
  ftun_fakeip_store_info_t info;
  ftun_budget_t *budget = NULL;
  const char *path = NULL;
  ftun_reservation_t *file_reservation = NULL;
  ftun_reservation_t *snapshot_reservation = NULL;
  ftun_fakeip_snapshot_t *snapshot = NULL;
  uint8_t *file = NULL;
  uint8_t *block;
  size_t maximum;
  size_t file_length = 0u;
  size_t mapping_bytes;
  size_t domain_bytes;
  size_t allocation;
  size_t cursor;
  size_t index;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (store == NULL || out == NULL || max_mappings == 0u ||
      max_mappings > UINT32_MAX) return FTUN_E_INVALID;
  if (max_mappings > (SIZE_MAX - FTUN_SNAPSHOT_HEADER_BYTES) /
                       (FTUN_SNAPSHOT_ENTRY_HEADER_BYTES + 253u)) {
    return FTUN_E_LIMIT;
  }
  maximum = FTUN_SNAPSHOT_HEADER_BYTES + max_mappings *
            (FTUN_SNAPSHOT_ENTRY_HEADER_BYTES + 253u);
  status = ftun_fakeip_store_snapshot_state(store, &path, &budget, &info);
  if (status != FTUN_OK) return status;
  status = ftun_snapshot_read(path, maximum, budget, &file, &file_length,
                              &file_reservation);
  if (status != FTUN_OK) return status;
  if (file_length < FTUN_SNAPSHOT_HEADER_BYTES ||
      memcmp(file, "FTMP", 4u) != 0 || ftun_snapshot_load_u32(file + 4u) != 1u ||
      memcmp(file + 8u, info.identity.uuid, FTUN_FAKEIP_UUID_BYTES) != 0 ||
      ftun_snapshot_load_u32(file + 36u) != 0u ||
      ftun_snapshot_load_u64(file + 40u) != ftun_snapshot_checksum_parts(
        file, file + FTUN_SNAPSHOT_HEADER_BYTES,
        file_length - FTUN_SNAPSHOT_HEADER_BYTES)) {
    status = FTUN_E_STATE_CORRUPT;
    goto done;
  }
  if (ftun_snapshot_load_u32(file + 32u) > max_mappings ||
      ftun_snapshot_load_u64(file + 24u) > info.sequence) {
    status = FTUN_E_STATE_CORRUPT;
    goto done;
  }
  mapping_bytes = (size_t)ftun_snapshot_load_u32(file + 32u) *
                  sizeof(ftun_fakeip_mapping_t);
  cursor = FTUN_SNAPSHOT_HEADER_BYTES;
  domain_bytes = 0u;
  for (index = 0u; index < ftun_snapshot_load_u32(file + 32u); index++) {
    uint16_t length;
    if (cursor > file_length - FTUN_SNAPSHOT_ENTRY_HEADER_BYTES) {
      status = FTUN_E_STATE_CORRUPT;
      goto done;
    }
    length = ftun_snapshot_load_u16(file + cursor + 4u);
    if (length == 0u || length > 253u ||
        cursor + FTUN_SNAPSHOT_ENTRY_HEADER_BYTES > file_length - length) {
      status = FTUN_E_STATE_CORRUPT;
      goto done;
    }
    domain_bytes += length + 1u;
    cursor += FTUN_SNAPSHOT_ENTRY_HEADER_BYTES + length;
  }
  if (cursor != file_length || sizeof(*snapshot) > SIZE_MAX - mapping_bytes ||
      sizeof(*snapshot) + mapping_bytes > SIZE_MAX - domain_bytes) {
    status = FTUN_E_STATE_CORRUPT;
    goto done;
  }
  allocation = sizeof(*snapshot) + mapping_bytes + domain_bytes;
  status = ftun_budget_reserve(budget, allocation, &snapshot_reservation);
  if (status != FTUN_OK) goto done;
  block = (uint8_t *)calloc(1u, allocation);
  if (block == NULL) {
    status = FTUN_E_LIMIT;
    goto done;
  }
  snapshot = (ftun_fakeip_snapshot_t *)block;
  snapshot->mappings = (ftun_fakeip_mapping_t *)(block + sizeof(*snapshot));
  snapshot->mapping_count = ftun_snapshot_load_u32(file + 32u);
  snapshot->sequence = ftun_snapshot_load_u64(file + 24u);
  snapshot->reservation = snapshot_reservation;
  snapshot_reservation = NULL;
  snapshot->owned_block = block;
  memcpy(snapshot->uuid, file + 8u, FTUN_FAKEIP_UUID_BYTES);
  block += sizeof(*snapshot) + mapping_bytes;
  cursor = FTUN_SNAPSHOT_HEADER_BYTES;
  for (index = 0u; index < snapshot->mapping_count; index++) {
    uint16_t length = ftun_snapshot_load_u16(file + cursor + 4u);
    snapshot->mappings[index].address = ftun_snapshot_load_u32(file + cursor);
    snapshot->mappings[index].domain.data = (const char *)block;
    snapshot->mappings[index].domain.length = length;
    memcpy(block, file + cursor + FTUN_SNAPSHOT_ENTRY_HEADER_BYTES, length);
    block[length] = '\0';
    block += length + 1u;
    cursor += FTUN_SNAPSHOT_ENTRY_HEADER_BYTES + length;
  }
  status = ftun_snapshot_validate(snapshot, &info, &allocation);
  if (status != FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
    goto done;
  }
  *out = snapshot;
  snapshot = NULL;
  status = FTUN_OK;

done:
  if (snapshot != NULL) {
    snapshot_reservation = snapshot->reservation;
    free(snapshot->owned_block);
  }
  free(file);
  if (ftun_reservation_release(&file_reservation) != FTUN_OK && status == FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
  }
  if (ftun_reservation_release(&snapshot_reservation) != FTUN_OK &&
      status == FTUN_OK) status = FTUN_E_STATE_CORRUPT;
  return status;
}

ftun_status_t ftun_fakeip_snapshot_destroy(ftun_fakeip_snapshot_t **snapshot)
{
  ftun_fakeip_snapshot_t *owned;
  ftun_reservation_t *reservation;
  if (snapshot == NULL) return FTUN_E_INVALID;
  owned = *snapshot;
  if (owned == NULL) return FTUN_OK;
  reservation = owned->reservation;
  free(owned->owned_block);
  *snapshot = NULL;
  return ftun_reservation_release(&reservation);
}
