#include "util/endpoint.h"
#include "util/dnswire.h"

#include <string.h>

typedef struct {
  uint16_t answer_count;
  uint16_t authority_count;
  uint16_t additional_count;
  size_t record_count;
} ftun_dns_layout_t;

static uint16_t ftun_dns_u16(const uint8_t *data)
{
  return (uint16_t)(((uint16_t)data[0] << 8u) | (uint16_t)data[1]);
}

static uint32_t ftun_dns_u32(const uint8_t *data)
{
  return ((uint32_t)data[0] << 24u) | ((uint32_t)data[1] << 16u) |
         ((uint32_t)data[2] << 8u) | (uint32_t)data[3];
}

static ftun_status_t ftun_dns_layout(ftun_bytes_t wire,
                                     ftun_dns_layout_t *layout)
{
  uint16_t question_count;
  size_t records;
  if (wire.data == NULL || layout == NULL) return FTUN_E_INVALID;
  if (wire.length < FTUN_DNS_HEADER_BYTES) return FTUN_E_PROTOCOL;
  if (wire.length > FTUN_DNS_MAX_MESSAGE_BYTES) return FTUN_E_LIMIT;
  question_count = ftun_dns_u16(wire.data + 4u);
  if (question_count != 1u) return FTUN_E_PROTOCOL;
  layout->answer_count = ftun_dns_u16(wire.data + 6u);
  layout->authority_count = ftun_dns_u16(wire.data + 8u);
  layout->additional_count = ftun_dns_u16(wire.data + 10u);
  records = (size_t)layout->answer_count +
            (size_t)layout->authority_count +
            (size_t)layout->additional_count;
  if (records > FTUN_DNS_MAX_RECORDS) return FTUN_E_LIMIT;
  layout->record_count = records;
  /* Header Z 位仍保留，AD/CD 使用各自已分配的位。 */
  if ((ftun_dns_u16(wire.data + 2u) & 0x0040u) != 0u) {
    return FTUN_E_PROTOCOL;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_dns_name_decode(
  ftun_bytes_t wire, size_t start, size_t source_limit,
  uint8_t *output, size_t output_capacity,
  size_t *out_consumed, size_t *out_length)
{
  size_t cursor = start;
  size_t consumed = 0u;
  size_t length = 0u;
  size_t steps = 0u;
  int jumped = 0;
  if (out_consumed != NULL) *out_consumed = 0u;
  if (out_length != NULL) *out_length = 0u;
  if (wire.data == NULL || start >= source_limit ||
      source_limit > wire.length || out_consumed == NULL ||
      out_length == NULL || (output == NULL && output_capacity != 0u)) {
    return FTUN_E_INVALID;
  }
  for (;;) {
    size_t limit = jumped ? wire.length : source_limit;
    uint8_t value;
    if (cursor >= limit || ++steps > wire.length) return FTUN_E_PROTOCOL;
    value = wire.data[cursor];
    if (value == 0u) {
      if (length >= FTUN_DNS_MAX_NAME_BYTES) return FTUN_E_PROTOCOL;
      if (output != NULL) {
        if (length >= output_capacity) return FTUN_E_LIMIT;
        output[length] = 0u;
      }
      length++;
      if (!jumped) consumed = cursor + 1u - start;
      *out_consumed = consumed;
      *out_length = length;
      return FTUN_OK;
    }
    if ((value & 0xc0u) == 0xc0u) {
      size_t target;
      if (cursor + 2u > limit) return FTUN_E_PROTOCOL;
      target = ((size_t)(value & 0x3fu) << 8u) |
               (size_t)wire.data[cursor + 1u];
      /* RFC 1035 指针引用先前出现的名称，向后约束同时消除环。 */
      if (target < FTUN_DNS_HEADER_BYTES || target >= cursor ||
          target >= start || target >= wire.length) return FTUN_E_PROTOCOL;
      if (!jumped) consumed = cursor + 2u - start;
      jumped = 1;
      cursor = target;
      continue;
    }
    if ((value & 0xc0u) == 0x40u) return FTUN_E_UNSUPPORTED;
    if ((value & 0xc0u) != 0u || value > 63u) return FTUN_E_PROTOCOL;
    if (cursor + 1u + (size_t)value > limit ||
        length + 1u + (size_t)value >= FTUN_DNS_MAX_NAME_BYTES) {
      return FTUN_E_PROTOCOL;
    }
    if (output != NULL) {
      if (length + 1u + (size_t)value > output_capacity) {
        return FTUN_E_LIMIT;
      }
      output[length] = value;
      memcpy(output + length + 1u, wire.data + cursor + 1u,
             (size_t)value);
    }
    length += 1u + (size_t)value;
    cursor += 1u + (size_t)value;
  }
}

static ftun_status_t ftun_dns_name_rdata(ftun_bytes_t wire, size_t start,
                                         size_t end, size_t *out_consumed)
{
  uint8_t name[FTUN_DNS_MAX_NAME_BYTES];
  size_t consumed = 0u;
  size_t length = 0u;
  ftun_status_t status = ftun_dns_name_decode(
    wire, start, end, name, sizeof(name), &consumed, &length);
  (void)length;
  if (out_consumed != NULL) *out_consumed =
    status == FTUN_OK ? consumed : 0u;
  return status;
}

static ftun_status_t ftun_dns_validate_options(ftun_bytes_t wire,
                                                size_t start, size_t end)
{
  size_t cursor = start;
  while (cursor < end) {
    size_t length;
    if (end - cursor < 4u) return FTUN_E_PROTOCOL;
    length = (size_t)ftun_dns_u16(wire.data + cursor + 2u);
    cursor += 4u;
    if (length > end - cursor) return FTUN_E_PROTOCOL;
    cursor += length;
  }
  return cursor == end ? FTUN_OK : FTUN_E_PROTOCOL;
}

static ftun_status_t ftun_dns_validate_rdata(ftun_bytes_t wire,
                                              uint16_t type,
                                              uint16_t class_code,
                                              size_t start, size_t end)
{
  size_t consumed;
  ftun_status_t status;
  size_t length = end - start;
  if (class_code == 1u && type == 1u) {
    return length == 4u ? FTUN_OK : FTUN_E_PROTOCOL;
  }
  if (class_code == 1u && type == 28u) {
    return length == 16u ? FTUN_OK : FTUN_E_PROTOCOL;
  }
  if (type == 2u || type == 5u || type == 12u || type == 39u) {
    status = ftun_dns_name_rdata(wire, start, end, &consumed);
    return status == FTUN_OK && consumed == length ?
      FTUN_OK : (status == FTUN_OK ? FTUN_E_PROTOCOL : status);
  }
  if (type == 15u) {
    if (length < 3u) return FTUN_E_PROTOCOL;
    status = ftun_dns_name_rdata(wire, start + 2u, end, &consumed);
    return status == FTUN_OK && consumed == length - 2u ?
      FTUN_OK : (status == FTUN_OK ? FTUN_E_PROTOCOL : status);
  }
  if (type == 33u) {
    if (length < 7u) return FTUN_E_PROTOCOL;
    status = ftun_dns_name_rdata(wire, start + 6u, end, &consumed);
    return status == FTUN_OK && consumed == length - 6u ?
      FTUN_OK : (status == FTUN_OK ? FTUN_E_PROTOCOL : status);
  }
  if (type == 6u) {
    size_t second;
    if (length < 22u) return FTUN_E_PROTOCOL;
    status = ftun_dns_name_rdata(wire, start, end, &consumed);
    if (status != FTUN_OK) return status;
    second = start + consumed;
    if (second >= end) return FTUN_E_PROTOCOL;
    status = ftun_dns_name_rdata(wire, second, end, &consumed);
    if (status != FTUN_OK) return status;
    return second + consumed <= end && end - (second + consumed) == 20u ?
      FTUN_OK : FTUN_E_PROTOCOL;
  }
  return FTUN_OK;
}

static ftun_dns_section_t ftun_dns_section_for(
  const ftun_dns_layout_t *layout, size_t index)
{
  if (index < (size_t)layout->answer_count) return FTUN_DNS_SECTION_ANSWER;
  if (index < (size_t)layout->answer_count +
              (size_t)layout->authority_count) {
    return FTUN_DNS_SECTION_AUTHORITY;
  }
  return FTUN_DNS_SECTION_ADDITIONAL;
}

static ftun_status_t ftun_dns_parse_sections(
  ftun_bytes_t wire, const ftun_dns_layout_t *layout,
  ftun_dns_message_t *message, uint8_t *name_storage,
  size_t name_capacity, size_t *out_name_bytes)
{
  uint8_t temporary_name[FTUN_DNS_MAX_NAME_BYTES];
  size_t cursor = FTUN_DNS_HEADER_BYTES;
  size_t name_bytes = 0u;
  size_t consumed;
  size_t name_length;
  size_t index;
  size_t opt_count = 0u;
  uint8_t extended_rcode = 0u;
  ftun_status_t status;
  uint8_t *name_output = message == NULL ? temporary_name : name_storage;
  size_t output_capacity = message == NULL ? sizeof(temporary_name) : name_capacity;

  status = ftun_dns_name_decode(wire, cursor, wire.length,
                                name_output, output_capacity,
                                &consumed, &name_length);
  if (status != FTUN_OK) return status;
  if (message != NULL) {
    message->question.name.data = name_storage;
    message->question.name.length = name_length;
  }
  cursor += consumed;
  if (wire.length - cursor < 4u) return FTUN_E_PROTOCOL;
  if (message != NULL) {
    message->question.type = ftun_dns_u16(wire.data + cursor);
    message->question.class_code = ftun_dns_u16(wire.data + cursor + 2u);
    name_storage += name_length;
    name_capacity -= name_length;
  }
  if (name_length > SIZE_MAX - name_bytes) return FTUN_E_LIMIT;
  name_bytes += name_length;
  cursor += 4u;

  for (index = 0u; index < layout->record_count; index++) {
    size_t name_start = cursor;
    size_t rdata_start;
    size_t rdata_end;
    uint16_t type;
    uint16_t class_code;
    uint32_t ttl;
    uint16_t rdata_length;
    ftun_dns_section_t section = ftun_dns_section_for(layout, index);
    ftun_dns_record_t *record = message == NULL ? NULL :
      (ftun_dns_record_t *)&message->records[index];
    name_output = message == NULL ? temporary_name : name_storage;
    output_capacity = message == NULL ? sizeof(temporary_name) : name_capacity;
    status = ftun_dns_name_decode(wire, cursor, wire.length,
                                  name_output, output_capacity,
                                  &consumed, &name_length);
    if (status != FTUN_OK) return status;
    cursor += consumed;
    if (wire.length - cursor < 10u) return FTUN_E_PROTOCOL;
    type = ftun_dns_u16(wire.data + cursor);
    class_code = ftun_dns_u16(wire.data + cursor + 2u);
    ttl = ftun_dns_u32(wire.data + cursor + 4u);
    rdata_length = ftun_dns_u16(wire.data + cursor + 8u);
    cursor += 10u;
    rdata_start = cursor;
    if ((size_t)rdata_length > wire.length - cursor) return FTUN_E_PROTOCOL;
    rdata_end = cursor + (size_t)rdata_length;
    if (type == FTUN_DNS_TYPE_OPT) {
      if (section != FTUN_DNS_SECTION_ADDITIONAL || opt_count != 0u ||
          consumed != 1u || wire.data[name_start] != 0u ||
          name_length != 1u || name_output[0] != 0u) {
        return FTUN_E_PROTOCOL;
      }
      status = ftun_dns_validate_options(wire, rdata_start, rdata_end);
      if (status != FTUN_OK) return status;
      opt_count++;
      extended_rcode = (uint8_t)(ttl >> 24u);
    } else {
      status = ftun_dns_validate_rdata(wire, type, class_code,
                                       rdata_start, rdata_end);
      if (status != FTUN_OK) return status;
    }
    if (record != NULL) {
      record->section = section;
      record->name.data = name_storage;
      record->name.length = name_length;
      record->type = type;
      record->rdata.data = wire.data + rdata_start;
      record->rdata.length = (size_t)rdata_length;
      if (type == FTUN_DNS_TYPE_OPT) {
        record->kind = FTUN_DNS_RECORD_OPT;
        record->udp_payload_size = class_code;
        record->extended_rcode = (uint8_t)(ttl >> 24u);
        record->edns_version = (uint8_t)(ttl >> 16u);
        record->edns_flags = (uint16_t)ttl;
      } else {
        record->kind = FTUN_DNS_RECORD_ORDINARY;
        record->class_code = class_code;
        record->ttl = ttl;
      }
      name_storage += name_length;
      name_capacity -= name_length;
    }
    if (name_length > SIZE_MAX - name_bytes) return FTUN_E_LIMIT;
    name_bytes += name_length;
    cursor = rdata_end;
  }
  if (cursor != wire.length) return FTUN_E_PROTOCOL;
  if (message != NULL) {
    message->rcode = (uint16_t)((uint16_t)(extended_rcode << 4u) |
                                (message->flags & 0x000fu));
  }
  *out_name_bytes = name_bytes;
  return FTUN_OK;
}

/* 有界 DNS wire parser。 */
ftun_status_t ftun_dnswire_measure(ftun_bytes_t wire, size_t *out_size)
{
  ftun_dns_layout_t layout;
  size_t name_bytes = 0, records_bytes, allocation_size;
  ftun_status_t status;
  if (out_size == NULL) return FTUN_E_INVALID;
  *out_size = 0;
  memset(&layout, 0, sizeof(layout));
  status = ftun_dns_layout(wire, &layout);
  if (status != FTUN_OK) return status;
  status = ftun_dns_parse_sections(wire, &layout, NULL, NULL, 0u,
                                   &name_bytes);
  if (status != FTUN_OK) return status;
  if (layout.record_count > SIZE_MAX / sizeof(ftun_dns_record_t)) return FTUN_E_LIMIT;
  records_bytes = layout.record_count * sizeof(ftun_dns_record_t);
  if (records_bytes > SIZE_MAX - sizeof(ftun_dns_message_t) ||
      name_bytes > SIZE_MAX - sizeof(ftun_dns_message_t) - records_bytes ||
      wire.length > SIZE_MAX - sizeof(ftun_dns_message_t) - records_bytes - name_bytes) {
    return FTUN_E_LIMIT;
  }
  allocation_size = sizeof(ftun_dns_message_t) + records_bytes + name_bytes + wire.length;
  *out_size = allocation_size;
  return FTUN_OK;
}
ftun_status_t ftun_dnswire_decode(ftun_bytes_t wire, void *storage, size_t capacity)
{
  ftun_dns_layout_t layout;
  ftun_dns_message_t *message = storage;
  ftun_dns_record_t *records;
  uint8_t *names, *owned_wire;
  size_t allocation_size, records_bytes, name_bytes, checked_name_bytes;
  ftun_status_t status = ftun_dnswire_measure(wire, &allocation_size);
  if (status != FTUN_OK) return status;
  if (storage == NULL || capacity < allocation_size) return FTUN_E_LIMIT;
  status = ftun_dns_layout(wire, &layout);
  if (status != FTUN_OK) return status;
  records_bytes = layout.record_count * sizeof(*records);
  name_bytes = allocation_size - sizeof(*message) - records_bytes - wire.length;
  memset(message, 0, sizeof(*message));
  records = (ftun_dns_record_t *)(message + 1);
  names = (uint8_t *)records + records_bytes;
  owned_wire = names + name_bytes;
  memcpy(owned_wire, wire.data, wire.length);
  message->id = ftun_dns_u16(owned_wire);
  message->flags = ftun_dns_u16(owned_wire + 2u);
  message->records = records;
  message->record_count = layout.record_count;
  message->answer_count = layout.answer_count;
  message->authority_count = layout.authority_count;
  message->additional_count = layout.additional_count;
  message->wire = owned_wire;
  message->wire_length = wire.length;
  status = ftun_dns_parse_sections(
    (ftun_bytes_t){owned_wire, wire.length}, &layout, message,
    names, name_bytes, &checked_name_bytes);
  return status == FTUN_OK && checked_name_bytes != name_bytes ? FTUN_E_STATE_CORRUPT : status;
}
static int ftun_dns_plain_name_valid(ftun_dns_name_t name)
{
  size_t cursor = 0u;
  if (name.data == NULL || name.length == 0u ||
      name.length > FTUN_DNS_MAX_NAME_BYTES) return 0;
  while (cursor < name.length) {
    uint8_t length = name.data[cursor++];
    if (length == 0u) return cursor == name.length;
    if (length > 63u || (size_t)length > name.length - cursor) return 0;
    cursor += (size_t)length;
  }
  return 0;
}

static uint8_t ftun_dns_fold(uint8_t value)
{
  return value >= (uint8_t)'A' && value <= (uint8_t)'Z' ?
         (uint8_t)(value + ((uint8_t)'a' - (uint8_t)'A')) : value;
}

static int ftun_dns_name_equal(ftun_dns_name_t left, ftun_dns_name_t right)
{
  size_t index;
  if (left.length != right.length) return 0;
  for (index = 0u; index < left.length; index++) {
    if (ftun_dns_fold(left.data[index]) != ftun_dns_fold(right.data[index])) {
      return 0;
    }
  }
  return 1;
}

static int ftun_dns_endpoint_valid(const ftun_endpoint_t *endpoint)
{
  return endpoint != NULL && ftun_endpoint_is_ip(endpoint) &&
         endpoint->port != 0u && endpoint->domain.length == 0u;
}

static int ftun_dns_endpoint_equal(const ftun_endpoint_t *left, const ftun_endpoint_t *right)
{
  return ftun_endpoint_equal(left, right);
}

ftun_status_t ftun_dns_message_matches(
  const ftun_dns_message_t *message, const ftun_dns_query_t *query,
  ftun_dns_transport_t transport, const ftun_endpoint_t *source,
  bool *out_matches)
{
  if (out_matches != NULL) *out_matches = false;
  if (message == NULL || query == NULL || out_matches == NULL ||
      !ftun_dns_plain_name_valid(query->question.name) ||
      !ftun_dns_endpoint_valid(&query->upstream) ||
      !ftun_dns_endpoint_valid(source) ||
      (query->transport != FTUN_DNS_TRANSPORT_UDP &&
       query->transport != FTUN_DNS_TRANSPORT_TCP) ||
      (transport != FTUN_DNS_TRANSPORT_UDP &&
       transport != FTUN_DNS_TRANSPORT_TCP)) return FTUN_E_INVALID;
  *out_matches = (message->flags & 0x8000u) != 0u &&
                 message->id == query->id &&
                 query->transport == transport &&
                 ftun_dns_endpoint_equal(&query->upstream, source) &&
                 message->question.type == query->question.type &&
                 message->question.class_code == query->question.class_code &&
                 ftun_dns_name_equal(message->question.name,
                                     query->question.name);
  return FTUN_OK;
}
