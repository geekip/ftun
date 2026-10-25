#include "dns/wire.h"
#include "core/budget.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "dns wire contract failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

static const uint8_t query_wire[] = {
  0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
  0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01
};

static const uint8_t response_wire[] = {
  0xbe, 0xef, 0x81, 0x83, 0x00, 0x01, 0x00, 0x01,
  0x00, 0x00, 0x00, 0x02,
  0x03, 'W', 'W', 'W', 0x07, 'E', 'x', 'a', 'm', 'p', 'l', 'e',
  0x03, 'C', 'O', 'M', 0x00, 0x00, 0x01, 0x00, 0x01,
  0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
  0x01, 0x2c, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04,
  0xc0, 0x0c, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00,
  0x00, 0x2a, 0x00, 0x03, 0xaa, 0xbb, 0xcc,
  0x00, 0x00, 0x29, 0x04, 0xd0, 0x01, 0x00, 0x80,
  0x00, 0x00, 0x07, 0xfd, 0xe9, 0x00, 0x03, 0x01,
  0x02, 0x03
};

static const uint8_t cname_wire[] = {
  0x01, 0x02, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
  0x00, 0x00, 0x00, 0x00,
  0x01, 'a', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
  0x03, 'c', 'o', 'm', 0x00, 0x00, 0x05, 0x00, 0x01,
  0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00,
  0x00, 0x3c, 0x00, 0x04, 0x01, 'b', 0xc0, 0x0e
};

static int name_equals(ftun_dns_name_t name,
                       const uint8_t *expected, size_t length)
{
  return name.length == length && memcmp(name.data, expected, length) == 0;
}

static int expect_status(const uint8_t *data, size_t length,
                         ftun_status_t expected)
{
  ftun_dns_message_t *message = (ftun_dns_message_t *)(uintptr_t)1;
  ftun_status_t status = ftun_dns_message_parse(
    (ftun_bytes_t){data, length}, &message);
  if (status != expected || message != NULL) return 0;
  return 1;
}

static int test_query_and_max_name(void)
{
  ftun_dns_message_t *message = NULL;
  uint8_t maximum[FTUN_DNS_HEADER_BYTES + FTUN_DNS_MAX_NAME_BYTES + 4u];
  size_t cursor = FTUN_DNS_HEADER_BYTES;
  size_t label;
  CHECK(ftun_dns_message_parse(
          (ftun_bytes_t){query_wire, sizeof(query_wire)}, &message) == FTUN_OK);
  CHECK(message != NULL && message->id == 0x1234u &&
        message->flags == 0x0100u && message->rcode == 0u);
  CHECK(message->record_count == 0u && message->records != NULL);
  CHECK(message->answer_count == 0u && message->authority_count == 0u &&
        message->additional_count == 0u);
  CHECK(message->question.type == 1u && message->question.class_code == 1u);
  CHECK(name_equals(message->question.name, query_wire + 12u, 17u));
  CHECK(message->wire != query_wire && message->wire_length == sizeof(query_wire));
  CHECK(ftun_dns_message_release(&message) == FTUN_OK && message == NULL);
  CHECK(ftun_dns_message_release(&message) == FTUN_OK);

  memset(maximum, 0, sizeof(maximum));
  maximum[4] = 0u;
  maximum[5] = 1u;
  for (label = 0u; label < 3u; label++) {
    maximum[cursor++] = 63u;
    memset(maximum + cursor, (int)('a' + label), 63u);
    cursor += 63u;
  }
  maximum[cursor++] = 61u;
  memset(maximum + cursor, 'z', 61u);
  cursor += 61u;
  maximum[cursor++] = 0u;
  maximum[cursor++] = 0u;
  maximum[cursor++] = 1u;
  maximum[cursor++] = 0u;
  maximum[cursor++] = 1u;
  CHECK(cursor == sizeof(maximum));
  CHECK(ftun_dns_message_parse((ftun_bytes_t){maximum, sizeof(maximum)},
                               &message) == FTUN_OK);
  CHECK(message->question.name.length == FTUN_DNS_MAX_NAME_BYTES);
  CHECK(ftun_dns_message_release(&message) == FTUN_OK);
  return 0;
}

static int test_records_and_ownership(void)
{
  ftun_dns_message_t *message = NULL;
  const ftun_dns_record_t *record;
  uint8_t mutable_wire[sizeof(response_wire)];
  static const uint8_t a_address[4] = {1u, 2u, 3u, 4u};
  memcpy(mutable_wire, response_wire, sizeof(mutable_wire));
  CHECK(ftun_dns_message_parse(
          (ftun_bytes_t){mutable_wire, sizeof(mutable_wire)}, &message) ==
        FTUN_OK);
  memset(mutable_wire, 0, sizeof(mutable_wire));
  CHECK(message->id == 0xbeefu && message->flags == 0x8183u &&
        message->rcode == 19u);
  CHECK(message->record_count == 3u && message->answer_count == 1u &&
        message->authority_count == 0u && message->additional_count == 2u);

  record = &message->records[0];
  CHECK(record->kind == FTUN_DNS_RECORD_ORDINARY &&
        record->section == FTUN_DNS_SECTION_ANSWER && record->type == 1u &&
        record->class_code == 1u && record->ttl == 300u &&
        record->rdata.length == 4u &&
        memcmp(record->rdata.data, a_address, 4u) == 0);
  CHECK(name_equals(record->name, response_wire + 12u, 17u));

  record = &message->records[1];
  CHECK(record->kind == FTUN_DNS_RECORD_ORDINARY &&
        record->section == FTUN_DNS_SECTION_ADDITIONAL &&
        record->type == 0xff00u && record->class_code == 1u &&
        record->ttl == 42u && record->rdata.length == 3u &&
        record->rdata.data[0] == 0xaau && record->rdata.data[1] == 0xbbu &&
        record->rdata.data[2] == 0xccu);

  record = &message->records[2];
  CHECK(record->kind == FTUN_DNS_RECORD_OPT &&
        record->section == FTUN_DNS_SECTION_ADDITIONAL &&
        record->type == FTUN_DNS_TYPE_OPT && record->class_code == 0u &&
        record->ttl == 0u && record->udp_payload_size == 1232u &&
        record->extended_rcode == 1u && record->edns_version == 0u &&
        record->edns_flags == FTUN_DNS_EDNS_FLAG_DO &&
        record->rdata.length == 7u);
  CHECK(ftun_dns_message_release(&message) == FTUN_OK);
  return 0;
}

static int test_known_rdata(void)
{
  ftun_dns_message_t *message = NULL;
  uint8_t trailing[sizeof(cname_wire) + 1u];
  CHECK(ftun_dns_message_parse(
          (ftun_bytes_t){cname_wire, sizeof(cname_wire)}, &message) == FTUN_OK);
  CHECK(message->record_count == 1u && message->records[0].type == 5u &&
        message->records[0].rdata.length == 4u);
  CHECK(ftun_dns_message_release(&message) == FTUN_OK);
  memcpy(trailing, cname_wire, sizeof(cname_wire));
  trailing[sizeof(cname_wire)] = 0u;
  trailing[41] = 0u;
  trailing[42] = 5u;
  CHECK(expect_status(trailing, sizeof(trailing), FTUN_E_PROTOCOL));
  return 0;
}

static int test_header_and_name_failures(void)
{
  uint8_t copy[sizeof(query_wire) + 1u];
  uint8_t truncated_label[14] = {0};
  uint8_t pointer[18] = {0};
  uint8_t oversized[FTUN_DNS_HEADER_BYTES + 256u + 4u];
  size_t cursor;
  size_t label;
  CHECK(expect_status(query_wire, 11u, FTUN_E_PROTOCOL));
  memcpy(copy, query_wire, sizeof(query_wire));
  copy[4] = 0u;
  copy[5] = 0u;
  CHECK(expect_status(copy, sizeof(query_wire), FTUN_E_PROTOCOL));
  memcpy(copy, query_wire, sizeof(query_wire));
  copy[5] = 2u;
  CHECK(expect_status(copy, sizeof(query_wire), FTUN_E_PROTOCOL));
  memcpy(copy, query_wire, sizeof(query_wire));
  copy[2] |= 0x00u;
  copy[3] |= 0x40u;
  CHECK(expect_status(copy, sizeof(query_wire), FTUN_E_PROTOCOL));
  memcpy(copy, query_wire, sizeof(query_wire));
  copy[12] = 0x40u;
  CHECK(expect_status(copy, sizeof(query_wire), FTUN_E_UNSUPPORTED));
  memcpy(copy, query_wire, sizeof(query_wire));
  copy[12] = 0x80u;
  CHECK(expect_status(copy, sizeof(query_wire), FTUN_E_PROTOCOL));
  memcpy(copy, query_wire, sizeof(query_wire));
  copy[12] = 0xc0u;
  copy[13] = 0x0cu;
  CHECK(expect_status(copy, sizeof(query_wire), FTUN_E_PROTOCOL));
  memcpy(copy, query_wire, sizeof(query_wire));
  copy[12] = 0xc0u;
  copy[13] = 0xffu;
  CHECK(expect_status(copy, sizeof(query_wire), FTUN_E_PROTOCOL));

  truncated_label[5] = 1u;
  truncated_label[12] = 3u;
  truncated_label[13] = 'a';
  CHECK(expect_status(truncated_label, sizeof(truncated_label),
                      FTUN_E_PROTOCOL));
  pointer[5] = 1u;
  pointer[12] = 0xc0u;
  pointer[13] = 0x00u;
  CHECK(expect_status(pointer, sizeof(pointer), FTUN_E_PROTOCOL));
  CHECK(expect_status(pointer, 13u, FTUN_E_PROTOCOL));

  memset(oversized, 0, sizeof(oversized));
  oversized[5] = 1u;
  cursor = FTUN_DNS_HEADER_BYTES;
  for (label = 0u; label < 3u; label++) {
    oversized[cursor++] = 63u;
    memset(oversized + cursor, 'a', 63u);
    cursor += 63u;
  }
  oversized[cursor++] = 62u;
  memset(oversized + cursor, 'b', 62u);
  cursor += 62u;
  oversized[cursor++] = 0u;
  oversized[cursor++] = 0u;
  oversized[cursor++] = 1u;
  oversized[cursor++] = 0u;
  oversized[cursor++] = 1u;
  CHECK(cursor == sizeof(oversized));
  CHECK(expect_status(oversized, sizeof(oversized), FTUN_E_PROTOCOL));

  memcpy(copy, query_wire, sizeof(query_wire));
  copy[sizeof(query_wire)] = 0u;
  CHECK(expect_status(copy, sizeof(copy), FTUN_E_PROTOCOL));
  copy[4] = 0u;
  copy[5] = 1u;
  copy[6] = 1u;
  copy[7] = 1u;
  CHECK(expect_status(copy, sizeof(copy), FTUN_E_LIMIT));
  return 0;
}

static int test_rr_and_opt_failures(void)
{
  uint8_t overrun[sizeof(response_wire)];
  uint8_t option[sizeof(response_wire)];
  static const uint8_t short_a[] = {
    0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x03, 0x01, 0x02, 0x03
  };
  static const uint8_t duplicate_opt[] = {
    0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x29, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00,
    0x00, 0x29, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00
  };
  static const uint8_t opt_answer[] = {
    0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x29, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00
  };
  static const uint8_t compressed_opt_name[] = {
    0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x01, 0x00, 0x01,
    0xc0, 0x0c, 0x00, 0x29, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
  };
  memcpy(overrun, response_wire, sizeof(overrun));
  overrun[43] = 0xffu;
  overrun[44] = 0xffu;
  CHECK(expect_status(overrun, sizeof(overrun), FTUN_E_PROTOCOL));
  CHECK(expect_status(short_a, sizeof(short_a), FTUN_E_PROTOCOL));
  CHECK(expect_status(duplicate_opt, sizeof(duplicate_opt), FTUN_E_PROTOCOL));
  CHECK(expect_status(opt_answer, sizeof(opt_answer), FTUN_E_PROTOCOL));
  CHECK(expect_status(compressed_opt_name, sizeof(compressed_opt_name),
                      FTUN_E_PROTOCOL));
  memcpy(option, response_wire, sizeof(option));
  option[77] = 0u;
  option[78] = 4u;
  CHECK(expect_status(option, sizeof(option), FTUN_E_PROTOCOL));
  return 0;
}

static int test_correlation(void)
{
  static const uint8_t lower_name[] = {
    0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm', 0x00
  };
  ftun_dns_message_t *response = NULL;
  ftun_dns_message_t *query_message = NULL;
  ftun_dns_query_t query;
  ftun_endpoint_t source;
  bool matches = false;
  CHECK(ftun_dns_message_parse(
          (ftun_bytes_t){response_wire, sizeof(response_wire)}, &response) ==
        FTUN_OK);
  CHECK(ftun_dns_message_parse(
          (ftun_bytes_t){query_wire, sizeof(query_wire)}, &query_message) ==
        FTUN_OK);
  memset(&query, 0, sizeof(query));
  query.id = 0xbeefu;
  query.transport = FTUN_DNS_TRANSPORT_UDP;
  query.upstream.kind = FTUN_ADDRESS_IPV4;
  query.upstream.address[0] = 8u;
  query.upstream.address[1] = 8u;
  query.upstream.address[2] = 8u;
  query.upstream.address[3] = 8u;
  query.upstream.port = 53u;
  query.question.name.data = lower_name;
  query.question.name.length = sizeof(lower_name);
  query.question.type = 1u;
  query.question.class_code = 1u;
  source = query.upstream;
  CHECK(ftun_dns_message_matches(response, &query, FTUN_DNS_TRANSPORT_UDP,
                                 &source, &matches) == FTUN_OK && matches);
  query.id++;
  CHECK(ftun_dns_message_matches(response, &query, FTUN_DNS_TRANSPORT_UDP,
                                 &source, &matches) == FTUN_OK && !matches);
  query.id--;
  query.question.type = 28u;
  CHECK(ftun_dns_message_matches(response, &query, FTUN_DNS_TRANSPORT_UDP,
                                 &source, &matches) == FTUN_OK && !matches);
  query.question.type = 1u;
  source.port = 54u;
  CHECK(ftun_dns_message_matches(response, &query, FTUN_DNS_TRANSPORT_UDP,
                                 &source, &matches) == FTUN_OK && !matches);
  source.port = 53u;
  CHECK(ftun_dns_message_matches(response, &query, FTUN_DNS_TRANSPORT_TCP,
                                 &source, &matches) == FTUN_OK && !matches);
  query.id = 0x1234u;
  CHECK(ftun_dns_message_matches(query_message, &query,
                                 FTUN_DNS_TRANSPORT_UDP,
                                 &source, &matches) == FTUN_OK && !matches);
  query.upstream.port = 0u;
  matches = true;
  CHECK(ftun_dns_message_matches(response, &query, FTUN_DNS_TRANSPORT_UDP,
                                 &source, &matches) == FTUN_E_INVALID &&
        !matches);
  CHECK(ftun_dns_message_release(&query_message) == FTUN_OK);
  CHECK(ftun_dns_message_release(&response) == FTUN_OK);
  return 0;
}

static int test_random_inputs(void)
{
  uint8_t data[512];
  uint32_t state = 0x91e10da5u;
  size_t iteration;
  for (iteration = 0u; iteration < 10000u; iteration++) {
    ftun_dns_message_t *message = (ftun_dns_message_t *)(uintptr_t)1;
    size_t length;
    size_t index;
    ftun_status_t status;
    state = state * 1664525u + 1013904223u;
    length = (size_t)(state % (uint32_t)(sizeof(data) + 1u));
    for (index = 0u; index < length; index++) {
      state = state * 1664525u + 1013904223u;
      data[index] = (uint8_t)(state >> 24u);
    }
    status = ftun_dns_message_parse((ftun_bytes_t){data, length}, &message);
    if (status == FTUN_OK) {
      CHECK(message != NULL);
      CHECK(ftun_dns_message_release(&message) == FTUN_OK);
    } else {
      CHECK(message == NULL);
    }
  }
  return 0;
}

/* TASK-DNS-008 / TEST-DNS-008：RFC 固定夹具、压缩边界与关联键。 */
static int test_owned_budget(void)
{
  ftun_budget_t *budget = NULL;
  ftun_dns_message_t *message = NULL;
  ftun_budget_usage_t usage;
  ftun_bytes_t input = {query_wire, sizeof(query_wire)};
  size_t bytes;
  CHECK(ftun_dns_message_parse(input, &message) == FTUN_OK);
  bytes = sizeof(*message) + message->question.name.length + input.length;
  CHECK(ftun_dns_message_release(&message) == FTUN_OK);
  CHECK(ftun_budget_create(NULL, bytes - 1u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_dns_message_parse_with_budget(budget, input, &message) == FTUN_E_LIMIT && message == NULL);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(ftun_budget_create(NULL, bytes, 0u, &budget) == FTUN_OK);
  CHECK(ftun_dns_message_parse_with_budget(budget, input, &message) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == bytes);
  CHECK(ftun_budget_destroy(&budget) == FTUN_E_AGAIN && budget != NULL);
  CHECK(ftun_dns_message_release(&message) == FTUN_OK && message == NULL);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

int main(void)
{
  CHECK(test_owned_budget() == 0);
  ftun_dns_message_t *message = (ftun_dns_message_t *)(uintptr_t)1;
  CHECK(ftun_dns_message_parse((ftun_bytes_t){NULL, 0u}, &message) ==
        FTUN_E_INVALID && message == NULL);
  CHECK(ftun_dns_message_parse(
          (ftun_bytes_t){query_wire, sizeof(query_wire)}, NULL) ==
        FTUN_E_INVALID);
  CHECK(ftun_dns_message_release(NULL) == FTUN_E_INVALID);
  CHECK(test_query_and_max_name() == 0);
  CHECK(test_records_and_ownership() == 0);
  CHECK(test_known_rdata() == 0);
  CHECK(test_header_and_name_failures() == 0);
  CHECK(test_rr_and_opt_failures() == 0);
  CHECK(test_correlation() == 0);
  CHECK(test_random_inputs() == 0);
  return 0;
}
