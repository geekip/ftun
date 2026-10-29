#define _POSIX_C_SOURCE 200809L
#include "proxy/protocol/socks5.h"
#include "libs/http/http.h"
#include "libs/tls/tls.h"
#include "platform/clock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *observed_malloc(size_t size);
static void observed_free(void *value);
#define malloc observed_malloc
#define free observed_free
#include "libs/http/http.c"
#undef malloc
#undef free

static ftun_budget_t *observed_budget;
static struct { void *value; size_t bytes; } allocations[32];
static size_t live_bytes, allocation_calls;
static bool fail_allocation;

static void *observed_malloc(size_t size)
{
  ftun_budget_usage_t usage;
  void *value;
  size_t index;
  if (ftun_budget_get_usage(observed_budget, &usage) != FTUN_OK ||
      usage.used_resources.memory_bytes < live_bytes + size) {
    fprintf(stderr, "HTTP allocation was not admitted\n");
    abort();
  }
  allocation_calls++;
  if (fail_allocation) { fail_allocation = false; return NULL; }
  value = malloc(size);
  if (value == NULL) return NULL;
  for (index = 0u; index < 32u; index++) if (allocations[index].value == NULL) {
    allocations[index].value = value;
    allocations[index].bytes = size;
    live_bytes += size;
    return value;
  }
  abort();
}

static void observed_free(void *value)
{
  size_t index;
  if (value == NULL) return;
  for (index = 0u; index < 32u; index++) if (allocations[index].value == value) {
    live_bytes -= allocations[index].bytes;
    allocations[index].value = NULL;
    free(value);
    return;
  }
  abort();
}

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "HTTP memory contract failed at %d: %s\n", __LINE__, #x); \
  return 1; } } while (0)

static int memory_contract(void)
{
  const char *locations[] = {"http://next.test/a", "//next.test/a", "/a", "next"};
  const char *expected[] = {"http://next.test/a", "http://next.test/a",
    "http://base.test/a", "http://base.test/dir/next"};
  const char base[] = "http://base.test/dir/start";
  const char response[] = "HTTP/1.1 302 Found\r\nETag: first\r\nETag: second\r\n"
    "Location: /a\r\nLocation: /b\r\nContent-Length: 0\r\n\r\n";
  const char last_etag[] = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nETag: complete\r\n\r\n";
  uint8_t wire[sizeof(response)];
  ftun_http_fetch_result_t result = {0};
  ftun_reservation_t reservation = (ftun_reservation_t){0}, hold = (ftun_reservation_t){0};
  ftun_budget_usage_t usage;
  char *text = NULL;
  size_t index, calls;
  CHECK(ftun_budget_create(NULL, 65536u, 0u, &observed_budget) == FTUN_OK);
  for (index = 0u; index < 4u; index++) {
    CHECK(ftun_http_redirect_url(observed_budget,
      (ftun_string_t){base, sizeof(base) - 1u}, locations[index], &text, &reservation) == FTUN_OK);
    CHECK(strcmp(text, expected[index]) == 0);
    CHECK(ftun_budget_get_usage(observed_budget, &usage) == FTUN_OK &&
      usage.used_resources.memory_bytes == strlen(text) + 1u && live_bytes == usage.used_resources.memory_bytes);
    observed_free(text); text = NULL;
    ftun_reservation_release(&reservation);
  }
  memcpy(wire, response, sizeof(response));
  CHECK(ftun_http_fetch_parse_response(observed_budget, wire, sizeof(response) - 1u,
    1024u, &result, &text, &reservation) == FTUN_OK);
  CHECK(strcmp(result.etag, "second") == 0 && strcmp(text, "/b") == 0);
  CHECK(ftun_budget_get_usage(observed_budget, &usage) == FTUN_OK &&
    usage.used_resources.memory_bytes == sizeof("second") + sizeof("/b") && usage.used_resources.memory_bytes == live_bytes);
  ftun_http_fetch_release(&result);
  observed_free(text); text = NULL;
  ftun_reservation_release(&reservation);
  memcpy(wire, last_etag, sizeof(last_etag));
  CHECK(ftun_http_fetch_parse_response(observed_budget, wire, sizeof(last_etag) - 1u,
    1024u, &result, &text, &reservation) == FTUN_OK);
  CHECK(strcmp(result.etag, "complete") == 0 && text == NULL && (reservation).budget == NULL);
  ftun_http_fetch_release(&result);
  fail_allocation = true;
  CHECK(ftun_http_redirect_url(observed_budget,
    (ftun_string_t){base, sizeof(base) - 1u}, "/a", &text, &reservation) == FTUN_E_LIMIT);
  CHECK(!fail_allocation && text == NULL && (reservation).budget == NULL && live_bytes == 0u);
  CHECK(ftun_budget_get_usage(observed_budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u);
  CHECK(ftun_budget_reserve(observed_budget, usage.normal_available_resources.memory_bytes, &hold) == FTUN_OK);
  calls = allocation_calls;
  CHECK(ftun_http_redirect_url(observed_budget,
    (ftun_string_t){base, sizeof(base) - 1u}, "/a", &text, &reservation) == FTUN_E_LIMIT);
  memcpy(wire, response, sizeof(response));
  CHECK(ftun_http_fetch_parse_response(observed_budget, wire, sizeof(response) - 1u,
    1024u, &result, &text, &reservation) == FTUN_E_LIMIT);
  CHECK(calls == allocation_calls && result.etag == NULL && (reservation).budget == NULL);
  ftun_http_fetch_release(&result);
  ftun_reservation_release(&hold);
  CHECK(ftun_budget_destroy(&observed_budget) == FTUN_OK);
  return 0;
}

static const char *test_ca;
static size_t context_opens;

ftun_status_t __real_ftun_tls_context_open(const ftun_tls_options_t *options,
  ftun_tls_context_t **out);
ftun_status_t __wrap_ftun_tls_context_open(const ftun_tls_options_t *options,
  ftun_tls_context_t **out)
{
  ftun_tls_options_t copy = *options;
  context_opens++;
  if (test_ca != NULL && test_ca[0] != '\0') copy.ca_file = test_ca;
  return __real_ftun_tls_context_open(&copy, out);
}

int main(int argc, char **argv)
{
  ftun_budget_t *budget = NULL;
  ftun_budget_options_t options = {{8u * 1024u * 1024u, 16u, 4096u}, {128u, 0u, 0u}, {0}};
  ftun_http_fetch_spec_t spec = {0};
  ftun_tls_context_t *shared_context = NULL;
  ftun_http_fetch_result_t result;
  ftun_budget_usage_t before, after;
  ftun_status_t status;
  uint64_t now;
  if (argc != 5) return 2;
  if (memory_contract() != 0) return 5;
  test_ca = argv[4];
  if (ftun_budget_create_resources(NULL, &options, &budget) != FTUN_OK ||
      ftun_budget_get_usage(budget, &before) != FTUN_OK ||
      ftun_monotonic_now(&now) != FTUN_OK) return 3;
  spec.budget = budget;
  observed_budget = budget;
  spec.allow_system_resolver = true;
  spec.url = (ftun_string_t){argv[1], strlen(argv[1])};
  spec.maximum_bytes = 4096u;
  spec.deadline_ms = now + 1500u;
  spec.generation = 7u;
  spec.purpose = FTUN_DIAL_PURPOSE_FRS_UPDATE;
  spec.if_none_match = (ftun_string_t){"\"control-test\"", 14u};
  if (atoi(argv[2]) != 0) {
    spec.use_proxy = true;
    spec.protocol = &ftun_socks5_protocol;
    spec.proxy.kind = FTUN_ADDRESS_IPV4;
    spec.proxy.port = (uint16_t)atoi(argv[2]);
    spec.proxy.address[0] = 127u;
    spec.proxy.address[3] = 1u;
    if (atoi(argv[3]) != 0) {
      spec.proxy_username = (ftun_string_t){"user", 4u};
      spec.proxy_password = (ftun_string_t){"pass", 4u};
    }
  }
  if (!spec.use_proxy && strncmp(argv[1], "https://", 8u) == 0) {
    spec.tls_context = &shared_context;
  }
  status = ftun_http_fetch(&spec, &result);
  if (status == FTUN_OK && shared_context != NULL) {
    unsigned int http_status = result.status;
    ftun_http_fetch_release(&result);
    /* 第二次拉取不能重新读取 CA；context 必须由 owner 保留。 */
    test_ca = "/nonexistent-ftun-context-reuse-ca.pem";
    status = ftun_http_fetch(&spec, &result);
    if (status != FTUN_OK || result.status != http_status ||
        !result.tls_verified || context_opens != 1u) return 8;
  }
  if (ftun_tls_context_destroy(&shared_context) != FTUN_OK) return 9;
  if (ftun_budget_get_usage(budget, &after) != FTUN_OK ||
      after.used_resources.memory_bytes != live_bytes || after.used_resources.memory_bytes != result.length +
        (result.etag == NULL ? 0u : strlen(result.etag) + 1u) ||
      after.used_resources.descriptors != 0u ||
      after.used_resources.queue_slots != 0u) return 6;
  printf("status=%d http=%u tls=%u length=%zu\n", (int)status,
    (unsigned)result.status, result.tls_verified ? 1u : 0u, result.length);
  if (result.length != 0u) (void)fwrite(result.data, 1u, result.length, stdout);
  ftun_http_fetch_release(&result);
  if (live_bytes != 0u) return 7;
  if (ftun_budget_get_usage(budget, &after) != FTUN_OK ||
      after.used_resources.memory_bytes != before.used_resources.memory_bytes || after.metadata_bytes != before.metadata_bytes ||
      ftun_budget_destroy(&budget) != FTUN_OK) return 4;
  observed_budget = NULL;
  return 0;
}
