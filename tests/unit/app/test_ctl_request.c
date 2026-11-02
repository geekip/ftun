#define _POSIX_C_SOURCE 200809L
#include "app/control/request.h"
#include "core/config/document.h"
#include "core/limits.h"
#include "platform/clock.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "control request failed at %d: %s\n", __LINE__, #x); abort(); } } while (0)

static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static atomic_bool entered;
static bool released;
static ftun_budget_t *budget;

cJSON *__real_cJSON_ParseWithLengthOpts(const char *, size_t, const char **, cJSON_bool);
cJSON *__wrap_cJSON_ParseWithLengthOpts(const char *value, size_t length,
  const char **end, cJSON_bool terminated)
{
  if (strcmp(value, "{\"hold\":true}") == 0) {
    CHECK(pthread_mutex_lock(&gate) == 0);
    atomic_store(&entered, true);
    while (!released) CHECK(pthread_cond_wait(&condition, &gate) == 0);
    CHECK(pthread_mutex_unlock(&gate) == 0);
  }
  return __real_cJSON_ParseWithLengthOpts(value, length, end, terminated);
}

static uint64_t now(void)
{
  uint64_t value;
  CHECK(ftun_monotonic_now(&value) == FTUN_OK);
  return value;
}

static ftun_status_t parse(const char *text, ftun_ctl_request_t *out)
{
  ftun_budget_usage_t usage;
  ftun_status_t status = ftun_ctl_request_parse(budget,
    (ftun_bytes_t){(const uint8_t *)text, strlen(text)}, out);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
  CHECK(usage.used_resources.memory_bytes == 0u);
  return status;
}

static void *hold_parser(void *unused)
{
  static const char text[] = "{\"hold\":true}";
  ftun_config_json_t document;
  (void)unused;
  CHECK(ftun_config_json_open(NULL, (ftun_bytes_t){(const uint8_t *)text,
    sizeof(text) - 1u}, &document) == FTUN_OK);
  ftun_config_json_close(&document);
  return NULL;
}

int main(void)
{
  static const struct { const char *name; ftun_ctl_operation_t operation; uint32_t timeout; } valid[] = {
    {"status", FTUN_CTL_STATUS, 5000u}, {"dns.status", FTUN_CTL_DNS_STATUS, 5000u},
    {"proxy.status", FTUN_CTL_PROXY_STATUS, 5000u}, {"reload", FTUN_CTL_RELOAD, 30000u},
    {"stop", FTUN_CTL_STOP, 15000u}
  };
  static const char *const invalid[] = {
    "{}", "[]", "null", "{\"op\":true}", "{\"op\":\"unknown\"}",
    "{\"op\":\"status\",\"unknown\":1}", "{\"op\":\"status\",\"op\":\"stop\"}",
    "{\"op\":\"status\",\"timeout_ms\":0}", "{\"op\":\"stop\",\"timeout_ms\":-1}",
    "{\"op\":\"stop\",\"timeout_ms\":1.5}", "{\"op\":\"stop\",\"timeout_ms\":3600001}",
    "{\"op\":\"stop\",\"timeout_ms\":1e1000}", "{\"op\":\"stop\",\"timeout_ms\":true}",
    "{\"op\":\"stop\",\"timeout_ms\":\"1\"}", "{\"op\":\"status\",\"boot\":1}",
    "{\"op\":\"status\",\"boot\":\"\"}", "{\"op\":\"status\",\"boot\":\"0123456789abcdeg\"}",
    "{\"op\":\"status\",\"boot\":\"0123456789abcdef0\"}",
    "{\"op\":\"status\\u0000stop\"}", "{\"op\\u0000\":\"status\"}",
    "{\"op\":\"status\"}x", "{\"op\":\"status\"}\n", "{\"op\":\"status\"}\r",
    "{\"op\":\"\xff\"}", "{\"op\":\"status\",\"boot\":\"\\ud800\"}"
  };
  ftun_ctl_request_t request;
  ftun_reservation_t hold = {0};
  ftun_budget_usage_t usage;
  char text[128], padded[FTUN_CTL_REQUEST_MAX + 1u];
  pthread_t thread;
  uint64_t deadline, started;
  size_t i;
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  for (i = 0u; i < sizeof(valid) / sizeof(valid[0]); i++) {
    CHECK(snprintf(text, sizeof(text), "{\"op\":\"%s\"}", valid[i].name) > 0);
    CHECK(parse(text, &request) == FTUN_OK && request.operation == valid[i].operation &&
      request.timeout_ms == valid[i].timeout && !request.boot_present);
  }
  CHECK(parse("{\"op\":\"reload\",\"timeout_ms\":0,\"boot\":\"FEDCBA9876543210\"}", &request) == FTUN_OK);
  CHECK(request.operation == FTUN_CTL_RELOAD && request.timeout_ms == 0u &&
    request.boot_present && request.boot == UINT64_C(0xfedcba9876543210));
  CHECK(parse("{\"op\":\"stop\",\"timeout_ms\":3600000}", &request) == FTUN_OK && request.timeout_ms == 3600000u);
  CHECK(parse("{\"op\":\"st\\u0061tus\",\"timeout_ms\":1}", &request) == FTUN_OK && request.timeout_ms == 1u);
  for (i = 0u; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    memset(&request, 0xa5, sizeof(request));
    CHECK(parse(invalid[i], &request) == FTUN_E_INVALID && request.operation == 0 &&
      request.timeout_ms == 0u && !request.boot_present && request.boot == 0u);
  }
  memset(padded, ' ', sizeof(padded));
  memcpy(padded, "{\"op\":\"status\"}", 15u);
  CHECK(ftun_ctl_request_parse(budget, (ftun_bytes_t){(const uint8_t *)padded,
    FTUN_CTL_REQUEST_MAX}, &request) == FTUN_OK);
  CHECK(ftun_ctl_request_parse(budget, (ftun_bytes_t){(const uint8_t *)padded,
    sizeof(padded)}, &request) == FTUN_E_LIMIT && request.operation == 0);
  CHECK(ftun_ctl_request_parse(budget, (ftun_bytes_t){NULL, 0u}, &request) == FTUN_E_INVALID);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
  CHECK(ftun_budget_reserve(budget, usage.normal_available_resources.memory_bytes, &hold) == FTUN_OK);
  CHECK(ftun_ctl_request_parse(budget, (ftun_bytes_t){(const uint8_t *)"{\"op\":\"status\"}", 15u},
    &request) == FTUN_E_LIMIT && request.operation == 0);
  ftun_reservation_release(&hold);
  atomic_init(&entered, false);
  CHECK(pthread_create(&thread, NULL, hold_parser, NULL) == 0);
  deadline = now() + 1000u;
  while (!atomic_load(&entered)) {
    struct timespec delay = {0, 1000000};
    CHECK(now() < deadline && nanosleep(&delay, NULL) == 0);
  }
  started = now();
  CHECK(parse("{\"op\":\"status\"}", &request) == FTUN_E_AGAIN && request.operation == 0);
  CHECK(now() - started < 100u);
  CHECK(pthread_mutex_lock(&gate) == 0);
  released = true;
  CHECK(pthread_cond_signal(&condition) == 0);
  CHECK(pthread_mutex_unlock(&gate) == 0);
  CHECK(pthread_join(thread, NULL) == 0);
  CHECK(parse("{\"op\":\"status\"}", &request) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(pthread_cond_destroy(&condition) == 0 && pthread_mutex_destroy(&gate) == 0);
  puts("Control request: strict JSON, boot guards, deadlines, bounded admission and nonblocking parse passed");
  return 0;
}
