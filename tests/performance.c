#define _POSIX_C_SOURCE 200809L
#include "proxy/sniff/http_host.h"
#include "proxy/sniff/tls_sni.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define FTUN_PERF_RUNS 5u
#define FTUN_PERF_SAMPLES 4096u
#define FTUN_PERF_ITERATIONS 100000u
#define FTUN_PERF_MIN_OPS_PER_SECOND 50000.0
#define FTUN_PERF_MAX_CPU_NS_PER_OP 20000.0
#define FTUN_PERF_MAX_P99_NS UINT64_C(200000)

typedef ftun_status_t (*ftun_perf_parse_fn)(ftun_bytes_t, ftun_sniff_result_t *);

static uint64_t ftun_perf_now(clockid_t clock_id)
{
  struct timespec value;
  if (clock_gettime(clock_id, &value) != 0) return 0u;
  return (uint64_t)value.tv_sec * UINT64_C(1000000000) +
         (uint64_t)value.tv_nsec;
}

static int ftun_perf_compare(const void *left, const void *right)
{
  uint64_t a = *(const uint64_t *)left;
  uint64_t b = *(const uint64_t *)right;
  return a < b ? -1 : a > b ? 1 : 0;
}

static int ftun_perf_compare_double(const void *left, const void *right)
{
  double a = *(const double *)left;
  double b = *(const double *)right;
  return a < b ? -1 : a > b ? 1 : 0;
}

static size_t ftun_perf_client_hello(uint8_t *out, const char *name)
{
  uint8_t body[512];
  uint8_t handshake[520];
  size_t name_length = strlen(name);
  size_t cursor = 0u;
  size_t handshake_length;
  body[cursor++] = 3u;
  body[cursor++] = 3u;
  memset(body + cursor, 0x5au, 32u);
  cursor += 32u;
  body[cursor++] = 0u;
  body[cursor++] = 0u;
  body[cursor++] = 2u;
  body[cursor++] = 0x13u;
  body[cursor++] = 0x01u;
  body[cursor++] = 1u;
  body[cursor++] = 0u;
  body[cursor++] = 0u;
  body[cursor++] = (uint8_t)(9u + name_length);
  body[cursor++] = 0u;
  body[cursor++] = 0u;
  body[cursor++] = 0u;
  body[cursor++] = (uint8_t)(5u + name_length);
  body[cursor++] = 0u;
  body[cursor++] = (uint8_t)(3u + name_length);
  body[cursor++] = 0u;
  body[cursor++] = (uint8_t)(name_length >> 8u);
  body[cursor++] = (uint8_t)name_length;
  memcpy(body + cursor, name, name_length);
  cursor += name_length;
  handshake[0] = 1u;
  handshake[1] = (uint8_t)(cursor >> 16u);
  handshake[2] = (uint8_t)(cursor >> 8u);
  handshake[3] = (uint8_t)cursor;
  memcpy(handshake + 4u, body, cursor);
  handshake_length = cursor + 4u;
  out[0] = 22u;
  out[1] = 3u;
  out[2] = 3u;
  out[3] = (uint8_t)(handshake_length >> 8u);
  out[4] = (uint8_t)handshake_length;
  memcpy(out + 5u, handshake, handshake_length);
  return handshake_length + 5u;
}

static int ftun_perf_run(const char *name, ftun_perf_parse_fn parse,
                         ftun_bytes_t input)
{
  uint64_t samples[FTUN_PERF_SAMPLES];
  size_t run;
  double throughputs[FTUN_PERF_RUNS];
  double cpu_costs[FTUN_PERF_RUNS];
  uint64_t p99_max = 0u;
  for (run = 0u; run < FTUN_PERF_RUNS; run++) {
    ftun_sniff_result_t result;
    uint64_t wall_start;
    uint64_t wall_end;
    uint64_t cpu_start;
    uint64_t cpu_end;
    size_t index;
    for (index = 0u; index < 1000u; index++) {
      if (parse(input, &result) != FTUN_OK || !result.found) return 0;
    }
    wall_start = ftun_perf_now(CLOCK_MONOTONIC);
    cpu_start = ftun_perf_now(CLOCK_PROCESS_CPUTIME_ID);
    for (index = 0u; index < FTUN_PERF_ITERATIONS; index++) {
      if (parse(input, &result) != FTUN_OK || !result.found) return 0;
    }
    cpu_end = ftun_perf_now(CLOCK_PROCESS_CPUTIME_ID);
    wall_end = ftun_perf_now(CLOCK_MONOTONIC);
    if (wall_end <= wall_start || cpu_end <= cpu_start) return 0;
    throughputs[run] = (double)FTUN_PERF_ITERATIONS * 1.0e9 /
                       (double)(wall_end - wall_start);
    cpu_costs[run] = (double)(cpu_end - cpu_start) /
                     (double)FTUN_PERF_ITERATIONS;
    for (index = 0u; index < FTUN_PERF_SAMPLES; index++) {
      uint64_t start = ftun_perf_now(CLOCK_MONOTONIC);
      if (parse(input, &result) != FTUN_OK || !result.found) return 0;
      samples[index] = ftun_perf_now(CLOCK_MONOTONIC) - start;
    }
    qsort(samples, FTUN_PERF_SAMPLES, sizeof(samples[0]), ftun_perf_compare);
    if (samples[(FTUN_PERF_SAMPLES * 99u) / 100u] > p99_max) {
      p99_max = samples[(FTUN_PERF_SAMPLES * 99u) / 100u];
    }
    printf("performance name=%s run=%zu operations=%u ops_per_second=%.0f "
           "cpu_ns_per_op=%.1f p50_ns=%" PRIu64 " p95_ns=%" PRIu64
           " p99_ns=%" PRIu64 "\n",
           name, run + 1u, FTUN_PERF_ITERATIONS, throughputs[run],
           cpu_costs[run], samples[FTUN_PERF_SAMPLES / 2u],
           samples[(FTUN_PERF_SAMPLES * 95u) / 100u],
           samples[(FTUN_PERF_SAMPLES * 99u) / 100u]);
  }
  qsort(throughputs, FTUN_PERF_RUNS, sizeof(throughputs[0]),
        ftun_perf_compare_double);
  qsort(cpu_costs, FTUN_PERF_RUNS, sizeof(cpu_costs[0]),
        ftun_perf_compare_double);
  return throughputs[FTUN_PERF_RUNS / 2u] >= FTUN_PERF_MIN_OPS_PER_SECOND &&
         cpu_costs[FTUN_PERF_RUNS / 2u] <= FTUN_PERF_MAX_CPU_NS_PER_OP &&
         p99_max <= FTUN_PERF_MAX_P99_NS;
}

int main(void)
{
  static const uint8_t http[] =
    "GET /resource HTTP/1.1\r\nHost: WWW.Example.COM:443\r\n"
    "User-Agent: ftun-performance\r\nAccept: */*\r\n\r\n";
  uint8_t tls[1024];
  size_t tls_length = ftun_perf_client_hello(tls, "WWW.Example.COM");
  if (!ftun_perf_run("http-host", ftun_sniff_http_host,
                     (ftun_bytes_t){http, sizeof(http) - 1u}) ||
      !ftun_perf_run("tls-sni", ftun_sniff_tls_sni,
                     (ftun_bytes_t){tls, tls_length})) {
    fputs("performance regression threshold exceeded\n", stderr);
    return 1;
  }
  return 0;
}
