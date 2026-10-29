#include "libs/tls/wolfssl_adapter.h"
#include "core/limits.h"

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "TLS resource contract failed at %d: %s\n", __LINE__, #x); \
  return 1; \
} } while (0)
#define STRINGIFY_INNER(x) #x
#define STRINGIFY(x) STRINGIFY_INNER(x)

static bool fail_init;
static bool fail_context;
static bool fail_client;
static bool fail_sni;
static size_t init_calls;
static size_t client_calls;

int __real_wolfSSL_Init(void);
int __wrap_wolfSSL_Init(void)
{
  init_calls++;
  return fail_init ? WOLFSSL_FAILURE : __real_wolfSSL_Init();
}

WOLFSSL_CTX *__real_wolfSSL_CTX_new(WOLFSSL_METHOD *method);
WOLFSSL_CTX *__wrap_wolfSSL_CTX_new(WOLFSSL_METHOD *method)
{
  /* method 已分配；由原生构造/销毁负责消费，故障夹具也不遗失所有权。 */
  WOLFSSL_CTX *context = __real_wolfSSL_CTX_new(method);
  if (fail_context) {
    wolfSSL_CTX_free(context);
    return NULL;
  }
  return context;
}

WOLFSSL *__real_wolfSSL_new(WOLFSSL_CTX *context);
WOLFSSL *__wrap_wolfSSL_new(WOLFSSL_CTX *context)
{
  client_calls++;
  return fail_client ? NULL : __real_wolfSSL_new(context);
}

int __real_wolfSSL_UseSNI(WOLFSSL *ssl, unsigned char type,
                          const void *data, unsigned short size);
int __wrap_wolfSSL_UseSNI(WOLFSSL *ssl, unsigned char type,
                          const void *data, unsigned short size)
{
  return fail_sni ? WOLFSSL_FAILURE :
    __real_wolfSSL_UseSNI(ssl, type, data, size);
}





static int usage_is(ftun_budget_t *budget, size_t memory, size_t metadata)
{
  ftun_budget_usage_t usage;
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
  CHECK(usage.used_resources.memory_bytes == memory && usage.used_resources.memory_bytes == memory);
  CHECK(usage.used_resources.descriptors == 0u);
  CHECK(usage.used_resources.queue_slots == 0u);
  CHECK(usage.metadata_bytes == metadata && usage.child_count == 0u);
  return 0;
}

int main(void)
{
  const char ca_file[] = STRINGIFY(FTUN_TEST_CERT_DIR) "/ca-cert.pem";
  ftun_tls_options_t options = {0};


  ftun_budget_t *budget = NULL;
  ftun_budget_t *other_budget = NULL;
  ftun_budget_options_t limits = {0};
  ftun_budget_usage_t empty, prepared, active, combined, usage;
  ftun_tls_context_t *context = NULL;
  ftun_tls_context_t *borrowed = NULL;
  ftun_tls_client_t *client = NULL;
  ftun_tls_client_t *second = NULL;
  ftun_tls_client_t *rejected = NULL;
  ftun_reservation_t hold = (ftun_reservation_t){0};
  size_t calls;
  limits.limit.memory_bytes = 128u * 1024u;
  /* TLS 借用 IO，资源向量为零的 FD/queue 也允许内存管道握手推进。 */
  CHECK(ftun_budget_create_resources(NULL, &limits, &budget) == FTUN_OK);
  CHECK(ftun_budget_create(NULL, 128u * 1024u, 0u, &other_budget) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &empty) == FTUN_OK);
  options.budget = budget;
  options.server_name = (ftun_string_t){"example.com", 11u};
  options.ca_file = ca_file;
  options.maximum_plaintext = 8192u;

  CHECK(ftun_budget_reserve(budget, empty.normal_available_resources.memory_bytes, &hold) == FTUN_OK);
  calls = init_calls;
  CHECK(ftun_wolfssl_prepare(&options, &context) == FTUN_E_LIMIT);
  CHECK(context == NULL && init_calls == calls);
  ftun_reservation_release(&hold);
  CHECK(usage_is(budget, 0u, empty.metadata_bytes) == 0);

  fail_init = true;
  CHECK(ftun_wolfssl_prepare(&options, &context) == FTUN_E_STATE_CORRUPT);
  CHECK(context == NULL);
  fail_init = false;
  CHECK(usage_is(budget, 0u, empty.metadata_bytes) == 0);
  fail_context = true;
  CHECK(ftun_wolfssl_prepare(&options, &context) == FTUN_E_LIMIT);
  CHECK(context == NULL);
  fail_context = false;
  CHECK(usage_is(budget, 0u, empty.metadata_bytes) == 0);
  options.ca_file = NULL;
  options.ca_pem = (ftun_bytes_t){(const uint8_t *)"invalid", 7u};
  CHECK(ftun_wolfssl_prepare(&options, &context) == FTUN_E_REJECTED);
  CHECK(context == NULL);
  CHECK(usage_is(budget, 0u, empty.metadata_bytes) == 0);
  options.ca_file = ca_file;
  options.ca_pem = (ftun_bytes_t){NULL, 0u};

  CHECK(ftun_wolfssl_prepare(&options, &context) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &prepared) == FTUN_OK);
  CHECK(prepared.used_resources.memory_bytes > 0u && prepared.used_resources.memory_bytes < options.maximum_plaintext);
  CHECK(ftun_budget_reserve(budget, prepared.normal_available_resources.memory_bytes, &hold) == FTUN_OK);
  calls = client_calls;
  CHECK(ftun_wolfssl_client_create(context, &options, &client) == FTUN_E_LIMIT);
  CHECK(client == NULL && client_calls == calls);
  ftun_reservation_release(&hold);
  CHECK(usage_is(budget, prepared.used_resources.memory_bytes, prepared.metadata_bytes) == 0);

  options.maximum_plaintext = 0u;
  CHECK(ftun_wolfssl_client_create(context, &options, &client) == FTUN_E_INVALID);
  options.maximum_plaintext = 1024u * 1024u + 1u;
  CHECK(ftun_wolfssl_client_create(context, &options, &client) == FTUN_E_INVALID);
  options.maximum_plaintext = 8192u;
  options.budget = other_budget;
  CHECK(ftun_wolfssl_client_create(context, &options, &client) == FTUN_E_INVALID);
  options.budget = budget;
  CHECK(client == NULL && client_calls == calls);
  CHECK(usage_is(budget, prepared.used_resources.memory_bytes, prepared.metadata_bytes) == 0);

  fail_client = true;
  CHECK(ftun_wolfssl_client_create(context, &options, &client) == FTUN_E_LIMIT);
  fail_client = false;
  CHECK(client == NULL);
  CHECK(usage_is(budget, prepared.used_resources.memory_bytes, prepared.metadata_bytes) == 0);
  fail_sni = true;
  CHECK(ftun_wolfssl_client_create(context, &options, &client) == FTUN_E_REJECTED);
  fail_sni = false;
  CHECK(client == NULL);
  CHECK(usage_is(budget, prepared.used_resources.memory_bytes, prepared.metadata_bytes) == 0);

  CHECK(ftun_wolfssl_client_create(context, &options, &client) == FTUN_OK);
  borrowed = context;
  context = NULL;
  CHECK(ftun_budget_get_usage(budget, &active) == FTUN_OK);
  CHECK(active.used_resources.memory_bytes > prepared.used_resources.memory_bytes + options.maximum_plaintext);
  CHECK(active.metadata_bytes == prepared.metadata_bytes);
  calls = client_calls;
  CHECK(ftun_wolfssl_client_create(borrowed, &options, &second) == FTUN_OK);
  CHECK(second != NULL && client_calls == calls + 1u);
  CHECK(usage_is(budget, active.used_resources.memory_bytes * 2u - prepared.used_resources.memory_bytes, active.metadata_bytes) == 0);
  CHECK(ftun_tls_client_destroy(&second) == FTUN_OK && second == NULL);
  CHECK(ftun_wolfssl_context_destroy(&borrowed) == FTUN_E_AGAIN);
  CHECK(borrowed != NULL);
  CHECK(usage_is(budget, active.used_resources.memory_bytes, active.metadata_bytes) == 0);
  CHECK(ftun_budget_destroy(&budget) == FTUN_E_AGAIN && budget != NULL);
  CHECK(ftun_tls_client_handshake(client) == FTUN_E_AGAIN);

  /* 新旧 client 并存时分别计量，名字与单次 I/O 额度按当前参数相加。 */
  options.server_name = (ftun_string_t){"longer.example.com", 18u};
  options.maximum_plaintext = 16384u;
  CHECK(ftun_tls_client_open(&options, &second) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &combined) == FTUN_OK);
  CHECK(combined.used_resources.memory_bytes == active.used_resources.memory_bytes * 2u + 8192u + 7u);
  CHECK(combined.used_resources.descriptors == 0u &&
        combined.used_resources.queue_slots == 0u);
  CHECK(ftun_budget_reserve(budget, combined.normal_available_resources.memory_bytes, &hold) == FTUN_OK);
  CHECK(ftun_tls_client_open(&options, &rejected) == FTUN_E_LIMIT);
  CHECK(rejected == NULL);
  CHECK(ftun_tls_client_handshake(client) == FTUN_E_AGAIN);
  CHECK(ftun_tls_client_handshake(second) == FTUN_E_AGAIN);
  ftun_reservation_release(&hold);
  CHECK(ftun_tls_client_destroy(&second) == FTUN_OK && second == NULL);
  CHECK(usage_is(budget, active.used_resources.memory_bytes, active.metadata_bytes) == 0);
  CHECK(ftun_tls_client_destroy(&client) == FTUN_OK && client == NULL);
  CHECK(usage_is(budget, prepared.used_resources.memory_bytes, empty.metadata_bytes) == 0);
  CHECK(ftun_wolfssl_context_destroy(&borrowed) == FTUN_OK && borrowed == NULL);
  CHECK(usage_is(budget, 0u, empty.metadata_bytes) == 0);

  CHECK(ftun_tls_client_open(NULL, &client) == FTUN_E_INVALID);
  CHECK(client == NULL);
  fail_client = true;
  CHECK(ftun_tls_client_open(&options, &client) == FTUN_E_LIMIT);
  fail_client = false;
  CHECK(client == NULL);
  CHECK(usage_is(budget, 0u, empty.metadata_bytes) == 0);
  CHECK(ftun_wolfssl_prepare(&options, &context) == FTUN_OK);
  options.server_name = (ftun_string_t){"example.com", 11u};
  options.maximum_plaintext = 4096u;
  CHECK(ftun_wolfssl_client_create(context, &options, &client) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK);
  CHECK(usage.used_resources.memory_bytes == active.used_resources.memory_bytes - 4096u);
  CHECK(ftun_tls_client_destroy(&client) == FTUN_OK && client == NULL);
  CHECK(ftun_wolfssl_context_destroy(&context) == FTUN_OK && context == NULL);
  CHECK(ftun_wolfssl_prepare(&options, &context) == FTUN_OK);
  CHECK(ftun_wolfssl_context_destroy(&context) == FTUN_OK && context == NULL);
  CHECK(ftun_budget_get_usage(other_budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u);
  CHECK(usage_is(budget, 0u, empty.metadata_bytes) == 0);
  CHECK(ftun_budget_destroy(&other_budget) == FTUN_OK && other_budget == NULL);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK && budget == NULL);
  return 0;
}
