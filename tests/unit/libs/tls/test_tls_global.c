#define _POSIX_C_SOURCE 200809L
#include "libs/tls/tls.h"
#include "core/limits.h"

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "TLS global contract failed at %d: %s\n", __LINE__, #x); \
  exit(1); \
} } while (0)
#define STR_INNER(x) #x
#define STR(x) STR_INNER(x)
#define THREADS 8u
#define ROUNDS 32u

static ftun_budget_t *shared_budget;
static ftun_tls_context_t *shared_context;
static atomic_uint init_calls;
static atomic_uint cleanup_calls;
static atomic_uint registration_calls;
static atomic_bool fail_init;
static atomic_bool fail_registration;
static atomic_bool inside_native_init;
static pthread_barrier_t start;
static pthread_barrier_t prepared;

int __real_wolfSSL_Init(void);
int __wrap_wolfSSL_Init(void)
{
  int result;
  (void)atomic_fetch_add(&init_calls, 1u);
  if (atomic_exchange(&fail_init, false)) return WOLFSSL_FAILURE;
  atomic_store(&inside_native_init, true);
  result = __real_wolfSSL_Init();
  atomic_store(&inside_native_init, false);
  return result;
}

int __real_wolfSSL_Cleanup(void);
int __wrap_wolfSSL_Cleanup(void)
{
  (void)atomic_fetch_add(&cleanup_calls, 1u);
  return __real_wolfSSL_Cleanup();
}

int __real_atexit(void (*callback)(void));
int __wrap_atexit(void (*callback)(void))
{
  /* 仅观察 FTUN 的登记，不依赖 native 是否编译了自动退出钩子。 */
  if (!atomic_load(&inside_native_init)) {
    (void)atomic_fetch_add(&registration_calls, 1u);
    if (atomic_exchange(&fail_registration, false)) return -1;
  }
  return __real_atexit(callback);
}





static void options_init(ftun_tls_options_t *options, ftun_budget_t *budget)
{
  *options = (ftun_tls_options_t){0};
  options->budget = budget;
  options->server_name = (ftun_string_t){"example.com", 11u};
  options->ca_file = STR(FTUN_TEST_CERT_DIR) "/ca-cert.pem";
  options->maximum_plaintext = 8192u;
}

static void barrier_wait(pthread_barrier_t *barrier)
{
  int status = pthread_barrier_wait(barrier);
  CHECK(status == 0 || status == PTHREAD_BARRIER_SERIAL_THREAD);
}

static void *create_clients(void *unused)
{
  ftun_budget_t *budget = NULL;
  ftun_budget_usage_t usage;
  ftun_tls_options_t options;

  size_t index;
  (void)unused;
  CHECK(ftun_budget_create(shared_budget, 128u * 1024u, 0u, &budget) == FTUN_OK);
  options_init(&options, budget);
  barrier_wait(&start);
  for (index = 0u; index < ROUNDS; index++) {
    ftun_tls_client_t *client = NULL;
    CHECK(ftun_tls_client_create(shared_context, &options, &client) == FTUN_OK);
    /* 每轮所有实例并存后再销毁，反复穿过零个/多个 FTUN 实例边界。 */
    barrier_wait(&prepared);
    CHECK(ftun_tls_client_handshake(client) == FTUN_E_AGAIN);
    CHECK(ftun_tls_client_destroy(&client) == FTUN_OK && client == NULL);
    CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u);
    barrier_wait(&start);
  }
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return NULL;
}

static void verify_exit(void)
{
  /* 此钩子先登记，FTUN 的正常退出清理必须在它之前真实执行。 */
  if (atomic_load(&init_calls) != 3u || atomic_load(&cleanup_calls) != 2u ||
      atomic_load(&registration_calls) != 2u) {
    fprintf(stderr, "TLS global exit counts: init=%u cleanup=%u registration=%u\n",
      atomic_load(&init_calls), atomic_load(&cleanup_calls),
      atomic_load(&registration_calls));
    _Exit(99);
  }
}

int main(void)
{
  ftun_budget_t *budget = NULL;
  ftun_budget_usage_t usage;
  ftun_tls_options_t options;

  ftun_tls_client_t *client = NULL;
  pthread_t threads[THREADS];
  WOLFSSL_CTX *external;
  WOLFSSL *session;
  size_t index;
  CHECK(__real_atexit(verify_exit) == 0);
  CHECK(ftun_budget_create(NULL, 128u * 1024u, 0u, &budget) == FTUN_OK);
  options_init(&options, budget);
  atomic_store(&fail_init, true);
  CHECK(ftun_tls_client_open(&options, &client) == FTUN_E_STATE_CORRUPT);
  CHECK(client == NULL && atomic_load(&cleanup_calls) == 0u);
  atomic_store(&fail_registration, true);
  CHECK(ftun_tls_client_open(&options, &client) == FTUN_E_LIMIT);
  CHECK(client == NULL && atomic_load(&cleanup_calls) == 1u);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u);

  /* 外部使用者持有自己的 native 引用，不计为 FTUN 初始化调用。 */
  atomic_store(&inside_native_init, true);
  CHECK(__real_wolfSSL_Init() == WOLFSSL_SUCCESS);
  atomic_store(&inside_native_init, false);
  external = wolfSSL_CTX_new(wolfTLS_client_method());
  CHECK(external != NULL);
  CHECK(ftun_budget_create(NULL, 4u * 1024u * 1024u, 0u, &shared_budget) == FTUN_OK);
  options_init(&options, shared_budget);
  CHECK(ftun_tls_context_open(&options, &shared_context) == FTUN_OK);
  CHECK(pthread_barrier_init(&start, NULL, THREADS) == 0);
  CHECK(pthread_barrier_init(&prepared, NULL, THREADS) == 0);
  for (index = 0u; index < THREADS; index++) {
    CHECK(pthread_create(&threads[index], NULL, create_clients, NULL) == 0);
  }
  for (index = 0u; index < THREADS; index++) CHECK(pthread_join(threads[index], NULL) == 0);
  CHECK(pthread_barrier_destroy(&prepared) == 0);
  CHECK(pthread_barrier_destroy(&start) == 0);
  CHECK(ftun_tls_context_destroy(&shared_context) == FTUN_OK);
  CHECK(ftun_budget_destroy(&shared_budget) == FTUN_OK);
  options_init(&options, budget);
  CHECK(atomic_load(&init_calls) == 3u && atomic_load(&cleanup_calls) == 1u);
  session = wolfSSL_new(external);
  CHECK(session != NULL);
  wolfSSL_free(session);
  wolfSSL_CTX_free(external);
  CHECK(__real_wolfSSL_Cleanup() == WOLFSSL_SUCCESS);
  CHECK(ftun_tls_client_open(&options, &client) == FTUN_OK);
  CHECK(ftun_tls_client_handshake(client) == FTUN_E_AGAIN);
  CHECK(ftun_tls_client_destroy(&client) == FTUN_OK && client == NULL);
  CHECK(atomic_load(&init_calls) == 3u && atomic_load(&cleanup_calls) == 1u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK && budget == NULL);
  return 0;
}
