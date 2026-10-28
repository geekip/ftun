#define _GNU_SOURCE 1

#include "tls/tls.h"
#include "core/budget.h"

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

/* 在默认大小的线程栈里完成一次 TLS 客户端握手并实测栈峰值。
 * musl 的默认线程栈只有 128 KiB，而 wolfSSL 未启用 SMALL_STACK 时握手路径上有
 * 较大的栈数组；Worker 线程使用默认栈，所以必须有足够余量。栈预先填充特征字节，
 * 线程结束后从低地址侧找第一个被改写的字节即为峰值。 */

#define STRINGIFY_INNER(x) #x
#define STRINGIFY(x) STRINGIFY_INNER(x)
#define CANARY 0xa5u
#define DEFAULT_STACK_BYTES (128u * 1024u)
#define MINIMUM_HEADROOM_BYTES (32u * 1024u)

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "tls worker stack failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

typedef struct {
  int fd;
  const char *hostname;
  const char *ca_file;
  int result;
  ftun_status_t status;
} client_job_t;

typedef struct {
  int fd;
  const char *certificate;
  const char *key;
  int result;
} server_job_t;

static ftun_status_t client_read(void *user, uint8_t *buffer, size_t capacity,
                                 size_t *length)
{
  ssize_t count = recv(*(int *)user, buffer, capacity, MSG_DONTWAIT);
  *length = 0u;
  if (count > 0) { *length = (size_t)count; return FTUN_OK; }
  if (count == 0) return FTUN_E_EOF;
  return errno == EAGAIN || errno == EWOULDBLOCK ? FTUN_E_AGAIN : FTUN_E_IO;
}

static ftun_status_t client_write(void *user, const uint8_t *buffer,
                                  size_t length, size_t *written)
{
  ssize_t count = send(*(int *)user, buffer, length, MSG_DONTWAIT | MSG_NOSIGNAL);
  *written = 0u;
  if (count >= 0) { *written = (size_t)count; return FTUN_OK; }
  return errno == EAGAIN || errno == EWOULDBLOCK ? FTUN_E_AGAIN : FTUN_E_IO;
}

static void *client_thread(void *argument)
{
  client_job_t *job = (client_job_t *)argument;
  ftun_tls_options_t options;
  ftun_tls_io_t io;
  ftun_tls_client_t *client = NULL;
  ftun_budget_t *budget = NULL;
  ftun_status_t status = FTUN_E_AGAIN;
  int round;
  job->result = 1;
  memset(&options, 0, sizeof(options));
  if (ftun_budget_create(NULL, 512u * 1024u, 0u, &budget) != FTUN_OK) return NULL;
  options.budget = budget;
  options.server_name.data = job->hostname;
  options.server_name.length = strlen(job->hostname);
  options.ca_file = job->ca_file;
  options.maximum_plaintext = 16384u;
  io.read = client_read;
  io.write = client_write;
  io.user = &job->fd;
  if (ftun_tls_client_open(&options, &io, &client) != FTUN_OK) return NULL;
  for (round = 0; round < 2000 && status == FTUN_E_AGAIN; round++) {
    struct pollfd entry = {job->fd, POLLIN, 0};
    status = ftun_tls_client_handshake(client);
    if (status == FTUN_E_AGAIN) (void)poll(&entry, 1u, 50);
  }
  job->status = status;
  if (status == FTUN_OK) {
    static const uint8_t message[] = {'p', 'i', 'n', 'g'};
    size_t written = 0u;
    if (ftun_tls_client_write(client, message, sizeof(message), &written) == FTUN_OK &&
        written == sizeof(message)) job->result = 0;
  }
  (void)ftun_tls_client_destroy(&client);
  (void)ftun_budget_destroy(&budget);
  return NULL;
}

static void *server_thread(void *argument)
{
  server_job_t *job = (server_job_t *)argument;
  WOLFSSL_CTX *context = wolfSSL_CTX_new(wolfTLS_server_method());
  WOLFSSL *ssl = NULL;
  char received[8];
  job->result = 1;
  if (context == NULL ||
      wolfSSL_CTX_use_certificate_file(context, job->certificate,
        WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS ||
      wolfSSL_CTX_use_PrivateKey_file(context, job->key,
        WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
    if (context != NULL) wolfSSL_CTX_free(context);
    return NULL;
  }
  ssl = wolfSSL_new(context);
  if (ssl != NULL) {
    wolfSSL_set_fd(ssl, job->fd);
    if (wolfSSL_accept(ssl) == WOLFSSL_SUCCESS &&
        wolfSSL_read(ssl, received, sizeof(received)) == 4) job->result = 0;
    wolfSSL_free(ssl);
  }
  wolfSSL_CTX_free(context);
  return NULL;
}

/* 返回峰值栈用量；失败返回 0。 */
static size_t measure(size_t stack_bytes, const char *hostname, const char *ca,
                      const char *certificate, const char *key)
{
  int pair[2];
  unsigned char *stack;
  pthread_attr_t attributes;
  pthread_t client, server;
  client_job_t client_job;
  server_job_t server_job;
  size_t index;
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0) return 0u;
  stack = mmap(NULL, stack_bytes, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
  if (stack == MAP_FAILED) return 0u;
  memset(stack, CANARY, stack_bytes);
  client_job = (client_job_t){pair[0], hostname, ca, 1, FTUN_OK};
  server_job = (server_job_t){pair[1], certificate, key, 1};
  if (pthread_attr_init(&attributes) != 0 ||
      pthread_attr_setstack(&attributes, stack, stack_bytes) != 0 ||
      pthread_create(&server, NULL, server_thread, &server_job) != 0) return 0u;
  if (pthread_create(&client, &attributes, client_thread, &client_job) != 0) return 0u;
  (void)pthread_join(client, NULL);
  /* 客户端失败时服务端还阻塞在读上，关闭连接让它退出。 */
  (void)shutdown(pair[0], SHUT_RDWR);
  (void)pthread_join(server, NULL);
  (void)pthread_attr_destroy(&attributes);
  (void)close(pair[0]);
  (void)close(pair[1]);
  if (client_job.result != 0 || server_job.result != 0) {
    fprintf(stderr, "handshake failed: client=%d (status %d) server=%d\n",
            client_job.result, (int)client_job.status, server_job.result);
    return 0u;
  }
  for (index = 0u; index < stack_bytes && stack[index] == CANARY; index++) {}
  (void)munmap(stack, stack_bytes);
  /* 栈向低地址增长：低地址侧连续未被改写的字节数就是剩余余量。 */
  return stack_bytes - index;
}

static void *touch_thread(void *argument)
{
  volatile unsigned char buffer[40000];
  size_t index;
  for (index = 0u; index < sizeof(buffer); index += 64u) buffer[index] = 1u;
  (void)argument;
  return NULL;
}

/* 测量方法自检：已知用掉约 40000 字节栈，测得值必须不小于它。 */
static int test_measurement(void)
{
  unsigned char *stack;
  pthread_attr_t attributes;
  pthread_t thread;
  size_t index;
  stack = mmap(NULL, DEFAULT_STACK_BYTES, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
  CHECK(stack != MAP_FAILED);
  memset(stack, CANARY, DEFAULT_STACK_BYTES);
  CHECK(pthread_attr_init(&attributes) == 0 &&
        pthread_attr_setstack(&attributes, stack, DEFAULT_STACK_BYTES) == 0 &&
        pthread_create(&thread, &attributes, touch_thread, NULL) == 0);
  CHECK(pthread_join(thread, NULL) == 0);
  (void)pthread_attr_destroy(&attributes);
  for (index = 0u; index < DEFAULT_STACK_BYTES && stack[index] == CANARY; index++) {}
  CHECK(DEFAULT_STACK_BYTES - index >= 40000u);
  CHECK(munmap(stack, DEFAULT_STACK_BYTES) == 0);
  return 0;
}

int main(int argc, char **argv)
{
  const char *certs = STRINGIFY(FTUN_TEST_CERT_DIR);
  char certificate[512], key[512], ca[512], ecc_certificate[512], ecc_key[512], ecc_ca[512];
  size_t stack_bytes = argc > 1 ? (size_t)strtoul(argv[1], NULL, 10) : DEFAULT_STACK_BYTES;
  size_t rsa_peak, ecc_peak;
  signal(SIGPIPE, SIG_IGN);
  CHECK(test_measurement() == 0);
  (void)snprintf(certificate, sizeof(certificate), "%s/server-cert.pem", certs);
  (void)snprintf(key, sizeof(key), "%s/server-key.pem", certs);
  (void)snprintf(ca, sizeof(ca), "%s/ca-cert.pem", certs);
  (void)snprintf(ecc_certificate, sizeof(ecc_certificate), "%s/server-ecc.pem", certs);
  (void)snprintf(ecc_key, sizeof(ecc_key), "%s/ecc-key.pem", certs);
  (void)snprintf(ecc_ca, sizeof(ecc_ca), "%s/ca-ecc-cert.pem", certs);
  rsa_peak = measure(stack_bytes, "example.com", ca, certificate, key);
  ecc_peak = measure(stack_bytes, "www.wolfssl.com", ecc_ca, ecc_certificate, ecc_key);
  printf("TLS client handshake stack peak: RSA %zu bytes, ECC %zu bytes (stack %zu)\n",
         rsa_peak, ecc_peak, stack_bytes);
  CHECK(rsa_peak != 0u && ecc_peak != 0u);
  CHECK(rsa_peak + MINIMUM_HEADROOM_BYTES <= stack_bytes);
  CHECK(ecc_peak + MINIMUM_HEADROOM_BYTES <= stack_bytes);
  return 0;
}
