#include "tls/tls.h"
#include "core/budget.h"

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "tls contract failed: %s\n", #x); return 1; \
} } while (0)

#define STRINGIFY_INNER(x) #x
#define STRINGIFY(x) STRINGIFY_INNER(x)

typedef struct {
  uint8_t client_to_server[65536];
  size_t client_to_server_length;
  uint8_t server_to_client[65536];
  size_t server_to_client_length;
} memory_pipe_t;

static ftun_status_t client_read(void *user, uint8_t *buffer,
                                 size_t capacity, size_t *length)
{
  memory_pipe_t *pipe = (memory_pipe_t *)user;
  size_t amount;
  *length = 0u;
  if (pipe->server_to_client_length == 0u) return FTUN_E_AGAIN;
  amount = pipe->server_to_client_length < capacity
    ? pipe->server_to_client_length : capacity;
  memcpy(buffer, pipe->server_to_client, amount);
  memmove(pipe->server_to_client, pipe->server_to_client + amount,
          pipe->server_to_client_length - amount);
  pipe->server_to_client_length -= amount;
  *length = amount;
  return FTUN_OK;
}

static ftun_status_t client_write(void *user, const uint8_t *buffer,
                                  size_t length, size_t *written)
{
  memory_pipe_t *pipe = (memory_pipe_t *)user;
  *written = 0u;
  if (length > sizeof(pipe->client_to_server) -
               pipe->client_to_server_length) return FTUN_E_AGAIN;
  memcpy(pipe->client_to_server + pipe->client_to_server_length,
         buffer, length);
  pipe->client_to_server_length += length;
  *written = length;
  return FTUN_OK;
}

static int server_read(WOLFSSL *ssl, char *buffer, int capacity, void *user)
{
  memory_pipe_t *pipe = (memory_pipe_t *)user;
  size_t amount;
  (void)ssl;
  if (pipe->client_to_server_length == 0u) return WOLFSSL_CBIO_ERR_WANT_READ;
  amount = pipe->client_to_server_length < (size_t)capacity
    ? pipe->client_to_server_length : (size_t)capacity;
  memcpy(buffer, pipe->client_to_server, amount);
  memmove(pipe->client_to_server, pipe->client_to_server + amount,
          pipe->client_to_server_length - amount);
  pipe->client_to_server_length -= amount;
  return (int)amount;
}

static int server_write(WOLFSSL *ssl, char *buffer, int length, void *user)
{
  memory_pipe_t *pipe = (memory_pipe_t *)user;
  (void)ssl;
  if ((size_t)length > sizeof(pipe->server_to_client) -
                       pipe->server_to_client_length) {
    return WOLFSSL_CBIO_ERR_WANT_WRITE;
  }
  memcpy(pipe->server_to_client + pipe->server_to_client_length,
         buffer, (size_t)length);
  pipe->server_to_client_length += (size_t)length;
  return length;
}

static int handshake_case(const char *hostname, const char *ca_file,
                          int expect_success)
{
  const char cert_file[] = STRINGIFY(FTUN_TEST_CERT_DIR) "/server-cert.pem";
  const char key_file[] = STRINGIFY(FTUN_TEST_CERT_DIR) "/server-key.pem";
  memory_pipe_t pipe;
  ftun_tls_options_t options;
  ftun_tls_io_t io;
  ftun_tls_client_t *client = NULL;
  ftun_budget_t *budget = NULL;
  WOLFSSL_CTX *server_context = NULL;
  WOLFSSL *server = NULL;
  int client_done = 0;
  int server_done = 0;
  int rejected = 0;
  size_t iteration;
  memset(&pipe, 0, sizeof(pipe));
  memset(&options, 0, sizeof(options));
  CHECK(ftun_budget_create(NULL, 256u * 1024u, 0u, &budget) == FTUN_OK);
  options.budget = budget;
  options.server_name.data = hostname;
  options.server_name.length = strlen(hostname);
  options.ca_file = ca_file;
  options.maximum_plaintext = 16384u;
  io.read = client_read;
  io.write = client_write;
  io.user = &pipe;
  CHECK(ftun_tls_client_open(&options, &io, &client) == FTUN_OK);
  server_context = wolfSSL_CTX_new(wolfTLS_server_method());
  CHECK(server_context != NULL);
  CHECK(wolfSSL_CTX_use_certificate_file(server_context, cert_file,
        WOLFSSL_FILETYPE_PEM) == WOLFSSL_SUCCESS);
  CHECK(wolfSSL_CTX_use_PrivateKey_file(server_context, key_file,
        WOLFSSL_FILETYPE_PEM) == WOLFSSL_SUCCESS);
  wolfSSL_SetIORecv(server_context, server_read);
  wolfSSL_SetIOSend(server_context, server_write);
  server = wolfSSL_new(server_context);
  CHECK(server != NULL);
  wolfSSL_SetIOReadCtx(server, &pipe);
  wolfSSL_SetIOWriteCtx(server, &pipe);
  for (iteration = 0u; iteration < 1000u && !rejected &&
       (!client_done || !server_done); iteration++) {
    ftun_status_t status;
    int result;
    if (!client_done) {
      status = ftun_tls_client_handshake(client);
      if (status == FTUN_OK) client_done = 1;
      else if (status != FTUN_E_AGAIN) rejected = 1;
    }
    if (!server_done) {
      result = wolfSSL_accept(server);
      if (result == WOLFSSL_SUCCESS) server_done = 1;
      else {
        int error = wolfSSL_get_error(server, result);
        CHECK(error == WOLFSSL_ERROR_WANT_READ ||
              error == WOLFSSL_ERROR_WANT_WRITE || rejected);
      }
    }
  }
  if (expect_success) {
    ftun_tls_info_t info;
    static const uint8_t message[] = {'p','i','n','g'};
    uint8_t received[8];
    size_t written = 0u;
    int result;
    CHECK(client_done && server_done && !rejected);
    CHECK(ftun_tls_client_get_info(client, &info) == FTUN_OK);
    CHECK(info.handshake_complete && info.peer_verified);
    CHECK(ftun_tls_client_write(client, message, sizeof(message),
                                &written) == FTUN_OK);
    CHECK(written == sizeof(message));
    result = wolfSSL_read(server, received, sizeof(received));
    CHECK(result == (int)sizeof(message));
    CHECK(memcmp(received, message, sizeof(message)) == 0);
  } else {
    CHECK(rejected && !client_done);
  }
  CHECK(ftun_tls_client_destroy(&client) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK && budget == NULL);
  wolfSSL_free(server);
  wolfSSL_CTX_free(server_context);
  return 0;
}

int main(void)
{
  const char ca_file[] = STRINGIFY(FTUN_TEST_CERT_DIR) "/ca-cert.pem";
  const char wrong_ca[] = STRINGIFY(FTUN_TEST_CERT_DIR) "/ca-ecc-cert.pem";
  ftun_tls_options_t invalid;
  ftun_tls_io_t io;
  ftun_tls_client_t *client = NULL;
  ftun_budget_t *budget = NULL;
  ftun_budget_t *small_budget = NULL;
  memory_pipe_t pipe;
  memset(&invalid, 0, sizeof(invalid));
  memset(&io, 0, sizeof(io));
  memset(&pipe, 0, sizeof(pipe));
  CHECK(ftun_budget_create(NULL, 256u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_budget_create(NULL, 128u, 0u, &small_budget) == FTUN_OK);
  invalid.budget = budget;
  invalid.server_name.data = "example.com";
  invalid.server_name.length = 11u;
  invalid.maximum_plaintext = 16384u;
  io.read = client_read; io.write = client_write; io.user = &pipe;
  CHECK(ftun_tls_client_open(&invalid, &io, &client) == FTUN_E_INVALID);
  CHECK(client == NULL); /* CA 缺失不允许降级 insecure。 */
  invalid.ca_file = ca_file;
  invalid.budget = small_budget;
  CHECK(ftun_tls_client_open(&invalid, &io, &client) == FTUN_E_LIMIT);
  CHECK(client == NULL);
  CHECK(ftun_budget_destroy(&small_budget) == FTUN_OK &&
        small_budget == NULL);
  invalid.budget = budget;
  CHECK(ftun_tls_client_open(&invalid, &io, &client) == FTUN_OK);
  CHECK(ftun_tls_client_handshake(client) == FTUN_E_AGAIN);
  {
    ftun_tls_info_t info;
    CHECK(ftun_tls_client_get_info(client, &info) == FTUN_OK &&
          !info.handshake_complete && (info.wants_read || info.wants_write));
  }
  CHECK(ftun_tls_client_destroy(&client) == FTUN_OK && client == NULL);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK && budget == NULL);
  CHECK(handshake_case("example.com", ca_file, 1) == 0);
  CHECK(handshake_case("wrong.example", ca_file, 0) == 0);
  CHECK(handshake_case("example.com", wrong_ca, 0) == 0);
  return 0;
}
