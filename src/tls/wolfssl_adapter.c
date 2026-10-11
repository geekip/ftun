/* TASK-TLS-002 / TEST-TLS-002：ftun_wolfssl_prepare，目标 0.4.0。 */
#include "wolfssl_adapter.h"
#include "core/budget.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>

struct ftun_tls_context {
  WOLFSSL_CTX *native;
  ftun_reservation_t *reservation;
};

struct ftun_tls_client {
  ftun_tls_context_t *context;
  WOLFSSL *native;
  ftun_tls_io_t io;
  char *server_name;
  size_t maximum_plaintext;
  bool handshake_complete;
  bool peer_verified;
  bool wants_read;
  bool wants_write;
};

static int ftun_wolfssl_name_valid(ftun_string_t name)
{
  size_t index;
  if (name.data == NULL || name.length == 0u || name.length > 253u) return 0;
  for (index = 0u; index < name.length; index++) {
    uint8_t byte = (uint8_t)name.data[index];
    if (byte <= 0x20u || byte >= 0x7fu || byte == (uint8_t)'/' ||
        byte == (uint8_t)'@' || byte == (uint8_t)':') return 0;
  }
  return 1;
}

static int ftun_wolfssl_receive(WOLFSSL *ssl, char *buffer, int capacity,
                                void *context)
{
  ftun_tls_client_t *client = (ftun_tls_client_t *)context;
  size_t length = 0u;
  ftun_status_t status;
  (void)ssl;
  if (client == NULL || buffer == NULL || capacity <= 0) {
    return WOLFSSL_CBIO_ERR_GENERAL;
  }
  status = client->io.read(client->io.user, (uint8_t *)buffer,
                           (size_t)capacity, &length);
  if (status == FTUN_E_AGAIN) return WOLFSSL_CBIO_ERR_WANT_READ;
  if (status == FTUN_E_EOF) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
  if (status != FTUN_OK || length == 0u || length > (size_t)capacity ||
      length > (size_t)INT_MAX) return WOLFSSL_CBIO_ERR_GENERAL;
  return (int)length;
}

static int ftun_wolfssl_send(WOLFSSL *ssl, char *buffer, int length,
                             void *context)
{
  ftun_tls_client_t *client = (ftun_tls_client_t *)context;
  size_t written = 0u;
  ftun_status_t status;
  (void)ssl;
  if (client == NULL || buffer == NULL || length <= 0) {
    return WOLFSSL_CBIO_ERR_GENERAL;
  }
  status = client->io.write(client->io.user, (const uint8_t *)buffer,
                            (size_t)length, &written);
  if (status == FTUN_E_AGAIN) return WOLFSSL_CBIO_ERR_WANT_WRITE;
  if (status != FTUN_OK || written == 0u || written > (size_t)length ||
      written > (size_t)INT_MAX) return WOLFSSL_CBIO_ERR_GENERAL;
  return (int)written;
}

ftun_status_t ftun_wolfssl_prepare(const ftun_tls_options_t *options, ftun_tls_context_t **out)
{
  ftun_tls_context_t *context;
  size_t charge;
  ftun_status_t status;
  int loaded;
  if (out != NULL) *out = NULL;
  if (out == NULL || options == NULL || options->budget == NULL ||
      !ftun_wolfssl_name_valid(options->server_name) ||
      options->maximum_plaintext == 0u ||
      options->maximum_plaintext > 1024u * 1024u ||
      ((options->ca_pem.length == 0u) ==
       (options->ca_file == NULL || options->ca_file[0] == '\0')) ||
      (options->ca_pem.length != 0u && options->ca_pem.data == NULL) ||
      options->ca_pem.length > (size_t)INT_MAX) return FTUN_E_INVALID;
  if (options->server_name.length > SIZE_MAX - sizeof(*context) -
      sizeof(ftun_tls_client_t) - 1u ||
      options->maximum_plaintext > SIZE_MAX - sizeof(*context) -
      sizeof(ftun_tls_client_t) - options->server_name.length - 1u) {
    return FTUN_E_LIMIT;
  }
  charge = sizeof(*context) + sizeof(ftun_tls_client_t) +
           options->server_name.length + 1u + options->maximum_plaintext;
  context = (ftun_tls_context_t *)calloc(1u, sizeof(*context));
  if (context == NULL) return FTUN_E_LIMIT;
  status = ftun_budget_reserve(options->budget, charge,
                               &context->reservation);
  if (status != FTUN_OK) {
    free(context);
    return status;
  }
  if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
    (void)ftun_wolfssl_context_destroy(&context);
    return FTUN_E_STATE_CORRUPT;
  }
  context->native = wolfSSL_CTX_new(wolfTLS_client_method());
  if (context->native == NULL) {
    (void)ftun_wolfssl_context_destroy(&context);
    return FTUN_E_LIMIT;
  }
  if (wolfSSL_CTX_SetMinVersion(context->native, WOLFSSL_TLSV1_2) !=
      WOLFSSL_SUCCESS) {
    (void)ftun_wolfssl_context_destroy(&context);
    return FTUN_E_UNSUPPORTED;
  }
  wolfSSL_CTX_set_verify(context->native, WOLFSSL_VERIFY_PEER, NULL);
  if (options->ca_pem.length != 0u) {
    loaded = wolfSSL_CTX_load_verify_buffer(
      context->native, options->ca_pem.data, (long)options->ca_pem.length,
      WOLFSSL_FILETYPE_PEM);
  } else {
    loaded = wolfSSL_CTX_load_verify_locations(context->native,
                                                options->ca_file, NULL);
  }
  if (loaded != WOLFSSL_SUCCESS) {
    (void)ftun_wolfssl_context_destroy(&context);
    return FTUN_E_REJECTED;
  }
  wolfSSL_SetIORecv(context->native, ftun_wolfssl_receive);
  wolfSSL_SetIOSend(context->native, ftun_wolfssl_send);
  *out = context;
  return FTUN_OK;
}

ftun_status_t ftun_wolfssl_client_create(ftun_tls_context_t *context,
                                         const ftun_tls_options_t *options,
                                         const ftun_tls_io_t *io,
                                         ftun_tls_client_t **out)
{
  ftun_tls_client_t *client;
  if (out != NULL) *out = NULL;
  if (context == NULL || context->native == NULL || options == NULL ||
      io == NULL || io->read == NULL || io->write == NULL || out == NULL ||
      !ftun_wolfssl_name_valid(options->server_name) ||
      options->server_name.length > (size_t)USHRT_MAX) return FTUN_E_INVALID;
  client = (ftun_tls_client_t *)calloc(1u, sizeof(*client));
  if (client == NULL) return FTUN_E_LIMIT;
  client->server_name = (char *)malloc(options->server_name.length + 1u);
  if (client->server_name == NULL) {
    free(client);
    return FTUN_E_LIMIT;
  }
  memcpy(client->server_name, options->server_name.data,
         options->server_name.length);
  client->server_name[options->server_name.length] = '\0';
  client->native = wolfSSL_new(context->native);
  if (client->native == NULL) {
    free(client->server_name);
    free(client);
    return FTUN_E_LIMIT;
  }
  client->context = context;
  client->io = *io;
  client->maximum_plaintext = options->maximum_plaintext;
  wolfSSL_SetIOReadCtx(client->native, client);
  wolfSSL_SetIOWriteCtx(client->native, client);
  if (wolfSSL_check_domain_name(client->native, client->server_name) !=
        WOLFSSL_SUCCESS ||
      wolfSSL_UseSNI(client->native, WOLFSSL_SNI_HOST_NAME,
                     client->server_name,
                     (unsigned short)options->server_name.length) !=
        WOLFSSL_SUCCESS) {
    wolfSSL_free(client->native);
    free(client->server_name);
    free(client);
    return FTUN_E_REJECTED;
  }
  *out = client;
  return FTUN_OK;
}

static ftun_status_t ftun_wolfssl_result(ftun_tls_client_t *client,
                                         int result)
{
  int error;
  client->wants_read = false;
  client->wants_write = false;
  if (result > 0) return FTUN_OK;
  error = wolfSSL_get_error(client->native, result);
  if (error == WOLFSSL_ERROR_WANT_READ) {
    client->wants_read = true;
    return FTUN_E_AGAIN;
  }
  if (error == WOLFSSL_ERROR_WANT_WRITE) {
    client->wants_write = true;
    return FTUN_E_AGAIN;
  }
  if (error == WOLFSSL_ERROR_ZERO_RETURN) return FTUN_E_EOF;
  return FTUN_E_REJECTED;
}

ftun_status_t ftun_wolfssl_client_handshake(ftun_tls_client_t *client)
{
  int result;
  ftun_status_t status;
  if (client == NULL || client->native == NULL) return FTUN_E_INVALID;
  if (client->handshake_complete) return FTUN_OK;
  result = wolfSSL_connect(client->native);
  status = ftun_wolfssl_result(client, result);
  if (status != FTUN_OK) return status;
  client->handshake_complete = true;
  client->peer_verified = true;
  return FTUN_OK;
}

ftun_status_t ftun_wolfssl_client_read(ftun_tls_client_t *client,
                                       uint8_t *buffer, size_t capacity,
                                       size_t *length)
{
  int result;
  ftun_status_t status;
  if (length != NULL) *length = 0u;
  if (client == NULL || buffer == NULL || capacity == 0u || length == NULL ||
      !client->handshake_complete) return FTUN_E_INVALID;
  if (capacity > client->maximum_plaintext) capacity = client->maximum_plaintext;
  if (capacity > (size_t)INT_MAX) capacity = (size_t)INT_MAX;
  result = wolfSSL_read(client->native, buffer, (int)capacity);
  status = ftun_wolfssl_result(client, result);
  if (status == FTUN_OK) *length = (size_t)result;
  return status;
}

ftun_status_t ftun_wolfssl_client_write(ftun_tls_client_t *client,
                                        const uint8_t *buffer, size_t length,
                                        size_t *written)
{
  int result;
  ftun_status_t status;
  if (written != NULL) *written = 0u;
  if (client == NULL || buffer == NULL || length == 0u || written == NULL ||
      !client->handshake_complete) return FTUN_E_INVALID;
  if (length > client->maximum_plaintext) length = client->maximum_plaintext;
  if (length > (size_t)INT_MAX) length = (size_t)INT_MAX;
  result = wolfSSL_write(client->native, buffer, (int)length);
  status = ftun_wolfssl_result(client, result);
  if (status == FTUN_OK) *written = (size_t)result;
  return status;
}

ftun_status_t ftun_wolfssl_client_info(const ftun_tls_client_t *client,
                                       ftun_tls_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (client == NULL || out == NULL) return FTUN_E_INVALID;
  out->handshake_complete = client->handshake_complete;
  out->peer_verified = client->peer_verified;
  out->wants_read = client->wants_read;
  out->wants_write = client->wants_write;
  return FTUN_OK;
}

ftun_status_t ftun_wolfssl_client_destroy(ftun_tls_client_t **client)
{
  ftun_tls_client_t *owned;
  ftun_tls_context_t *context;
  if (client == NULL) return FTUN_E_INVALID;
  owned = *client;
  if (owned == NULL) return FTUN_OK;
  context = owned->context;
  wolfSSL_free(owned->native);
  free(owned->server_name);
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *client = NULL;
  return ftun_wolfssl_context_destroy(&context);
}

ftun_status_t ftun_wolfssl_context_destroy(ftun_tls_context_t **context)
{
  ftun_tls_context_t *owned;
  ftun_status_t status;
  if (context == NULL) return FTUN_E_INVALID;
  owned = *context;
  if (owned == NULL) return FTUN_OK;
  wolfSSL_CTX_free(owned->native);
  status = ftun_reservation_release(&owned->reservation);
  if (status != FTUN_OK) return status;
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *context = NULL;
  return FTUN_OK;
}
