/* ftun_wolfssl_prepare。 */
#include "libs/tls/wolfssl_adapter.h"
#include "util/ip.h"
#include "core/limits.h"
#include "platform/atomic.h"

#include <limits.h>
#include "platform/thread.h"
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>
#include <wolfssl/wolfcrypt/asn.h>

/* TLS 标准记录上限 2^14 + 2^11 密文扩展 + 5 字节头；复用 wolfSSL 回调，
 * 第一方只保存有界字节，不借用或模拟 socket。 */
#define FTUN_TLS_CIPHERTEXT_BYTES (16384u + 2048u + 5u)
typedef struct {
  uint8_t data[FTUN_TLS_CIPHERTEXT_BYTES];
  size_t head;
  size_t length;
} ftun_tls_ring_t;
struct ftun_tls_context {
  WOLFSSL_CTX *native;
  ftun_budget_t *budget;
  ftun_reservation_t reservation;
  ftun_atomic_size_t clients;
  ftun_mutex_t create_mutex;
};

struct ftun_tls_client {
  ftun_tls_context_t *context;
  ftun_reservation_t reservation;
  WOLFSSL *native;
  ftun_tls_ring_t input;
  ftun_tls_ring_t output;
  bool input_closed;
  bool owns_context;
  char *server_name;
  size_t maximum_plaintext;
  bool handshake_complete;
  bool peer_verified;
  ftun_ip_t identity_ip;
  bool wants_read;
  bool wants_write;
};

/* 独立 Core/worker 共用一个进程级引用；实例销毁不能撤销其他使用者的
 * 全局状态。失败不置位，下次可重试；不依赖 native 的条件式退出钩子。 */
static ftun_mutex_t ftun_wolfssl_init_mutex = FTUN_MUTEX_INITIALIZER;
static bool ftun_wolfssl_initialized;

static void ftun_wolfssl_cleanup(void)
{
  (void)wolfSSL_Cleanup();
}

static ftun_status_t ftun_wolfssl_initialize(void)
{
  ftun_status_t status = FTUN_OK;
  ftun_mutex_lock(&ftun_wolfssl_init_mutex);
  if (!ftun_wolfssl_initialized) {
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
      status = FTUN_E_STATE_CORRUPT;
    } else if (atexit(ftun_wolfssl_cleanup) != 0) {
      status = wolfSSL_Cleanup() == WOLFSSL_SUCCESS
        ? FTUN_E_LIMIT : FTUN_E_STATE_CORRUPT;
    } else {
      ftun_wolfssl_initialized = true;
    }
  }
  ftun_mutex_unlock(&ftun_wolfssl_init_mutex);
  return status;
}

static int ftun_wolfssl_name_valid(ftun_string_t name)
{
  size_t index;
  ftun_ip_t ip;
  if (name.data == NULL || name.length == 0u || name.length > 253u) return 0;
  if (ftun_ip_parse(name.data, name.length, &ip)) return 1;
  for (index = 0u; index < name.length; index++) {
    uint8_t byte = (uint8_t)name.data[index];
    if (byte <= 0x20u || byte >= 0x7fu || byte == (uint8_t)'/' ||
        byte == (uint8_t)'@' || byte == (uint8_t)':') return 0;
  }
  return 1;
}

static size_t ring_write(ftun_tls_ring_t *ring, const uint8_t *data, size_t length)
{
  size_t tail = (ring->head + ring->length) % FTUN_TLS_CIPHERTEXT_BYTES;
  size_t amount = length < FTUN_TLS_CIPHERTEXT_BYTES - ring->length
    ? length : FTUN_TLS_CIPHERTEXT_BYTES - ring->length;
  size_t first = amount < FTUN_TLS_CIPHERTEXT_BYTES - tail
    ? amount : FTUN_TLS_CIPHERTEXT_BYTES - tail;
  if (first != 0u) memcpy(ring->data + tail, data, first);
  if (amount > first) memcpy(ring->data, data + first, amount - first);
  ring->length += amount;
  return amount;
}

static void ring_consume(ftun_tls_ring_t *ring, size_t length)
{
  ring->head = (ring->head + length) % FTUN_TLS_CIPHERTEXT_BYTES;
  ring->length -= length;
}

static int ftun_wolfssl_receive(WOLFSSL *ssl, char *buffer, int capacity, void *context)
{
  ftun_tls_client_t *client = context;
  ftun_tls_ring_t *ring = &client->input;
  size_t amount, first;
  (void)ssl;
  if (ring->length == 0u) return client->input_closed
    ? WOLFSSL_CBIO_ERR_CONN_CLOSE : WOLFSSL_CBIO_ERR_WANT_READ;
  amount = ring->length < (size_t)capacity ? ring->length : (size_t)capacity;
  first = amount < FTUN_TLS_CIPHERTEXT_BYTES - ring->head
    ? amount : FTUN_TLS_CIPHERTEXT_BYTES - ring->head;
  memcpy(buffer, ring->data + ring->head, first);
  if (amount > first) memcpy(buffer + first, ring->data, amount - first);
  ring_consume(ring, amount);
  return (int)amount;
}

static int ftun_wolfssl_send(WOLFSSL *ssl, char *buffer, int length, void *context)
{
  ftun_tls_client_t *client = context;
  (void)ssl;
  if ((size_t)length > FTUN_TLS_CIPHERTEXT_BYTES - client->output.length) {
    return WOLFSSL_CBIO_ERR_WANT_WRITE;
  }
  return (int)ring_write(&client->output, (const uint8_t *)buffer, (size_t)length);
}

size_t ftun_tls_client_input_space(const ftun_tls_client_t *client)
{
  return FTUN_TLS_CIPHERTEXT_BYTES - client->input.length;
}

ftun_status_t ftun_tls_client_feed(ftun_tls_client_t *client, ftun_bytes_t bytes,
  size_t *consumed)
{
  if (consumed != NULL) *consumed = 0u;
  if (client == NULL || consumed == NULL || (bytes.length != 0u && bytes.data == NULL)) return FTUN_E_INVALID;
  if (client->input_closed) return FTUN_E_EOF;
  *consumed = ring_write(&client->input, bytes.data, bytes.length);
  return bytes.length != 0u && *consumed == 0u ? FTUN_E_AGAIN : FTUN_OK;
}

void ftun_tls_client_close_input(ftun_tls_client_t *client)
{
  client->input_closed = true;
}

ftun_status_t ftun_tls_client_ciphertext(ftun_tls_client_t *client, ftun_bytes_t *out)
{
  size_t first;
  if (out != NULL) *out = (ftun_bytes_t){NULL, 0u};
  if (client == NULL || out == NULL) return FTUN_E_INVALID;
  if (client->output.length == 0u) return FTUN_E_AGAIN;
  first = FTUN_TLS_CIPHERTEXT_BYTES - client->output.head;
  out->data = client->output.data + client->output.head;
  out->length = first < client->output.length ? first : client->output.length;
  return FTUN_OK;
}

ftun_status_t ftun_tls_client_consume(ftun_tls_client_t *client, size_t length)
{
  if (client == NULL || length > client->output.length) return FTUN_E_INVALID;
  ring_consume(&client->output, length);
  return FTUN_OK;
}

/* 证书链/有效期仍由wolfSSL验证；只追加叶证书的严格IP SAN类型匹配。
 * 使用锁定上游的证书解析器，不把DNS SAN或CN中的数值文本当作IP身份。 */
static int verify_peer(int verified, WOLFSSL_X509_STORE_CTX *store)
{
  ftun_tls_client_t *client = store->userCtx;
  DecodedCert cert;
  bool matched = false;
  size_t length;
  if (!verified) return 0;
  if (store->error_depth != 0 || client->identity_ip.family == FTUN_IP_NONE) return 1;
  length = client->identity_ip.family == FTUN_IP_V4 ? 4u : 16u;
  wc_InitDecodedCert(&cert, store->certs[0].buffer, store->certs[0].length, NULL);
  if (wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL) == 0) {
    for (DNS_entry *name = cert.altNames; name != NULL; name = name->next) {
      if (name->type == ASN_IP_TYPE && name->len == (int)length &&
          memcmp(name->name, client->identity_ip.bytes, length) == 0) {
        matched = true;
        break;
      }
    }
  }
  wc_FreeDecodedCert(&cert);
  return matched ? 1 : 0;
}

ftun_status_t ftun_wolfssl_prepare(const ftun_tls_options_t *options, ftun_tls_context_t **out)
{
  ftun_tls_context_t *context;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
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
  status = ftun_budget_reserve(options->budget, sizeof(*context), &reservation);
  if (status != FTUN_OK) return status;
  context = (ftun_tls_context_t *)calloc(1u, sizeof(*context));
  if (context == NULL) {
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  status = ftun_mutex_init(&context->create_mutex);
  if (status != FTUN_OK) {
    free(context);
    ftun_reservation_release(&reservation);
    return status;
  }
  ftun_atomic_init(&context->clients, 0u);
  context->budget = options->budget;
  context->reservation = reservation;
  status = ftun_wolfssl_initialize();
  if (status != FTUN_OK) {
    (void)ftun_wolfssl_context_destroy(&context);
    return status;
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
  wolfSSL_CTX_set_verify(context->native, WOLFSSL_VERIFY_PEER, verify_peer);
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
                                         ftun_tls_client_t **out)
{
  ftun_tls_client_t *client;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_status_t status;
  size_t charge;
  if (out != NULL) *out = NULL;
  if (context == NULL || context->native == NULL || options == NULL ||
      options->budget == NULL || out == NULL ||
      !ftun_wolfssl_name_valid(options->server_name) ||
      options->maximum_plaintext == 0u ||
      options->maximum_plaintext > 1024u * 1024u ||
      options->server_name.length > (size_t)USHRT_MAX) return FTUN_E_INVALID;
  bool same_root = false;
  status = ftun_budget_same_root(context->budget, options->budget, &same_root);
  if (status != FTUN_OK || !same_root) return status == FTUN_OK ? FTUN_E_INVALID : status;
  if (options->server_name.length > SIZE_MAX - sizeof(*client) - 1u ||
      options->maximum_plaintext > SIZE_MAX - sizeof(*client) -
      options->server_name.length - 1u) return FTUN_E_LIMIT;
  /* 明文额度是单次 I/O 的逻辑预留，不是 wolfSSL 原生堆的计量。 */
  charge = sizeof(*client) + options->server_name.length + 1u +
           options->maximum_plaintext;
  status = ftun_budget_reserve(options->budget, charge, &reservation);
  if (status != FTUN_OK) return status;
  client = (ftun_tls_client_t *)calloc(1u, sizeof(*client));
  if (client == NULL) {
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  client->server_name = (char *)malloc(options->server_name.length + 1u);
  if (client->server_name == NULL) {
    free(client);
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  memcpy(client->server_name, options->server_name.data,
         options->server_name.length);
  client->server_name[options->server_name.length] = '\0';
  /* wolfSSL 的首次 new 会延迟分配 ctx->suites；只串行构造，读写不持锁。 */
  ftun_mutex_lock(&context->create_mutex);
  client->native = wolfSSL_new(context->native);
  ftun_mutex_unlock(&context->create_mutex);
  if (client->native == NULL) {
    free(client->server_name);
    free(client);
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  client->context = context;
  client->reservation = reservation;
  client->maximum_plaintext = options->maximum_plaintext;
  wolfSSL_SetIOReadCtx(client->native, client);
  wolfSSL_SetIOWriteCtx(client->native, client);
  ftun_ip_t ip;
  bool literal = ftun_ip_parse(client->server_name, options->server_name.length, &ip);
  /* 数值地址由verify_peer校验IP SAN；SNI只携带域名。 */
  if (literal) client->identity_ip = ip;
  wolfSSL_SetCertCbCtx(client->native, client);
  int identity = literal ? WOLFSSL_SUCCESS
    : wolfSSL_check_domain_name(client->native, client->server_name);
  if (identity != WOLFSSL_SUCCESS ||
      (!literal && wolfSSL_UseSNI(client->native, WOLFSSL_SNI_HOST_NAME,
                     client->server_name,
                     (unsigned short)options->server_name.length) !=
        WOLFSSL_SUCCESS)) {
    wolfSSL_free(client->native);
    free(client->server_name);
    free(client);
    ftun_reservation_release(&reservation);
    return FTUN_E_REJECTED;
  }
  (void)ftun_atomic_fetch_add(&context->clients, 1u);
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
  ftun_reservation_t reservation;
  bool owns_context;
  if (client == NULL) return FTUN_E_INVALID;
  owned = *client;
  if (owned == NULL) return FTUN_OK;
  context = owned->context;
  owns_context = owned->owns_context;
  reservation = owned->reservation;
  wolfSSL_free(owned->native);
  free(owned->server_name);
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *client = NULL;
  ftun_reservation_release(&reservation);
  (void)ftun_atomic_fetch_sub_explicit(&context->clients, 1u, FTUN_MEMORY_ACQ_REL);
  return owns_context ? ftun_wolfssl_context_destroy(&context) : FTUN_OK;
}

ftun_status_t ftun_wolfssl_context_destroy(ftun_tls_context_t **context)
{
  ftun_tls_context_t *owned;
  ftun_reservation_t reservation;
  if (context == NULL) return FTUN_E_INVALID;
  owned = *context;
  if (owned == NULL) return FTUN_OK;
  if (ftun_atomic_load(&owned->clients) != 0u) return FTUN_E_AGAIN;
  reservation = owned->reservation;
  wolfSSL_CTX_free(owned->native);
  ftun_mutex_destroy(&owned->create_mutex);
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *context = NULL;
  ftun_reservation_release(&reservation);
  return FTUN_OK;
}

ftun_status_t ftun_wolfssl_client_open(const ftun_tls_options_t *options,
  ftun_tls_client_t **out)
{
  ftun_tls_context_t *context = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (out == NULL) return FTUN_E_INVALID;
  status = ftun_wolfssl_prepare(options, &context);
  if (status != FTUN_OK) return status;
  status = ftun_wolfssl_client_create(context, options, out);
  if (status != FTUN_OK) (void)ftun_wolfssl_context_destroy(&context);
  else (*out)->owns_context = true;
  return status;
}
