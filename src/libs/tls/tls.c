#include "libs/tls/tls.h"
#include "libs/tls/wolfssl_adapter.h"
ftun_status_t ftun_tls_context_open(const ftun_tls_options_t *options, ftun_tls_context_t **out)
{
  return ftun_wolfssl_prepare(options, out);
}
ftun_status_t ftun_tls_context_destroy(ftun_tls_context_t **context)
{
  return ftun_wolfssl_context_destroy(context);
}
ftun_status_t ftun_tls_client_create(ftun_tls_context_t *context,
  const ftun_tls_options_t *options, ftun_tls_client_t **out)
{
  return ftun_wolfssl_client_create(context, options, out);
}
ftun_status_t ftun_tls_client_open(const ftun_tls_options_t *options, ftun_tls_client_t **out)
{
  return ftun_wolfssl_client_open(options, out);
}
ftun_status_t ftun_tls_client_handshake(ftun_tls_client_t *client)
{
  return ftun_wolfssl_client_handshake(client);
}
ftun_status_t ftun_tls_client_read(ftun_tls_client_t *client,
  uint8_t *buffer, size_t capacity, size_t *length)
{
  return ftun_wolfssl_client_read(client, buffer, capacity, length);
}
ftun_status_t ftun_tls_client_write(ftun_tls_client_t *client,
  const uint8_t *buffer, size_t length, size_t *written)
{
  return ftun_wolfssl_client_write(client, buffer, length, written);
}
ftun_status_t ftun_tls_client_get_info(const ftun_tls_client_t *client, ftun_tls_info_t *out)
{
  return ftun_wolfssl_client_info(client, out);
}
ftun_status_t ftun_tls_client_destroy(ftun_tls_client_t **client)
{
  return ftun_wolfssl_client_destroy(client);
}
