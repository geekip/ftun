/* ftun_tls_client_open。 */
#include "tls.h"
#include "wolfssl_adapter.h"

ftun_status_t ftun_tls_client_open(const ftun_tls_options_t *options,
                                   const ftun_tls_io_t *io,
                                   ftun_tls_client_t **out)
{
  ftun_tls_context_t *context = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (out == NULL) return FTUN_E_INVALID;
  status = ftun_wolfssl_prepare(options, &context);
  if (status != FTUN_OK) return status;
  status = ftun_wolfssl_client_create(context, options, io, out);
  if (status != FTUN_OK) (void)ftun_wolfssl_context_destroy(&context);
  return status;
}

ftun_status_t ftun_tls_client_handshake(ftun_tls_client_t *client)
{ return ftun_wolfssl_client_handshake(client); }

ftun_status_t ftun_tls_client_read(ftun_tls_client_t *client,
                                   uint8_t *buffer, size_t capacity,
                                   size_t *length)
{ return ftun_wolfssl_client_read(client, buffer, capacity, length); }

ftun_status_t ftun_tls_client_write(ftun_tls_client_t *client,
                                    const uint8_t *buffer, size_t length,
                                    size_t *written)
{ return ftun_wolfssl_client_write(client, buffer, length, written); }

ftun_status_t ftun_tls_client_get_info(const ftun_tls_client_t *client,
                                       ftun_tls_info_t *out)
{ return ftun_wolfssl_client_info(client, out); }

ftun_status_t ftun_tls_client_destroy(ftun_tls_client_t **client)
{ return ftun_wolfssl_client_destroy(client); }
