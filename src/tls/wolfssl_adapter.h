#ifndef FTUN_TLS_WOLFSSL_ADAPTER_H
#define FTUN_TLS_WOLFSSL_ADAPTER_H
/* TASK-TLS-002 / TEST-TLS-002：ftun_wolfssl_prepare，目标 0.4.0。 */
#include "tls/tls.h"

/* TASK-TLS-002 / TEST-TLS-002：wolfSSL v5.8.4-stable 候选。 */
ftun_status_t ftun_wolfssl_prepare(const ftun_tls_options_t *options, ftun_tls_context_t **out);
ftun_status_t ftun_wolfssl_client_create(ftun_tls_context_t *context,
                                         const ftun_tls_options_t *options,
                                         const ftun_tls_io_t *io,
                                         ftun_tls_client_t **out);
ftun_status_t ftun_wolfssl_client_handshake(ftun_tls_client_t *client);
ftun_status_t ftun_wolfssl_client_read(ftun_tls_client_t *client,
                                       uint8_t *buffer, size_t capacity,
                                       size_t *length);
ftun_status_t ftun_wolfssl_client_write(ftun_tls_client_t *client,
                                        const uint8_t *buffer, size_t length,
                                        size_t *written);
ftun_status_t ftun_wolfssl_client_info(const ftun_tls_client_t *client,
                                       ftun_tls_info_t *out);
ftun_status_t ftun_wolfssl_client_destroy(ftun_tls_client_t **client);
ftun_status_t ftun_wolfssl_context_destroy(ftun_tls_context_t **context);
#endif
