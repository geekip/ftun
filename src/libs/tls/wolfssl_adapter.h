#ifndef FTUN_LIBS_TLS_WOLFSSL_ADAPTER_H
#define FTUN_LIBS_TLS_WOLFSSL_ADAPTER_H
/* ftun_wolfssl_prepare。 */
#include "libs/tls/tls.h"

/* wolfSSL v5.8.4-stable 候选。 */
ftun_status_t ftun_wolfssl_prepare(const ftun_tls_options_t *options, ftun_tls_context_t **out);
/* Context 保留拥有权，成功会话持有一份引用；会话可在不同 owner 使用。
 * Context 销毁与会话创建由宿主串行，会话推进/释放不共享可变会话状态。 */
ftun_status_t ftun_wolfssl_client_create(ftun_tls_context_t *context,
  const ftun_tls_options_t *options, ftun_tls_client_t **out);
ftun_status_t ftun_wolfssl_client_open(const ftun_tls_options_t *options,
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
