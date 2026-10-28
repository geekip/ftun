#ifndef FTUN_TLS_WOLFSSL_ADAPTER_H
#define FTUN_TLS_WOLFSSL_ADAPTER_H
/* ftun_wolfssl_prepare。 */
#include "tls/tls.h"

/* wolfSSL v5.8.4-stable 候选。 */
ftun_status_t ftun_wolfssl_prepare(const ftun_tls_options_t *options, ftun_tls_context_t **out);
/* context 与 client 由同一 owner 串行使用。成功时 context 所有权转给唯一
 * client，调用方不再销毁或复用；失败时 context 保留，可重试或销毁。
 * client 按实际 options 单独准入，budget 必须等于 prepare 的借用节点。
 * 持有 client 时重复创建或销毁 context 返回 AGAIN，不释放其资源。 */
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
