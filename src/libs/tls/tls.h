#ifndef FTUN_LIBS_TLS_TLS_H
#define FTUN_LIBS_TLS_TLS_H
/* ftun_tls_client_open。 */
#include "util/types.h"

typedef struct ftun_tls_client ftun_tls_client_t;

struct ftun_tls_options {
  ftun_budget_t *budget;
  ftun_string_t server_name;
  ftun_bytes_t ca_pem;
  const char *ca_file;
  size_t maximum_plaintext;
};

typedef struct {
  bool handshake_complete;
  bool peer_verified;
  bool wants_read;
  bool wants_write;
} ftun_tls_info_t;

/* Context 加载并验证 CA 后固定配置，可供多个会话共享；每个会话归自己的 owner。
 * context 的 budget 借用至销毁；会话可使用同根的其他预算节点。
 * 创建/销毁 context 须与创建会话串行；活跃会话存在时销毁返回 AGAIN。
 * 会话销毁只释放自身引用，不销毁显式拥有的 context。
 * wolfSSL 原生证书/堆开销未精确计量，不构成 native/RSS 硬限额。 */
ftun_status_t ftun_tls_context_open(const ftun_tls_options_t *options,
  ftun_tls_context_t **out);
ftun_status_t ftun_tls_context_destroy(ftun_tls_context_t **context);
/* 借用已校验的 context；只使用 options 的 budget/server_name/maximum_plaintext。
 * 包装对象、名字、双向有界密文缓冲及单次明文额度均先准入。
 * 所有会话接口只操作内存，不调用传输、线程或业务回调。 */
ftun_status_t ftun_tls_client_create(ftun_tls_context_t *context,
  const ftun_tls_options_t *options, ftun_tls_client_t **out);
/* 便利构造：该会话独占内部 context，销毁会话时一并销毁。 */
ftun_status_t ftun_tls_client_open(const ftun_tls_options_t *options,
  ftun_tls_client_t **out);
/* feed 复制已接纳前缀；缓冲满返回 AGAIN，调用方保有未接纳部分。
 * ciphertext 返回只读连续借用，consume 只消费已交付前缀；同一 owner 串行调用。
 * close_input 保留已入队字节，全部消费后向 TLS 报告传输 EOF。 */
size_t ftun_tls_client_input_space(const ftun_tls_client_t *client);
ftun_status_t ftun_tls_client_feed(ftun_tls_client_t *client, ftun_bytes_t bytes,
  size_t *consumed);
void ftun_tls_client_close_input(ftun_tls_client_t *client);
ftun_status_t ftun_tls_client_ciphertext(ftun_tls_client_t *client, ftun_bytes_t *out);
ftun_status_t ftun_tls_client_consume(ftun_tls_client_t *client, size_t length);
ftun_status_t ftun_tls_client_handshake(ftun_tls_client_t *client);
ftun_status_t ftun_tls_client_read(ftun_tls_client_t *client,
                                   uint8_t *buffer, size_t capacity,
                                   size_t *length);
ftun_status_t ftun_tls_client_write(ftun_tls_client_t *client,
                                    const uint8_t *buffer, size_t length,
                                    size_t *written);
ftun_status_t ftun_tls_client_get_info(const ftun_tls_client_t *client,
                                       ftun_tls_info_t *out);
ftun_status_t ftun_tls_client_destroy(ftun_tls_client_t **client);
#endif
