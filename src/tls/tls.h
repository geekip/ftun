#ifndef FTUN_TLS_TLS_H
#define FTUN_TLS_TLS_H
/* ftun_tls_client_open。 */
#include "internal/contracts.h"

typedef struct ftun_tls_client ftun_tls_client_t;

typedef ftun_status_t (*ftun_tls_io_read_fn)(void *user, uint8_t *buffer,
                                             size_t capacity,
                                             size_t *length);
typedef ftun_status_t (*ftun_tls_io_write_fn)(void *user,
                                              const uint8_t *buffer,
                                              size_t length,
                                              size_t *written);

typedef struct {
  ftun_tls_io_read_fn read;
  ftun_tls_io_write_fn write;
  void *user;
} ftun_tls_io_t;

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

/* 同步推进的非阻塞 TLS 客户端。底层 IO 的
 * AGAIN 被精确映射为 wants_read/wants_write；不允许关闭 peer/hostname 验证。
 * budget 为借用且必须比 client 长寿；准入会为包装对象、主机名和有界
 * 明文工作量保留逻辑预算；maximum_plaintext 限制单次 read/write，
 * 不表示预分配该大小的第一方缓冲。wolfSSL context/session、证书、
 * 原生缓冲和 allocator 开销未精确计量，不构成 native/RSS 硬限额。
 * options 与 io 只在 create 同步借用，backend 复制所需主机名与回调，
 * io.user 及其底层传输借用至 client 销毁；FD/队列由传输拥有方计量。 */
ftun_status_t ftun_tls_client_open(const ftun_tls_options_t *options,
                                   const ftun_tls_io_t *io,
                                   ftun_tls_client_t **out);
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
