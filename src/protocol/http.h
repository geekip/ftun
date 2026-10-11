#ifndef FTUN_PROTOCOL_HTTP_H
#define FTUN_PROTOCOL_HTTP_H
/* TASK-PROTOCOL-002 / TEST-PROTOCOL-002：ftun_http_decode，目标 0.4.0。 */

#include "internal/contracts.h"

#define FTUN_HTTP_MAX_HEADER_BYTES 16384u
#define FTUN_HTTP_MAX_METHOD_BYTES 16u
#define FTUN_HTTP_MAX_TARGET_BYTES 2048u

typedef enum {
  FTUN_HTTP_PROXY_FORWARD = 1,
  FTUN_HTTP_PROXY_CONNECT
} ftun_http_proxy_kind_t;

typedef struct {
  ftun_http_proxy_kind_t kind;
  ftun_string_t method;         /* 借用 input。 */
  ftun_string_t request_target; /* 借用 input。 */
  ftun_endpoint_t target;       /* DOMAIN 字符串借用 input。 */
  ftun_string_t proxy_authorization; /* 去除首尾 OWS 后借用 input。 */
  size_t header_bytes;
  uint64_t content_length;
  bool has_content_length;
  bool has_proxy_authorization;
  bool connection_close;
} ftun_http_request_t;

/* HTTP/1.0 与 HTTP/1.1 显式代理请求解析。
 * TASK-PROTOCOL-002 / TEST-PROTOCOL-002，目标 0.4.0。
 * 仅接纳 absolute-form http:// 与 CONNECT authority-form；拒绝 userinfo、
 * 分段/折叠头、重复 Host、TE/CL 冲突和无界数字。OK 时所有字符串同步借用
 * input，consumed 精确位于 body 首字节；AGAIN 时输出清零。 */
ftun_status_t ftun_http_decode_request(ftun_bytes_t input,
                                       ftun_http_request_t *out,
                                       size_t *consumed);

/* 将已校验的 absolute-form 正向代理请求改写为 origin-form，并移除只应在
 * 客户端与代理之间出现的代理认证/连接头。body 不在本函数处理范围内。 */
ftun_status_t ftun_http_rewrite_forward(
  ftun_bytes_t input, const ftun_http_request_t *request,
  uint8_t *output, size_t capacity, size_t *written);

/* 保留统一协议入口，只导出完成、消费长度和目标。 */
ftun_status_t ftun_http_decode(ftun_bytes_t input, ftun_protocol_result_t *out);

#endif
