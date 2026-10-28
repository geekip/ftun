#ifndef FTUN_PROXY_HTTP_FETCH_H
#define FTUN_PROXY_HTTP_FETCH_H

#include "core/budget.h"
#include "proxy/control_resolver.h"
#include "internal/contracts.h"

typedef struct {
  ftun_budget_t *budget;
  ftun_string_t url;
  ftun_endpoint_t proxy;
  char proxy_domain[FTUN_CONTROL_ENDPOINT_TEXT_BYTES];
  ftun_string_t proxy_username;
  ftun_string_t proxy_password;
  ftun_string_t if_none_match;
  size_t maximum_bytes;
  uint64_t deadline_ms;
  uint32_t socket_mark;
  uint64_t generation;
  ftun_dial_purpose_t purpose;
  ftun_control_path_binding_t path;
  bool allow_system_resolver;
  ftun_control_resolver_plan_t resolver;
  bool use_proxy;
} ftun_http_fetch_spec_t;

typedef struct {
  uint8_t *data;
  size_t length;
  char *etag;
  unsigned int status;
  bool tls_verified;
  /* 正文与ETag分别拥有实际分配额度，release统一消费。 */
  ftun_reservation_t *reservation;
  ftun_reservation_t *etag_reservation;
} ftun_http_fetch_result_t;

ftun_status_t ftun_http_fetch(const ftun_http_fetch_spec_t *spec,
                              ftun_http_fetch_result_t *out);
/* Resolve a configured DIRECT/SOCKS5/group path into the transport fields in
 * spec.  runtime may be NULL during initial FRS bootstrap; group defaults are
 * used until an active Runtime exists. */
ftun_status_t ftun_http_fetch_route(const ftun_config_t *config,
                                    const ftun_runtime_t *runtime,
                                    const char *outbound_name,
                                    ftun_http_fetch_spec_t *spec);
/* Select the local resolver used for every URL host, including redirects.
 * Empty server means Bootstrap (or SystemResolver when DNS is disabled). */
ftun_status_t ftun_http_fetch_resolver(const ftun_config_t *config,
                                       const ftun_runtime_t *runtime,
                                       ftun_string_t server,
                                       ftun_http_fetch_spec_t *spec);
/* 解析一个完整的 HTTP 响应（可原地去掉分块编码，所以 wire 必须可写）。成功时
 * 正文在 wire 开头、长度在 out->length；etag 与 location 由调用方释放。导出是为了让
 * fuzz 目标直接喂入不可信字节，不经过网络。 */
ftun_status_t ftun_http_fetch_parse_response(
  ftun_budget_t *budget, uint8_t *wire, size_t wire_length, size_t maximum,
  ftun_http_fetch_result_t *out, char **location,
  ftun_reservation_t **location_reservation);
void ftun_http_fetch_release(ftun_http_fetch_result_t *result);

#endif
