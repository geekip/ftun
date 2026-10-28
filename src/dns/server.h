#ifndef FTUN_DNS_SERVER_H
#define FTUN_DNS_SERVER_H

#include "core/budget.h"
#include "core/operation.h"
#include "dns/cache.h"
#include "dns/upstream_set.h"

typedef void (*ftun_dns_transport_completion_fn)(
  void *user, ftun_status_t status, ftun_dns_transport_t transport,
  const ftun_endpoint_t *source, ftun_bytes_t response);

typedef struct {
  /* 借用 transport 所属实例；由 server inflight 保活至最终回调返回。 */
  const void *scope;
  uint32_t root_id;
  uint32_t leaf_id;
} ftun_dns_transport_binding_t;

typedef struct {
  /* 仅在逻辑查询首次 cache miss 后选择一次；失败清空输出且不取得资源。
   * binding 按值保存，UDP/TCP fallback 不再读取当前组状态。 */
  ftun_status_t (*select)(void *context, uint32_t root_id,
                          ftun_dns_transport_binding_t *out);
  /* 成功接纳后不得在 submit 返回前同步回调；response 仅借到回调返回。 */
  ftun_status_t (*submit)(void *context,
                          const ftun_dns_transport_binding_t *binding,
                          uint64_t policy_fingerprint,
                          uint64_t server_fingerprint,
                          const ftun_endpoint_t *upstream,
                          ftun_dns_transport_t transport,
                          ftun_bytes_t query, uint64_t deadline_ms,
                          ftun_dns_transport_completion_fn completion,
                          void *user, void **out_request);
  /* 成功后 transport 不再回调并清空原请求句柄；AGAIN 表示稍后重试取消。
   * 取消调用内允许同步交付原请求结果；server 保留结果至 Operation 仲裁，
   * 取消失败不丢结果，取消成功仅产生 CANCELLED 的 owner callback。 */
  ftun_status_t (*cancel)(void *context, void **request);
  void *context;
  /* 仅供成功结果校验使用的接收时刻；缺省仍使用 server.now。
   * 新查询与 TCP fallback 的准入必须继续检查真实当前期限。 */
  uint64_t (*response_now)(void *context);
} ftun_dns_query_transport_t;

typedef uint64_t (*ftun_dns_server_now_fn)(void *user);

typedef struct {
  ftun_budget_t *budget;
  ftun_operation_queue_t *operations;
  ftun_endpoint_t upstream;
  /* 可选，被借用：同一服务器的多个上游地址（配置顺序即优先级）及其被动健康。
   * 提供时 upstream 必须等于集合的第一个地址；网络类失败（超时、不可达）
   * 记入集合，并在剩余期限内最多换一个地址重试。 */
  ftun_upstream_set_t *upstream_set;
  uint32_t outbound_id;
  uint64_t fingerprint;
  ftun_dns_transport_t transport;
  bool tcp_fallback;
  bool fakeip;
  size_t max_response_bytes;
  ftun_dns_query_transport_t query_transport;
  ftun_dns_cache_t *cache; /* 可选借用。 */
  ftun_dns_server_now_fn now;
  void *now_user;
} ftun_dns_server_options_t;

typedef struct {
  uint32_t outbound_id;
  uint64_t fingerprint;
  size_t inflight;
  ftun_dns_transport_t transport;
  bool tcp_fallback;
  bool fakeip;
} ftun_dns_server_info_t;

ftun_status_t ftun_dns_server_create(const ftun_dns_server_options_t *options,
                                     ftun_dns_server_t **out);
ftun_status_t ftun_dns_server_get_info(const ftun_dns_server_t *server,
                                       ftun_dns_server_info_t *out);

/* 真实 DNS 传输。
 * server.outbound 只固定 QueryTransport 通道，入口只接受 REAL 请求；响应按
 * ID、Question、实际端点和 transport 关联。UDP TC 在同一 server/出口和
 * 原绝对 deadline 下切 TCP，不重新进行策略选择。接纳后复制全部请求字节，
 * 最终 completion 在 operation queue dispatch 时恰好一次收到借用响应。
 */
ftun_status_t ftun_dns_exchange(ftun_core_t *core,
                                const ftun_dns_server_t *server,
                                const ftun_dns_query_t *query,
                                ftun_operation_t **out);
/* 有在途请求时返回 AGAIN。cache/queue/transport 均由调用者拥有。 */
ftun_status_t ftun_dns_server_destroy(ftun_dns_server_t **server);

#endif
