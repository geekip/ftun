#ifndef FTUN_DNS_DISPATCHER_H
#define FTUN_DNS_DISPATCHER_H

#include "dns/bootstrap.h"
#include "dns/server.h"

typedef ftun_status_t (*ftun_dns_server_select_fn)(uint32_t outbound_id,
                                                   size_t *out_server,
                                                   void *user);
typedef ftun_status_t (*ftun_dns_named_server_select_fn)(ftun_string_t name,
                                                         size_t *out_server,
                                                         void *user);
typedef ftun_status_t (*ftun_dns_dispatch_fn)(
  void *user, ftun_core_t *core, ftun_dns_dispatcher_t *dispatcher,
  const ftun_dns_query_t *query, ftun_operation_t **out);

typedef struct {
  ftun_budget_t *budget;
  /* POLICY 裸出口 ID 的配置作用域；宿主保活，固定 server 入口可为空。 */
  const ftun_config_t *config_scope;
  ftun_operation_queue_t *operations;
  ftun_dns_server_t *const *servers;
  size_t server_count;
  ftun_dns_server_select_fn select_server;
  ftun_dns_named_server_select_fn select_named_server;
  void *select_user;
} ftun_dns_dispatcher_options_t;

typedef struct {
  size_t server_count;
  size_t inflight_local;
} ftun_dns_dispatcher_info_t;

ftun_status_t ftun_dns_dispatcher_create(
  const ftun_dns_dispatcher_options_t *options, ftun_dns_dispatcher_t **out);
ftun_status_t ftun_dns_dispatcher_get_info(
  const ftun_dns_dispatcher_t *dispatcher, ftun_dns_dispatcher_info_t *out);

/* 供业务策略分派函数（ftun_dns_dispatch_fn）使用的只读访问，不暴露私有布局。
 * dispatcher 只在分派回调期间借用；server 句柄借用至该回调返回。 */
ftun_status_t ftun_dns_dispatcher_validate(
  const ftun_dns_dispatcher_t *dispatcher, const ftun_dns_query_t *query);
const ftun_config_t *ftun_dns_dispatcher_config_scope(
  const ftun_dns_dispatcher_t *dispatcher);
ftun_status_t ftun_dns_dispatcher_select(
  const ftun_dns_dispatcher_t *dispatcher, uint32_t outbound_id,
  size_t *out_server);
/* 未配置按名选择时返回 UNSUPPORTED。 */
ftun_status_t ftun_dns_dispatcher_select_named(
  const ftun_dns_dispatcher_t *dispatcher, ftun_string_t name,
  size_t *out_server);
/* 越界返回 INVALID。 */
ftun_status_t ftun_dns_dispatcher_server(
  const ftun_dns_dispatcher_t *dispatcher, size_t index,
  ftun_dns_server_t **out);
/* DNS 原语：把 wire 名称转为点分主机名；由 dispatcher 直接合成本地回答。 */
ftun_status_t ftun_dns_name_domain(ftun_dns_name_t name, char output[254],
                                   size_t *out_length);
ftun_status_t ftun_dns_local_answer(ftun_dns_dispatcher_t *dispatcher,
                                    const ftun_dns_query_t *query,
                                    uint16_t rcode, int with_address,
                                    uint32_t address,
                                    ftun_operation_t **out);

/* 固定与策略 DNS 入口。
 * FIXED 直接使用 fixed_server；POLICY 只按当前已知元数据求值并把业务出口
 * 映射为 DNS server。real_only 禁止进入 POLICY，避免内部 REAL 递归。
 * fake-ip server 对 A 合成全局身份，对 AAAA/SVCB/HTTPS 返回 NOERROR 空答；
 * 其他类型和所有 REAL 请求进入真实 QueryTransport。
 */
/* 不读取 Proxy route/runtime 的固定 server 分派，供独立 DNS service 使用。 */
ftun_status_t ftun_dns_dispatch_fixed(void *user, ftun_core_t *core,
                                      ftun_dns_dispatcher_t *dispatcher,
                                      const ftun_dns_query_t *query,
                                      ftun_operation_t **out);
ftun_status_t ftun_dns_dispatcher_destroy(ftun_dns_dispatcher_t **dispatcher);

#endif
