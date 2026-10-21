#ifndef FTUN_NETWORK_RESOLVER_H
#define FTUN_NETWORK_RESOLVER_H

#include "network/view.h"
#include "platform/system_resolver.h"

typedef struct ftun_resolver_provider ftun_resolver_provider_t;

/* Resolver Provider 只把域名解析为有界候选地址，不建立业务连接。
 * system 的异步输入按原契约在接纳前复制；generation、purpose 和 domain
 * 是不可省略的路径身份，防止 reload 后把旧结果写入新代。 */
typedef struct {
  ftun_system_resolve_request_t system;
  uint64_t generation;
  ftun_dial_purpose_t purpose;
  ftun_dial_domain_t requested_domain;
} ftun_resolver_provider_request_t;

typedef struct {
  ftun_status_t (*start)(void *context, ftun_core_t *core,
                         const ftun_resolver_provider_request_t *request,
                         ftun_operation_t **out);
  ftun_status_t (*reload_prepare)(void *context, uint64_t generation);
  void (*reload_commit)(void *context, uint64_t generation);
  void (*reload_abort)(void *context, uint64_t generation);
  ftun_status_t (*quiesce)(void *context);
  ftun_status_t (*stop_until)(void *context, uint64_t deadline_ms);
} ftun_resolver_provider_ops_t;

typedef struct {
  ftun_budget_t *budget;
  uint64_t generation;
  ftun_resolver_provider_ops_t ops;
  /* 借用；必须比 provider 及其全部已接纳 operation 长寿。 */
  void *context;
} ftun_resolver_provider_spec_t;

typedef struct {
  uint64_t generation;
  uint64_t pending_generation;
  bool accepting;
  bool stopped;
  bool reload_prepared;
} ftun_resolver_provider_info_t;

/* Provider 拥有自身预算 reservation，借用 backend context。接纳成功必须
 * 返回唯一 operation；取消统一走 ftun_operation_cancel。reload prepare
 * 只预留下一代，commit 不失败；旧代已接纳 operation 可继续终结。 */
ftun_status_t ftun_resolver_provider_create(
  const ftun_resolver_provider_spec_t *spec,
  ftun_resolver_provider_t **out);
ftun_status_t ftun_resolver_provider_start(
  ftun_resolver_provider_t *provider, ftun_core_t *core,
  const ftun_resolver_provider_request_t *request,
  ftun_operation_t **out);
ftun_status_t ftun_resolver_provider_reload_prepare(
  ftun_resolver_provider_t *provider, uint64_t generation);
ftun_status_t ftun_resolver_provider_reload_commit(
  ftun_resolver_provider_t *provider, uint64_t generation);
ftun_status_t ftun_resolver_provider_reload_abort(
  ftun_resolver_provider_t *provider);
ftun_status_t ftun_resolver_provider_quiesce(
  ftun_resolver_provider_t *provider);
ftun_status_t ftun_resolver_provider_stop_until(
  ftun_resolver_provider_t *provider, uint64_t deadline_ms);
ftun_status_t ftun_resolver_provider_get_info(
  const ftun_resolver_provider_t *provider,
  ftun_resolver_provider_info_t *out);
ftun_status_t ftun_resolver_provider_destroy(
  ftun_resolver_provider_t **provider);

#endif
