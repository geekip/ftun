#ifndef FTUN_LIBS_RESOLVER_RESOLVER_H
#define FTUN_LIBS_RESOLVER_RESOLVER_H

#include "libs/transport/view.h"
#include "libs/resolver/system.h"
#include "core/event/loop.h"

typedef struct ftun_resolver_provider ftun_resolver_provider_t;
typedef struct ftun_resolver_scope ftun_resolver_scope_t;

#define FTUN_RESOLVER_MAX_SERVERS 16u

typedef enum {
  FTUN_RESOLVER_SYSTEM = 0,
  FTUN_RESOLVER_BOOTSTRAP,
  FTUN_RESOLVER_NAMED
} ftun_resolver_source_t;

/* Resolver Provider 只把域名解析为有界候选地址，不建立业务连接。
 * system 的异步输入按原契约在接纳前复制；generation、purpose 和 domain
 * 是不可省略的路径身份，防止 reload 后把旧结果写入新代。 */
typedef struct {
  ftun_system_resolve_request_t system;
  uint64_t generation;
  ftun_dial_purpose_t purpose;
  ftun_dial_domain_t requested_domain;
  /* system 保存共同域名、预算、期限、保护与完成参数。来源由宿主显式
   * 选择，工厂不得在失败后改用另一来源；输入只借用至 start 返回。 */
  ftun_resolver_source_t source;
  ftun_event_loop_t *loop;
  ftun_operation_queue_t *operations;
  ftun_string_t resolver_name;
  const ftun_endpoint_t *servers;
  size_t server_count;
  const ftun_network_view_t *network_view;
  uint64_t network_generation;
  uint16_t query_id;
} ftun_resolver_provider_request_t;

typedef struct {
  /* 零接纳失败必须清空 out 且零回调；接纳前复制借用输入。完成必须由
   * owner 派发、恰好一次，不能在 start 或取消 hook 内联回调。 */
  ftun_status_t (*start)(void *context, ftun_core_t *core,
                         const ftun_resolver_provider_request_t *request,
                         ftun_operation_t **out);
  /* 失败仍保留 pending generation，必须调用同步 reload_abort 回收；
   * reload_commit 仅允许完整 prepare 成功后调用。 */
  ftun_status_t (*reload_prepare)(void *context, uint64_t generation);
  void (*reload_commit)(void *context, uint64_t generation);
  void (*reload_abort)(void *context, uint64_t generation);
  /* 失败后接纳已关闭，但后端 quiesce 仍会在下次清理时重试。 */
  ftun_status_t (*quiesce)(void *context);
  ftun_status_t (*stop_until)(void *context, uint64_t deadline_ms);
} ftun_resolver_provider_ops_t;

typedef struct {
  ftun_budget_t *budget;
  uint64_t generation;
  ftun_resolver_provider_ops_t ops;
  /* 借用；必须比 provider 及其全部已接纳 operation 长寿。 */
  void *context;
  /* 零采用 4096；分别限制在途请求与配置范围，不能无界排队。 */
  size_t max_pending;
  size_t max_scopes;
} ftun_resolver_provider_spec_t;

typedef struct {
  uint64_t generation;
  uint64_t pending_generation;
  bool accepting;
  bool stopped;
  bool reload_prepared;
  size_t pending;
  size_t scopes;
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
/* 仅在当前代接纳配置范围。旧范围可在 reload 后继续相同逻辑请求，
 * 不允许任意新请求声称属于旧代；quiesce 后禁止新解析。引用归 owner。 */
ftun_status_t ftun_resolver_provider_scope(ftun_resolver_provider_t *provider,
  uint64_t generation, ftun_resolver_scope_t **out);
ftun_status_t ftun_resolver_scope_retain(ftun_resolver_scope_t *scope);
ftun_status_t ftun_resolver_scope_release(ftun_resolver_scope_t **scope);
ftun_status_t ftun_resolver_scope_generation(const ftun_resolver_scope_t *scope,
  uint64_t *out);
ftun_status_t ftun_resolver_scope_start(ftun_resolver_scope_t *scope,
  ftun_core_t *core, const ftun_resolver_provider_request_t *request,
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
