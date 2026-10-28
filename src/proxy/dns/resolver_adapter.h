#ifndef FTUN_PROXY_DNS_RESOLVER_ADAPTER_H
#define FTUN_PROXY_DNS_RESOLVER_ADAPTER_H

#include "proxy/session.h"
#include "dns/bootstrap.h"
#include "network/resolver.h"

/* 路由前真实解析请求。session 必须处于 ROUTING、尚未固定出口且没有已有
 * 真实候选；query 携带唯一域名、deadline、保护策略和完成回调。
 * dns_enabled=false 时忽略 default_server/bootstrap 来源并强制 SystemResolver；
 * 启用时非空 default_server 只选择该命名 REAL resolver，空值只选 Bootstrap。
 */
struct ftun_resolve_request {
  const ftun_session_t *session;
  bool dns_enabled;
  ftun_string_t default_server;
  ftun_bootstrap_request_t query;
};

typedef struct {
  ftun_status_t (*system_resolve)(
    void *context, ftun_core_t *core,
    const ftun_system_resolve_request_t *request, ftun_operation_t **out);
  ftun_status_t (*bootstrap_resolve)(
    void *context, ftun_core_t *core,
    const ftun_bootstrap_request_t *request, ftun_operation_t **out);
  /* 实现必须以 REAL 模式查询已准备的命名 server；接纳异步请求前复制或
   * 固定 server identity，不得在失败后调用另一来源。 */
  ftun_status_t (*server_resolve)(
    void *context, ftun_core_t *core, ftun_string_t server,
    const ftun_bootstrap_request_t *request, ftun_operation_t **out);
  void *context;
} ftun_resolver_backend_t;

/* 按用途选择解析器。
 * 仅负责路由前 REAL 来源选择并原样转交子 Operation，不包装、不 fallback。
 * completion 应在 owner loop 用 ftun_session_store_resolved 把成功结果写回
 * 同一 Session，再调用 ftun_session_operation_complete；之后从原规则继续。
 * 已有结果或已固定出口返回 STALE 且零回调，防止二次解析覆盖候选。
 */
/* 显式 backend 的来源选择契约测试入口；生产消费者使用 Provider。 */
ftun_status_t ftun_resolve_real_with_backend(
  ftun_core_t *core, const ftun_resolve_request_t *request,
  const ftun_resolver_backend_t *backend, ftun_operation_t **out);

/* 生产来源选择入口。scope 在逻辑请求接纳时固定配置代次；命名来源由
 * Composition 绑定到该代 DNS 服务，接纳后不改用新代或其他来源。 */
ftun_status_t ftun_proxy_dns_resolve_with_provider(
  ftun_core_t *core, ftun_resolver_scope_t *scope, bool dns_enabled,
  ftun_string_t default_server, const ftun_bootstrap_request_t *query,
  ftun_dial_purpose_t purpose, ftun_operation_t **out);
ftun_status_t ftun_resolve_real_with_provider(ftun_core_t *core,
  const ftun_resolve_request_t *request, ftun_resolver_scope_t *scope,
  ftun_operation_t **out);

#endif
