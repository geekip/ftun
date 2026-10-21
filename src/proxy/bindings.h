#ifndef FTUN_PROXY_BINDINGS_H
#define FTUN_PROXY_BINDINGS_H

#include "network/resolver.h"
#include "event/event.h"
#include "proxy/dns/runtime_adapter.h"
#include "transport/path.h"
#include "tun/service.h"

/* Composition 注入的不可变工厂表。Proxy 在自己的 Budget 和 generation 下
 * 创建 Resolver/Path provider；backend context 只借用。需要 TUN 时，L3
 * provider 由 Composition 的物理 TUN owner 先发布；socket-only 组合为空。 */
typedef struct {
  /* Composition 拥有并由同一 owner 线程驱动；所有已装配 service 共用。 */
  ftun_event_loop_t *loop;
  ftun_resolver_provider_ops_t resolver;
  void *resolver_context;
  ftun_path_provider_ops_t path;
  void *path_context;
  /* DNS service 与 Proxy 平级装配；Proxy 只借用当前发布代。 */
  ftun_proxy_dns_runtime_adapter_t *dns;
  /* Proxy 拥有 FakeIP 身份服务；Composition 槽只传递显式借用。 */
  ftun_fakeip_service_t **fakeip_slot;
  const ftun_l3_provider_t *l3;
  /* prepare 阶段允许 owner 尚未发布；activate 前必须完成发布。 */
  bool l3_deferred;
} ftun_proxy_bindings_t;

bool ftun_proxy_bindings_valid(const ftun_proxy_bindings_t *bindings);

#endif
