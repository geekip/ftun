#ifndef FTUN_PROXY_RUNTIME_H
#define FTUN_PROXY_RUNTIME_H

#include "config/model.h"
#include "core/budget.h"
#include "core/operation.h"
#include "internal/contracts.h"
#include "proxy/bindings.h"

typedef struct ftun_proxy_runtime ftun_proxy_runtime_t;

typedef struct {
  size_t work;
  uint64_t busy_ms;
  uint64_t deadline_lateness_ms;
  bool quota_exhausted;
} ftun_proxy_runtime_run_usage_t;

typedef struct {
  size_t tcp_capacity;
  size_t tcp_active;
  size_t udp_flow_capacity;
  size_t udp_flow_active;
  size_t udp_association_capacity;
  size_t udp_association_active;
  size_t flow_resident_slabs;
  size_t udp_resident_slabs;
  size_t pending_resident_slabs;
  uint64_t stale_slot_rejections;
} ftun_proxy_runtime_capacity_info_t;

ftun_status_t ftun_proxy_runtime_datagram_capacity(
  const ftun_config_t *config, size_t *out);
ftun_status_t ftun_proxy_runtime_event_source_capacity(
  const ftun_config_t *config, size_t *out);

/* Linux v1 Proxy 数据面装配。prepare 在 Snapshot commit 前打开入站资源；
 * activate 只在 commit 成功后发布接纳。DNS 生命周期由平级 service 独立
 * 管理，Proxy 只通过 Composition 发布槽借用当前代。调用前 *out 必须为空；
 * 失败后非空输出仅供 destroy_until 重试清理，bindings/config 仍须存活。 */
ftun_status_t ftun_proxy_runtime_prepare(ftun_core_t *core, ftun_budget_t *budget,
                                  ftun_operation_queue_t *operations,
                                  const ftun_proxy_bindings_t *bindings,
                                  const ftun_config_t *config,
                                  uint64_t generation,
                                  ftun_proxy_runtime_t **out);
ftun_status_t ftun_proxy_runtime_activate(ftun_proxy_runtime_t *engine);
ftun_status_t ftun_proxy_runtime_reload_prepare(ftun_proxy_runtime_t *engine,
                                         const ftun_config_t *config,
                                         uint64_t generation);
ftun_status_t ftun_proxy_runtime_reload_prepare_planned(
  ftun_proxy_runtime_t *engine, const ftun_config_t *config, uint64_t generation,
  const void *plan);
ftun_status_t ftun_proxy_runtime_reload_commit(ftun_proxy_runtime_t *engine,
                                        uint64_t generation);
ftun_status_t ftun_proxy_runtime_reload_abort(ftun_proxy_runtime_t *engine);
ftun_status_t ftun_proxy_runtime_run_once(ftun_proxy_runtime_t *engine, bool may_block,
                                   ftun_proxy_runtime_run_usage_t *out_usage);
ftun_status_t ftun_proxy_runtime_get_capacity_info(
  ftun_proxy_runtime_t *engine, ftun_proxy_runtime_capacity_info_t *out);
ftun_status_t ftun_proxy_runtime_wakeup(ftun_proxy_runtime_t *engine);
ftun_status_t ftun_proxy_runtime_quiesce(ftun_proxy_runtime_t *engine);
ftun_status_t ftun_proxy_runtime_drain_until(ftun_proxy_runtime_t *engine,
                                             uint64_t deadline_ms);
ftun_status_t ftun_proxy_runtime_stop_until(ftun_proxy_runtime_t *engine,
                                     uint64_t deadline_ms);
ftun_status_t ftun_proxy_runtime_stop(ftun_proxy_runtime_t *engine);
ftun_status_t ftun_proxy_runtime_destroy_until(ftun_proxy_runtime_t **engine,
                                        uint64_t deadline_ms);
ftun_status_t ftun_proxy_runtime_destroy(ftun_proxy_runtime_t **engine);

#endif
