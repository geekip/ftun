#ifndef FTUN_DNS_SERVICE_H
#define FTUN_DNS_SERVICE_H

#include "config/model.h"
#include "core/budget.h"
#include "core/operation.h"
#include "dns/dispatcher.h"
#include "event/event.h"
#include "internal/contracts.h"

#include <stdbool.h>

typedef struct ftun_dns_runtime ftun_dns_runtime_t;
#ifndef FTUN_DNS_RUNTIME_PLAN_T_DEFINED
#define FTUN_DNS_RUNTIME_PLAN_T_DEFINED 1
typedef struct ftun_dns_runtime_plan ftun_dns_runtime_plan_t;
#endif

typedef ftun_status_t (*ftun_dns_group_select_fn)(
  void *user, uint32_t group_id, uint32_t *out_member);

typedef struct {
  ftun_dns_group_select_fn select_member;
  ftun_dns_dispatch_fn dispatch;
  void *user;
} ftun_dns_runtime_adapter_t;

ftun_status_t ftun_dns_runtime_prepare(
  ftun_core_t *core, ftun_budget_t *budget,
  ftun_operation_queue_t *operations, ftun_event_loop_t *loop,
  const ftun_config_t *config, const ftun_dns_runtime_adapter_t *adapter,
  uint32_t socket_mark,
  ftun_dns_runtime_t **out);
ftun_status_t ftun_dns_runtime_prepare_reload(
  const ftun_dns_runtime_t *active, ftun_core_t *core,
  ftun_budget_t *budget, ftun_operation_queue_t *operations,
  ftun_event_loop_t *loop,
  const ftun_config_t *config, const ftun_dns_runtime_adapter_t *adapter,
  uint32_t socket_mark,
  ftun_dns_runtime_t **out);
ftun_status_t ftun_dns_runtime_plan_prepare(const ftun_config_t *config,
                                           uint32_t socket_mark,
                                           ftun_dns_runtime_plan_t **out);
ftun_status_t ftun_dns_runtime_plan_destroy(ftun_dns_runtime_plan_t **plan);
ftun_status_t ftun_dns_runtime_prepare_reload_planned(
  const ftun_dns_runtime_t *active, ftun_core_t *core,
  ftun_budget_t *budget, ftun_operation_queue_t *operations,
  ftun_event_loop_t *loop,
  const ftun_config_t *config, const ftun_dns_runtime_adapter_t *adapter,
  uint32_t socket_mark,
  const ftun_dns_runtime_plan_t *plan, ftun_dns_runtime_t **out);
ftun_status_t ftun_dns_runtime_commit_reload(ftun_dns_runtime_t **active,
                                             ftun_dns_runtime_t **prepared,
                                             ftun_dns_runtime_t **retired);
/* Quiesced old generations finish accepted work before their resources are
 * reclaimed. AGAIN means the bounded retired slot is still in use. */
ftun_status_t ftun_dns_runtime_reap(ftun_dns_runtime_t **retired);
ftun_status_t ftun_dns_runtime_activate(ftun_dns_runtime_t *dns);
ftun_status_t ftun_dns_runtime_run_once(ftun_dns_runtime_t *dns, size_t quota,
                                       size_t *out_work);
bool ftun_dns_runtime_has_ready(const ftun_dns_runtime_t *dns);
ftun_status_t ftun_dns_runtime_next_deadline(
  const ftun_dns_runtime_t *dns, uint64_t *out_deadline_ms, bool *out_present);
bool ftun_dns_runtime_has_hijack(const ftun_dns_runtime_t *dns);
/* 返回显式借用的 dispatcher；借用期不得超过 dns 实例。 */
ftun_status_t ftun_dns_runtime_dispatcher(ftun_dns_runtime_t *dns,
                                        ftun_dns_dispatcher_t **out);
/* 停止接纳新查询但保留已接收请求的回复通道，重复调用幂等。 */
ftun_status_t ftun_dns_runtime_quiesce(ftun_dns_runtime_t *dns);
/* Takes ownership of descriptor on success and attaches it to the same
 * policy DNS protocol used by TUN UDP/53 hijack. */
ftun_status_t ftun_dns_runtime_hijack_tcp(ftun_dns_runtime_t *dns,
                                         int descriptor);
ftun_status_t ftun_dns_runtime_hijack_udp(
  ftun_dns_runtime_t *dns, ftun_datagram_t *inbound,
  const ftun_endpoint_t *client, const ftun_packet_t *packet);
ftun_status_t ftun_dns_runtime_stop(ftun_dns_runtime_t *dns);
ftun_status_t ftun_dns_runtime_destroy(ftun_dns_runtime_t **dns);

#endif
