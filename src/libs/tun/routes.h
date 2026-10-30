#ifndef FTUN_LIBS_TUN_ROUTES_H
#define FTUN_LIBS_TUN_ROUTES_H
#include "util/types.h"
#include "libs/transport/view.h"
#include "platform/route.h"

/* 动态路由事务使用非阻塞 平台路由接口，并把 fd/timer 挂到 owner loop。
 * total_deadline_ms 是绝对单调毫秒；step_timeout_ms 限制单个 ACK/dump。
 * 每个资源先核验不存在再 CREATE|EXCL。ACK 超时必须 dump reconcile，
 * 无法确认的资源按可能已创建保留所有权并进入可重试清理状态。 */
ftun_status_t ftun_route_async_start(
  const ftun_route_policy_t *policy, ftun_event_loop_t *loop,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  ftun_route_async_t **out);
/* 测试与受控宿主注入；io/context 借用至 destroy，initial_sequence 不能为 0。 */
ftun_status_t ftun_route_async_start_with_io(
  const ftun_route_policy_t *policy, const ftun_route_async_io_t *io,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  uint32_t initial_sequence, ftun_route_async_t **out);
/* NetworkView 使用的通用有界资源计划。guard plan 只含持久拒绝兜底，
 * overlay plan 只含当前可达路径；调用方必须先提交 guard 再发布路径。 */
ftun_status_t ftun_route_async_start_plan(
  const ftun_route_plan_t *plan, ftun_event_loop_t *loop,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  ftun_route_async_t **out);
ftun_status_t ftun_route_async_start_plan_with_io(
  const ftun_route_plan_t *plan, const ftun_route_async_io_t *io,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  uint32_t initial_sequence, ftun_route_async_t **out);
/* 将同步启动事务的资源及撤销责任转交给非阻塞事务，不发任何路由变更。
 * 成功清空 source；分配、Event 或参数失败时 source 保持原样。部分同步
 * 清理失败的资源也可以接管，但只能继续 release，不能当作 READY 发布。 */
ftun_status_t ftun_route_async_adopt(
  ftun_route_transaction_t **source, ftun_event_loop_t *loop,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  ftun_route_async_t **out);
ftun_status_t ftun_route_async_adopt_with_io(
  ftun_route_transaction_t **source, const ftun_route_async_io_t *io,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  uint32_t initial_sequence, ftun_route_async_t **out);
ftun_status_t ftun_route_guard_plan(
  const ftun_network_view_t *view, uint32_t table, uint32_t first_priority,
  ftun_route_plan_t *out);
ftun_status_t ftun_route_overlay_plan(
  const ftun_network_view_t *view, ftun_string_t tun_interface,
  uint32_t table, uint32_t metric, ftun_route_plan_t *out);
/* 对已 READY 的事务做对账修复：按计划顺序（地址、保护规则、路由、捕获规则）
 * 逐项核验，已存在的保持，缺失的重新添加。不重建整个事务，任何失败都回到
 * READY 并记录 repair_result，已有资源保持原所有权；下次对账可以重试。
 * 仅 READY 可调用，否则返回 AGAIN（进行中）或 INVALID。 */
ftun_status_t ftun_route_async_repair(
  ftun_route_async_t *operation, uint64_t now_ms,
  uint64_t total_deadline_ms);
/* 单轮最多处理 max_work 个提交或回复；不会等待 I/O。 */
ftun_status_t ftun_route_async_run(ftun_route_async_t *operation,
                                         uint64_t now_ms, size_t max_work,
                                         size_t *out_work);
ftun_status_t ftun_route_async_next_deadline(
  const ftun_route_async_t *operation, uint64_t *out_deadline,
  bool *out_present);
ftun_status_t ftun_route_async_get_info(
  const ftun_route_async_t *operation,
  ftun_route_async_info_t *out);
/* APPLYING 时请求 release 会取消安装并反序清理；清理失败后可用新期限重试。 */
ftun_status_t ftun_route_async_release(
  ftun_route_async_t *operation, uint64_t now_ms,
  uint64_t total_deadline_ms);
/* 只有无活动/不确定资源的终态可销毁；其余返回 AGAIN 并保留句柄。 */
ftun_status_t ftun_route_async_destroy(
  ftun_route_async_t **operation);

/* Linux 路由资源事务。
 * 实现路径：记录实例所有权；保护与 TUN 路由按序准备；冲突拒绝、失败反序撤销；本机/LAN 分别验收，退出不改他人规则。
 * 调用边界：不访问配置 AST，不跨线程修改 Session。
 * policy 仅在调用期间借用，成功 transaction 拥有已安装资源记录。
 * 本机范围使用 iif lo，LAN 范围必须显式提供接口；strict-route 只阻断同一范围 IPv6。
 * 冲突返回 rejected；普通失败完成逆序回滚并清空输出。
 * 若回滚本身失败则返回 state-corrupt 并交付 transaction，调用者必须重试 release。
 */
/* 系统事务持有对象额度，同步调用期间准入一个控制FD。 */
ftun_status_t ftun_route_prepare_with_budget(ftun_budget_t *budget,
  const ftun_route_policy_t *policy, ftun_route_transaction_t **out);
ftun_status_t ftun_route_prepare_with_io_and_budget(ftun_budget_t *budget,
  const ftun_route_policy_t *policy, const ftun_route_io_t *io,
  ftun_route_transaction_t **out);
ftun_status_t ftun_route_prepare(const ftun_route_policy_t *policy, ftun_route_transaction_t **out);
/* 测试与受控宿主注入；操作表会复制，context 必须比 transaction 长寿。 */
ftun_status_t ftun_route_prepare_with_io(const ftun_route_policy_t *policy,
                                               const ftun_route_io_t *io,
                                               ftun_route_transaction_t **out);
ftun_status_t ftun_route_get_info(const ftun_route_transaction_t *transaction,
                                        ftun_route_info_t *out);
/* 逆序删除仍活动的自有资源；部分失败保留句柄和失败项供重试。 */
ftun_status_t ftun_route_release(ftun_route_transaction_t **transaction);
size_t ftun_route_async_allocation_size(void);
#endif
