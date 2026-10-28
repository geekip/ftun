#ifndef FTUN_DNS_UPSTREAM_SET_H
#define FTUN_DNS_UPSTREAM_SET_H
#include "core/budget.h"
#include "core/recovery.h"

/* 一个 DNS 服务器的多个上游地址及其被动健康状态。
 * 配置顺序就是优先级；每个地址是一个恢复实体（A0）。健康只由真实查询的
 * 网络类失败触发：失败的地址进入退避，到期后恢复为“可以再试一次”，
 * 不会自己发起探测。本模块只属于 owner 线程。 */
#define FTUN_UPSTREAM_SET_MAX 4u
/* A0 的 kind 位：供 trigger_kind 在网络变化时提前所有 DNS 上游的重试。 */
#define FTUN_UPSTREAM_SET_RECOVERY_KIND UINT32_C(2)

typedef struct ftun_upstream_set ftun_upstream_set_t;
typedef uint64_t (*ftun_upstream_now_fn)(void *user);

/* endpoints 按优先级排列并被复制；scheduler 被借用，须晚于集合销毁。 */
ftun_status_t ftun_upstream_set_create(ftun_budget_t *budget,
  ftun_recovery_scheduler_t *scheduler, const ftun_endpoint_t *endpoints,
  size_t count, ftun_upstream_now_fn now, void *now_user,
  ftun_upstream_set_t **out);
ftun_status_t ftun_upstream_set_destroy(ftun_upstream_set_t **set);
size_t ftun_upstream_set_count(const ftun_upstream_set_t *set);
const ftun_endpoint_t *ftun_upstream_set_endpoint(
  const ftun_upstream_set_t *set, size_t index);
/* 取 after 之后第一个可用地址；after 为 SIZE_MAX 表示从头开始。
 * recovering 为真表示该地址刚从失败中恢复，只应给它较短的试探期限。
 * 没有可用地址返回 IO（调用方应立即失败，不阻塞）。 */
ftun_status_t ftun_upstream_set_pick(ftun_upstream_set_t *set, size_t after,
  size_t *out_index, bool *out_recovering);
/* 网络类失败（超时、不可达、连接中断）。上游自己返回的 SERVFAIL/REFUSED 不算。 */
void ftun_upstream_set_report_failure(ftun_upstream_set_t *set, size_t index);
#endif
