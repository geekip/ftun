#ifndef FTUN_CORE_RECOVERY_H
#define FTUN_CORE_RECOVERY_H
#include "util/types.h"
#include "core/limits.h"

/* 统一恢复调度器：把可失效实体（监听、DNS 上游、FRS 来源、探测、TUN 承载等）
 * 按“可用 → 等待恢复 → 尝试恢复”管理。纯状态机，只属于 owner 线程：
 * 不持有计时器，也不读时钟；调用方传入 now_ms，把 next_deadline 并入自己
 * 已有的期限汇总，到期后调用 run。实体槽在创建时按容量一次性准入。 */

typedef enum {
  FTUN_RECOVERY_AVAILABLE = 1,
  FTUN_RECOVERY_WAITING,
  FTUN_RECOVERY_ATTEMPTING
} ftun_recovery_state_t;

typedef enum {
  FTUN_RECOVERY_FAULT_NETWORK = 1,
  FTUN_RECOVERY_FAULT_RESOURCE,
  FTUN_RECOVERY_FAULT_AUTH,
  FTUN_RECOVERY_FAULT_CONFIG,
  FTUN_RECOVERY_FAULT_PROTOCOL
} ftun_recovery_fault_t;

typedef struct ftun_recovery_scheduler ftun_recovery_scheduler_t;

/* 实体和尝试共用的令牌；槽复用后旧令牌返回 STALE。同一实体同一时刻最多
 * 一次尝试，所以令牌同时标识这次尝试。 */
typedef struct {
  size_t slot;
  uint64_t generation;
} ftun_recovery_id_t;

typedef struct {
  uint64_t initial_ms;    /* 首次失败后的等待，候选值 1000 */
  uint64_t maximum_ms;    /* 退避上限，候选值 30000 */
  uint64_t stable_ms;     /* 持续可用多久才重置退避，候选值 60000 */
  uint32_t jitter_permille; /* 抖动幅度（千分比），候选值 200 */
  uint64_t auth_retry_ms; /* AUTH/CONFIG 类故障的固定低频重试间隔 */
  uint64_t seed;          /* 抖动用伪随机数种子，非密码学用途；0 取内置值 */
} ftun_recovery_policy_t;

typedef struct {
  /* 位掩码中的一位，供 trigger_kind 按类别提前尝试。 */
  uint32_t kind;
  /* 单次尝试的期限；0 表示不设期限。 */
  uint64_t attempt_timeout_ms;
  /* 开始一次尝试。返回 OK 表示已开始，结果必须用 attempt_finish 交回
   * （可在回调内同步交回）；返回非 OK 等同于这次尝试立即失败。 */
  ftun_status_t (*attempt)(void *user, ftun_recovery_id_t id);
  /* 期限到、注销或停止时请求取消；取消不等于结束，实体仍要 attempt_finish。 */
  void (*cancel)(void *user, ftun_recovery_id_t id);
  void *user;
} ftun_recovery_spec_t;

typedef struct {
  bool in_use;
  bool retiring;
  ftun_recovery_id_t id;
  uint32_t kind;
  ftun_recovery_state_t state;
  ftun_recovery_fault_t fault;
  uint32_t failures;
  uint64_t next_ms;
} ftun_recovery_info_t;

ftun_status_t ftun_recovery_scheduler_create(ftun_budget_t *budget,
  size_t capacity, const ftun_recovery_policy_t *policy,
  ftun_recovery_scheduler_t **out);
/* 停止后不再接受触发和新尝试，并请求取消全部进行中的尝试。 */
void ftun_recovery_scheduler_stop(ftun_recovery_scheduler_t *scheduler);
/* 仍有尝试未结束时返回 AGAIN，调度器保持有效。 */
ftun_status_t ftun_recovery_scheduler_destroy(
  ftun_recovery_scheduler_t **scheduler);

/* 新实体处于 AVAILABLE。槽用尽返回 LIMIT。 */
ftun_status_t ftun_recovery_entity_register(
  ftun_recovery_scheduler_t *scheduler, const ftun_recovery_spec_t *spec,
  uint64_t now_ms, ftun_recovery_id_t *out);
/* 未在尝试则立即释放；正在尝试则请求取消，槽保留到 attempt_finish。 */
ftun_status_t ftun_recovery_entity_unregister(
  ftun_recovery_scheduler_t *scheduler, ftun_recovery_id_t id);

/* 仅对 AVAILABLE 的实体生效；已在等待或尝试中的实体忽略。 */
ftun_status_t ftun_recovery_report_failure(
  ftun_recovery_scheduler_t *scheduler, ftun_recovery_id_t id,
  uint64_t now_ms, ftun_recovery_fault_t fault);
/* 实体在尝试之外自行恢复（例如外部重新打开了监听）。 */
/* 结束一次尝试。fault 仅在 status 非 OK 时使用。期限已到的尝试无论结果
 * 如何都按失败处理。 */
ftun_status_t ftun_recovery_attempt_finish(
  ftun_recovery_scheduler_t *scheduler, ftun_recovery_id_t id,
  uint64_t now_ms, ftun_status_t status, ftun_recovery_fault_t fault);

/* 把匹配 kind 的、处于 WAITING 的网络/资源/协议类实体提前到 now_ms；
 * AUTH/CONFIG 类不参与。同一轮内的多次触发自然合并。 */
void ftun_recovery_trigger_kind(ftun_recovery_scheduler_t *scheduler,
  uint32_t kind_mask, uint64_t now_ms);
/* 处理到期的尝试与期限，最多 quota 个动作。 */
ftun_status_t ftun_recovery_run(ftun_recovery_scheduler_t *scheduler,
  uint64_t now_ms, size_t quota, size_t *out_work);
/* 最早需要调用 run 的时刻；没有则 present 为 false。 */
ftun_status_t ftun_recovery_next_deadline(
  const ftun_recovery_scheduler_t *scheduler, uint64_t *out, bool *present);
/* 按槽下标查询，index 从 0 到 capacity-1。 */
ftun_status_t ftun_recovery_query(const ftun_recovery_scheduler_t *scheduler,
  size_t index, ftun_recovery_info_t *out);

#endif
