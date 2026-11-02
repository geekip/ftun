#ifndef FTUN_CORE_LOG_AGGREGATE_H
#define FTUN_CORE_LOG_AGGREGATE_H
#include "core/log/log.h"

#define FTUN_LOG_AGGREGATE_CAPACITY 256u
#define FTUN_LOG_AGGREGATE_WINDOW_MS UINT64_C(60000)
#define FTUN_LOG_AGGREGATE_DETAIL_FIELDS (FTUN_LOG_MAX_FIELDS - 5u)

typedef struct ftun_log_aggregate ftun_log_aggregate_t;
typedef struct {
  uint64_t failures, suppressed, overflowed, filtered;
  uint64_t first, summaries, recovered, errors;
  size_t active;
} ftun_log_aggregate_usage_t;

/* 仅owner线程访问；Worker失败先通过结果回到owner。
 * 固定256键：模块+静态event_id+实例内唯一实体ID。实体ID不能复用槽位下标；
 * label为已校验UTF8的配置实体名称，最多保留255字节，不作为匹配键。
 * 描述符及字段名来自生产者静态目录；不保存record字段/Runtime借用。
 * 业务字段最多11项，不复用entity/entity_id/truncated/count/in/duration_ms。
 * now_ms使用单调时钟。logger同步借用，可为NULL（静默仍累计失败）。 */
/* destroy前须成功detach并撤销Core发布；不隐式输出或等待writer。 */
ftun_status_t ftun_log_aggregate_create(ftun_budget_t *budget, ftun_log_aggregate_t **out);
void ftun_log_aggregate_destroy(ftun_log_aggregate_t **aggregate);
ftun_status_t ftun_log_aggregate_failure(ftun_log_aggregate_t *aggregate,
  ftun_logger_t *logger, const ftun_log_record_t *record, uint64_t entity,
  ftun_string_t label, uint64_t now_ms);
ftun_status_t ftun_log_aggregate_recovery(ftun_log_aggregate_t *aggregate,
  ftun_logger_t *logger, const ftun_log_event_t *failure, uint64_t entity,
  const ftun_log_record_t *record, uint64_t now_ms);
/* 宿主把最早期限并入已有owner调度；UINT64_MAX表示当前没有待检查周期。
 * tick只输出本周期新增重复次数；flush在撤销logger前汇总并清空所有键。
 * 静默期间过滤的计数不进入之后的日志，usage始终覆盖全部失败。 */
uint64_t ftun_log_aggregate_deadline(const ftun_log_aggregate_t *aggregate);
ftun_status_t ftun_log_aggregate_tick(ftun_log_aggregate_t *aggregate,
  ftun_logger_t *logger, uint64_t now_ms);
ftun_status_t ftun_log_aggregate_flush(ftun_log_aggregate_t *aggregate,
  ftun_logger_t *logger, uint64_t now_ms);
/* 配置实体退场：汇总未输出次数并释放键/标签，不声称故障已恢复。 */
ftun_status_t ftun_log_aggregate_retire(ftun_log_aggregate_t *aggregate,
  ftun_logger_t *logger, ftun_log_module_t module, uint64_t entity, uint64_t now_ms);
void ftun_log_aggregate_usage(const ftun_log_aggregate_t *aggregate,
  ftun_log_aggregate_usage_t *out);
/* App组合把同一个聚合器接入owner的既有loop，只有需要汇总时占一个timer。
 * failure/recovery只由owner调用；query可跨线程取得发布锁内的计数快照。
 * 独立Core宿主未配置聚合器时，attach/detach无操作，其余返回AGAIN。 */
ftun_status_t ftun_log_aggregate_attach(ftun_core_t *core, ftun_event_loop_t *loop);
ftun_status_t ftun_log_aggregate_detach(ftun_core_t *core);
ftun_status_t ftun_log_failure(ftun_core_t *core, const ftun_log_record_t *record,
  uint64_t entity, ftun_string_t label, uint64_t now_ms);
ftun_status_t ftun_log_recovery(ftun_core_t *core, const ftun_log_event_t *failure,
  uint64_t entity, const ftun_log_record_t *record, uint64_t now_ms);
ftun_status_t ftun_log_aggregate_query(ftun_core_t *core, ftun_log_aggregate_usage_t *out);
ftun_status_t ftun_log_retire(ftun_core_t *core, ftun_log_module_t module,
  uint64_t entity, uint64_t now_ms);
#endif
