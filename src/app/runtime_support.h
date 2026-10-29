#ifndef FTUN_APP_RUNTIME_SUPPORT_H
#define FTUN_APP_RUNTIME_SUPPORT_H

#include "app/config/config.h"
#include "core/worker.h"

typedef struct ftun_app_runtime_candidate ftun_app_runtime_candidate_t;

typedef struct {
  ftun_status_t status;
  bool published;
} ftun_app_publish_result_t;

/* owner 在提交 reload 时从当前生效配置捕获，不读取候选配置猜测旧路由。
 * 按值进入 Worker；socket mark 与 libc 隐藏 socket 的授权相互独立。 */
typedef struct {
  uint64_t generation;
  uint32_t socket_mark;
  bool allow_system_resolver;
} ftun_app_prepare_context_t;

/* 由静态 composition 选择的业务附件，不提供动态注册或独立运行循环。
 * 宿主持有配置，附件可借用至 release 成功；失败仍须保留非空附件。
 * prepare/load_state 在 worker 独占候选上运行，其余候选操作由 owner 执行。
 * prepare借用宿主预算直到附件release成功，包含错误/取消后的待回收对象。
 * job的input及out_reservation共同归宿主；Worker复制后free并归还临时额度。
 * execute不借Core，但可借宿主持有至Worker及结果回收完成的Budget。 */
typedef struct {
  ftun_status_t (*attach)(ftun_core_t *, size_t, size_t);
  ftun_status_t (*clear)(ftun_core_t *);
  ftun_status_t (*check)(ftun_core_t *, const ftun_config_t *, bool);
  ftun_status_t (*start)(ftun_core_t *, ftun_budget_t *, const ftun_config_t *, uint64_t,
    ftun_app_runtime_candidate_t **, uint32_t *);
  ftun_status_t (*prepare)(ftun_budget_t *, const ftun_config_t *, uint64_t, const ftun_app_prepare_context_t *,
    ftun_app_runtime_candidate_t **, bool *);
  void (*load_state)(ftun_app_runtime_candidate_t *);
  ftun_status_t (*adopt)(ftun_core_t *, ftun_app_runtime_candidate_t *,
    uint64_t, uint32_t *);
  ftun_status_t (*stage)(ftun_core_t *, ftun_app_runtime_candidate_t *, uint64_t);
  ftun_status_t (*inherit)(ftun_core_t *, ftun_app_runtime_candidate_t *);
  ftun_status_t (*commit)(ftun_core_t *, ftun_app_runtime_candidate_t *);
  void (*committed)(ftun_core_t *, const ftun_app_runtime_candidate_t *);
  ftun_status_t (*release)(ftun_core_t *, ftun_app_runtime_candidate_t **);
  ftun_status_t (*select)(ftun_core_t *, ftun_string_t, ftun_string_t);
  ftun_status_t (*state_job)(ftun_core_t *, ftun_budget_t *, const char *, uint64_t,
    ftun_worker_job_t *, ftun_reservation_t *);
  ftun_status_t (*publish_job)(ftun_app_runtime_candidate_t *, ftun_worker_job_t *,
    ftun_reservation_t *);
  const char *state_failure_message;
  const char *publish_warning_message;
} ftun_app_runtime_support_t;

/* 缺席业务时返回 NULL；公共宿主仍拥有完整控制、事务、日志和停止流程。 */
const ftun_app_runtime_support_t *ftun_app_runtime_support(void);
/* CLI 预算与运行组合共用同一事件容量推导，不复制业务模块的公式。 */
ftun_status_t ftun_app_event_source_capacity(const ftun_config_t *config, size_t *out);
ftun_status_t ftun_app_datagram_capacity(const ftun_config_t *config, size_t *out);

#endif
