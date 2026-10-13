#ifndef FTUN_CORE_ENGINE_H
#define FTUN_CORE_ENGINE_H

#include "config/model.h"
#include "core/budget.h"
#include "core/operation.h"
#include "internal/contracts.h"

typedef struct ftun_engine ftun_engine_t;
typedef struct ftun_engine_dns_plan ftun_engine_dns_plan_t;

/* Linux v1 生产数据面装配。prepare 在 Runtime commit 前打开不可变入站资源；
 * activate 只在 commit 成功后发布接纳。reload prepare 在 Runtime commit 前
 * 完成 DNS 资源准备，commit 不分配；旧 Session 继续持有原 Runtime。 */
ftun_status_t ftun_engine_prepare(ftun_core_t *core, ftun_budget_t *budget,
                                  ftun_operation_queue_t *operations,
                                  const ftun_config_t *config,
                                  uint64_t generation,
                                  ftun_engine_t **out);
ftun_status_t ftun_engine_activate(ftun_engine_t *engine);
ftun_status_t ftun_engine_reload_prepare(ftun_engine_t *engine,
                                         const ftun_config_t *config,
                                         uint64_t generation);
ftun_status_t ftun_engine_reload_prepare_planned(
  ftun_engine_t *engine, const ftun_config_t *config, uint64_t generation,
  const ftun_engine_dns_plan_t *dns_plan);
ftun_status_t ftun_engine_reload_commit(ftun_engine_t *engine,
                                        uint64_t generation);
ftun_status_t ftun_engine_reload_abort(ftun_engine_t *engine);
ftun_status_t ftun_engine_run_once(ftun_engine_t *engine);
ftun_status_t ftun_engine_wakeup(ftun_engine_t *engine);
ftun_status_t ftun_engine_stop(ftun_engine_t *engine);
ftun_status_t ftun_engine_destroy(ftun_engine_t **engine);

#endif
