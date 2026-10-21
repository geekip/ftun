#ifndef FTUN_CORE_CONTEXT_H
#define FTUN_CORE_CONTEXT_H

#include "core/budget.h"
#include "internal/contracts.h"

/* Core 上下文只保存通用 owner-loop 资源和一个类型擦除的业务扩展。
 * 扩展的具体类型与生命周期由 Composition 选择的服务层负责。 */
ftun_status_t ftun_core_context_create(ftun_budget_t *budget,
                                       ftun_core_t **out);
ftun_status_t ftun_core_context_bind(ftun_core_t *core, void *extension);
ftun_status_t ftun_core_context_extension(const ftun_core_t *core,
                                          void **out);
ftun_status_t ftun_core_context_budget(ftun_core_t *core,
                                       ftun_budget_t **out);
ftun_status_t ftun_core_context_generation(const ftun_core_t *core,
                                           uint64_t *out);
ftun_status_t ftun_core_context_set_generation(ftun_core_t *core,
                                               uint64_t generation);
ftun_status_t ftun_core_context_set_logger(ftun_core_t *core,
                                           ftun_logger_t *logger);
ftun_status_t ftun_core_context_logger(ftun_core_t *core,
                                       ftun_logger_t **out);
ftun_status_t ftun_core_context_set_control(ftun_core_t *core, void *control);
ftun_status_t ftun_core_context_control(ftun_core_t *core, void **out);
ftun_status_t ftun_core_context_destroy(ftun_core_t **core);

#endif
