#ifndef FTUN_APP_CONFIG_CONFIG_H
#define FTUN_APP_CONFIG_CONFIG_H
#include "util/types.h"

typedef enum {
  FTUN_CONFIG_STEP_NONE = 0,
  FTUN_CONFIG_STEP_READ,
  FTUN_CONFIG_STEP_PARSE,
  FTUN_CONFIG_STEP_PATHS,
  FTUN_CONFIG_STEP_VALIDATE,
  FTUN_CONFIG_STEP_COMPILE
} ftun_config_step_t;

/* 固定值追踪，不借用配置或错误文本，可由 Worker 随结果交回 owner。 */
typedef struct {
  ftun_config_step_t completed;
  ftun_config_step_t failed;
  ftun_status_t status;
} ftun_config_trace_t;

ftun_status_t ftun_config_load_traced(const char *path, ftun_config_t **out,
  ftun_config_trace_t *trace);
/* budget借用到最后配置/计划引用释放，构造临时存储也在此预算准入。 */
ftun_status_t ftun_config_load_budget_traced(ftun_budget_t *budget,
  const char *path, ftun_config_t **out, ftun_config_trace_t *trace);
const char *ftun_config_step_name(ftun_config_step_t step);
void ftun_config_trace_emit(ftun_core_t *core, const ftun_config_trace_t *trace,
  uint64_t generation);
/* 配置加载协调。
 * 实现路径：有界读取后依次调用 parser/validate/compile；路径相对配置目录；失败不替换 active Runtime。
 * 调用边界：不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；core提供借用预算；NULL用于独立未绑定加载。
 * 成功返回拥有型配置及其 plan；失败不转移所有权并清空输出。
 */
ftun_status_t ftun_config_load(ftun_core_t *core, const char *path, ftun_config_t **out);

#endif
