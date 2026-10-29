#ifndef FTUN_STATUS_H
#define FTUN_STATUS_H
#include "ftun/instance.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef enum {
  FTUN_CORE_CREATED = 1,
  FTUN_CORE_STARTING,
  FTUN_CORE_RUNNING,
  FTUN_CORE_STOPPING,
  FTUN_CORE_STOPPED
} ftun_core_state_t;
/* get_info 没有输出长度参数，此结构不得追加字段或改变布局。
 * 新的内部统计不通过这个公开输出结构写入。 */
typedef struct {
  ftun_core_state_t state;
  uint64_t generation;
  size_t pending_operations;
  uint64_t owner_rounds;
  uint64_t owner_max_busy_ms;
  uint64_t owner_max_deadline_lateness_ms;
  size_t owner_max_work;
  uint64_t owner_quota_exhaustions;
} ftun_core_info_t;
ftun_status_t ftun_core_get_info(ftun_core_t *core, ftun_core_info_t *out);

#ifdef __cplusplus
}
#endif
#endif
