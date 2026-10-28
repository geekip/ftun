#ifndef FTUN_CORE_CONTEXT_INTERNAL_H
#define FTUN_CORE_CONTEXT_INTERNAL_H

#include "core/context.h"
#include <pthread.h>
#include <stdatomic.h>

#define FTUN_CORE_CONTEXT_MAGIC UINT32_C(0x46544358)

struct ftun_core {
  uint32_t context_magic;
  ftun_budget_t *budget;
  ftun_reservation_t *reservation;
  ftun_logger_t *logger;
  ftun_event_log_t *events;
  void *control;
  void *extension;
  /* 运行配置代次只由 owner 经 reserve/publish 推进，跨线程原子读取。 */
  _Atomic uint64_t generation;
  uint64_t reserved_generation; /* 零表示没有预留；仅 owner 读写。 */
  const void *reserved_owner;   /* 预留持有者标识，只做相等比较。 */
  pthread_mutex_t logger_mutex;
};

static inline int ftun_core_context_valid(const ftun_core_t *core)
{
  return core != NULL && core->context_magic == FTUN_CORE_CONTEXT_MAGIC &&
         core->budget != NULL;
}

#endif
