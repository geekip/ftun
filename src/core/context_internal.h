#ifndef FTUN_CORE_CONTEXT_INTERNAL_H
#define FTUN_CORE_CONTEXT_INTERNAL_H

#include "core/context.h"
#include <pthread.h>

#define FTUN_CORE_CONTEXT_MAGIC UINT32_C(0x46544358)

struct ftun_core {
  uint32_t context_magic;
  ftun_budget_t *budget;
  ftun_reservation_t *reservation;
  ftun_logger_t *logger;
  ftun_event_log_t *events;
  void *control;
  void *extension;
  uint64_t generation;
  pthread_mutex_t logger_mutex;
};

static inline int ftun_core_context_valid(const ftun_core_t *core)
{
  return core != NULL && core->context_magic == FTUN_CORE_CONTEXT_MAGIC &&
         core->budget != NULL;
}

#endif
