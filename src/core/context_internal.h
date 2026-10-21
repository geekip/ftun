#ifndef FTUN_CORE_CONTEXT_INTERNAL_H
#define FTUN_CORE_CONTEXT_INTERNAL_H

#include "core/context.h"

#define FTUN_CORE_CONTEXT_MAGIC UINT32_C(0x46544358)

struct ftun_core {
  uint32_t context_magic;
  ftun_budget_t *budget;
  ftun_logger_t *logger;
  void *control;
  void *extension;
  uint64_t generation;
};

static inline int ftun_core_context_valid(const ftun_core_t *core)
{
  return core != NULL && core->context_magic == FTUN_CORE_CONTEXT_MAGIC &&
         core->budget != NULL;
}

#endif
