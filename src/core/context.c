#include "core/context_internal.h"

#include <stdlib.h>

ftun_status_t ftun_core_context_create(ftun_budget_t *budget,
                                       ftun_core_t **out)
{
  ftun_core_t *core;
  if (out != NULL) *out = NULL;
  if (budget == NULL || out == NULL) return FTUN_E_INVALID;
  core = (ftun_core_t *)calloc(1u, sizeof(*core));
  if (core == NULL) return FTUN_E_LIMIT;
  core->context_magic = FTUN_CORE_CONTEXT_MAGIC;
  core->budget = budget;
  *out = core;
  return FTUN_OK;
}

ftun_status_t ftun_core_context_bind(ftun_core_t *core, void *extension)
{
  if (!ftun_core_context_valid(core)) return FTUN_E_INVALID;
  if (core->extension != NULL && extension != NULL &&
      core->extension != extension) return FTUN_E_STALE;
  core->extension = extension;
  return FTUN_OK;
}

ftun_status_t ftun_core_context_extension(const ftun_core_t *core,
                                          void **out)
{
  if (out != NULL) *out = NULL;
  if (!ftun_core_context_valid(core) || out == NULL) return FTUN_E_INVALID;
  if (core->extension == NULL) return FTUN_E_AGAIN;
  *out = core->extension;
  return FTUN_OK;
}

ftun_status_t ftun_core_context_budget(ftun_core_t *core,
                                       ftun_budget_t **out)
{
  if (out != NULL) *out = NULL;
  if (!ftun_core_context_valid(core) || out == NULL) return FTUN_E_INVALID;
  *out = core->budget;
  return FTUN_OK;
}

ftun_status_t ftun_core_context_generation(const ftun_core_t *core,
                                           uint64_t *out)
{
  if (out != NULL) *out = 0u;
  if (!ftun_core_context_valid(core) || out == NULL) return FTUN_E_INVALID;
  *out = core->generation;
  return FTUN_OK;
}

ftun_status_t ftun_core_context_set_generation(ftun_core_t *core,
                                               uint64_t generation)
{
  if (!ftun_core_context_valid(core)) return FTUN_E_INVALID;
  core->generation = generation;
  return FTUN_OK;
}

ftun_status_t ftun_core_context_set_logger(ftun_core_t *core,
                                           ftun_logger_t *logger)
{
  if (!ftun_core_context_valid(core)) return FTUN_E_INVALID;
  core->logger = logger;
  return FTUN_OK;
}

ftun_status_t ftun_core_context_logger(ftun_core_t *core,
                                       ftun_logger_t **out)
{
  if (out != NULL) *out = NULL;
  if (!ftun_core_context_valid(core) || out == NULL) return FTUN_E_INVALID;
  if (core->logger == NULL) return FTUN_E_AGAIN;
  *out = core->logger;
  return FTUN_OK;
}

ftun_status_t ftun_core_context_set_control(ftun_core_t *core, void *control)
{
  if (!ftun_core_context_valid(core)) return FTUN_E_INVALID;
  core->control = control;
  return FTUN_OK;
}

ftun_status_t ftun_core_context_control(ftun_core_t *core, void **out)
{
  if (out != NULL) *out = NULL;
  if (!ftun_core_context_valid(core) || out == NULL) return FTUN_E_INVALID;
  if (core->control == NULL) return FTUN_E_AGAIN;
  *out = core->control;
  return FTUN_OK;
}

ftun_status_t ftun_core_context_destroy(ftun_core_t **core)
{
  ftun_core_t *owned;
  if (core == NULL) return FTUN_E_INVALID;
  owned = *core;
  if (owned == NULL) return FTUN_OK;
  if (!ftun_core_context_valid(owned)) return FTUN_E_INVALID;
  if (owned->extension != NULL || owned->logger != NULL ||
      owned->control != NULL) return FTUN_E_AGAIN;
  owned->context_magic = 0u;
  owned->budget = NULL;
  free(owned);
  *core = NULL;
  return FTUN_OK;
}
