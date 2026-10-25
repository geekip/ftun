#include "core/context_internal.h"

#include <stdlib.h>

ftun_status_t ftun_core_context_create(ftun_budget_t *budget,
                                       ftun_core_t **out)
{
  ftun_core_t *core;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (budget == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_budget_reserve(budget, sizeof(*core), &reservation);
  if (status != FTUN_OK) return status;
  core = (ftun_core_t *)calloc(1u, sizeof(*core));
  if (core == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  if (pthread_mutex_init(&core->logger_mutex, NULL) != 0) {
    free(core);
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_IO;
  }
  core->context_magic = FTUN_CORE_CONTEXT_MAGIC;
  core->budget = budget;
  core->reservation = reservation;
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

ftun_status_t ftun_core_context_set_budget(ftun_core_t *core,
                                           ftun_budget_t *budget)
{
  if (!ftun_core_context_valid(core) || budget == NULL) return FTUN_E_INVALID;
  if (core->extension != NULL) return FTUN_E_AGAIN;
  core->budget = budget;
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
  /* 日志借用不读取 owner 可切换的 budget；存活期间 magic 保持不变。 */
  if (core == NULL || core->context_magic != FTUN_CORE_CONTEXT_MAGIC) {
    return FTUN_E_INVALID;
  }
  if (pthread_mutex_lock(&core->logger_mutex) != 0) return FTUN_E_IO;
  core->logger = logger;
  (void)pthread_mutex_unlock(&core->logger_mutex);
  return FTUN_OK;
}

ftun_status_t ftun_core_context_logger_acquire(ftun_core_t *core,
                                               ftun_logger_t **out)
{
  if (out != NULL) *out = NULL;
  if (core == NULL || core->context_magic != FTUN_CORE_CONTEXT_MAGIC ||
      out == NULL) return FTUN_E_INVALID;
  if (pthread_mutex_lock(&core->logger_mutex) != 0) return FTUN_E_IO;
  if (core->logger == NULL) {
    (void)pthread_mutex_unlock(&core->logger_mutex);
    return FTUN_E_AGAIN;
  }
  *out = core->logger;
  return FTUN_OK;
}

ftun_status_t ftun_core_context_set_event_log(ftun_core_t *core,
                                              ftun_event_log_t *log)
{
  ftun_status_t status = FTUN_OK;
  if (core == NULL || core->context_magic != FTUN_CORE_CONTEXT_MAGIC) return FTUN_E_INVALID;
  if (pthread_mutex_lock(&core->logger_mutex) != 0) return FTUN_E_IO;
  if (core->events != NULL && log != NULL && core->events != log) status = FTUN_E_STALE;
  else core->events = log;
  (void)pthread_mutex_unlock(&core->logger_mutex);
  return status;
}

ftun_status_t ftun_core_context_publish_logger(ftun_core_t *core,
  ftun_logger_t *logger, bool silent)
{
  ftun_status_t status = FTUN_OK;
  if (core == NULL || core->context_magic != FTUN_CORE_CONTEXT_MAGIC ||
      (!silent && logger == NULL)) return FTUN_E_INVALID;
  if (pthread_mutex_lock(&core->logger_mutex) != 0) return FTUN_E_IO;
  if (core->events != NULL) {
    ftun_event_log_usage_t usage;
    status = ftun_event_log_get_usage(core->events, &usage);
    if (status != FTUN_OK || usage.closed) {
      (void)pthread_mutex_unlock(&core->logger_mutex);
      return status != FTUN_OK ? status : FTUN_E_STALE;
    }
    status = usage.configured ?
      ftun_event_log_reconfigure(core->events, core->logger, silent) :
      ftun_event_log_publish(core->events, logger, silent);
  }
  core->logger = logger;
  (void)pthread_mutex_unlock(&core->logger_mutex);
  return status;
}

ftun_status_t ftun_core_context_events_acquire(ftun_core_t *core,
  ftun_event_log_t **events, ftun_logger_t **logger)
{
  if (events != NULL) *events = NULL;
  if (logger != NULL) *logger = NULL;
  if (core == NULL || core->context_magic != FTUN_CORE_CONTEXT_MAGIC ||
      events == NULL || logger == NULL) return FTUN_E_INVALID;
  if (pthread_mutex_lock(&core->logger_mutex) != 0) return FTUN_E_IO;
  if (core->events == NULL) {
    (void)pthread_mutex_unlock(&core->logger_mutex);
    return FTUN_E_AGAIN;
  }
  *events = core->events;
  *logger = core->logger;
  return FTUN_OK;
}

ftun_status_t ftun_core_context_finish_logging(ftun_core_t *core,
  const ftun_lifecycle_event_t *terminal)
{
  ftun_status_t status = FTUN_OK;
  if (core == NULL || core->context_magic != FTUN_CORE_CONTEXT_MAGIC) return FTUN_E_INVALID;
  if (pthread_mutex_lock(&core->logger_mutex) != 0) return FTUN_E_IO;
  if (core->events != NULL) status = ftun_event_log_finish_with(core->events, core->logger, terminal);
  if (status != FTUN_E_INVALID) core->logger = NULL;
  (void)pthread_mutex_unlock(&core->logger_mutex);
  return status;
}

ftun_status_t ftun_core_context_logger_release(ftun_core_t *core)
{
  if (core == NULL || core->context_magic != FTUN_CORE_CONTEXT_MAGIC) {
    return FTUN_E_INVALID;
  }
  return pthread_mutex_unlock(&core->logger_mutex) == 0 ? FTUN_OK : FTUN_E_IO;
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
  ftun_reservation_t *reservation;
  if (core == NULL) return FTUN_E_INVALID;
  owned = *core;
  if (owned == NULL) return FTUN_OK;
  if (!ftun_core_context_valid(owned)) return FTUN_E_INVALID;
  if (owned->extension != NULL || owned->logger != NULL || owned->events != NULL ||
      owned->control != NULL) return FTUN_E_AGAIN;
  if (pthread_mutex_destroy(&owned->logger_mutex) != 0) return FTUN_E_IO;
  reservation = owned->reservation;
  owned->context_magic = 0u;
  owned->budget = NULL;
  free(owned);
  *core = NULL;
  return ftun_reservation_release(&reservation);
}
