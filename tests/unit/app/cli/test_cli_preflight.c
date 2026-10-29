#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>
#include "app/config/model.h"
#include "app/cli/internal.h"
#include "app/config/compile.h"
#include "app/config/config.h"
#include "core/context.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if defined(FTUN_HAVE_MODULE_FAKEIP)
#include "app/cli/cmd_fakeip.c"
#include <stdarg.h>
static bool force_random_fallback;
static ftun_budget_t *random_budget;
static size_t random_opens;
ftun_status_t __real_ftun_random_bytes(void *buffer, size_t length);
ftun_status_t __wrap_ftun_random_bytes(void *buffer, size_t length)
{
  return force_random_fallback ? FTUN_E_IO : __real_ftun_random_bytes(buffer, length);
}
ftun_status_t __real_ftun_random_device_bytes(void *buffer, size_t length);
ftun_status_t __wrap_ftun_random_device_bytes(void *buffer, size_t length)
{
  ftun_budget_usage_t usage;
  ftun_status_t status;
  if (ftun_budget_get_usage(random_budget, &usage) != FTUN_OK ||
      usage.used_resources.descriptors != 1u) abort();
  random_opens++;
  status = __real_ftun_random_device_bytes(buffer, length);
  if (ftun_budget_get_usage(random_budget, &usage) != FTUN_OK ||
      usage.used_resources.descriptors != 1u) abort();
  return status;
}
#endif

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "cli preflight failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

static ftun_budget_t *loaded_budget;
static unsigned int core_destroy_calls;
static int reject_load, hold_config, hold_core;

ftun_status_t __real_ftun_config_load_budget_traced(ftun_budget_t *budget,
  const char *path, ftun_config_t **out, ftun_config_trace_t *trace);
ftun_status_t __wrap_ftun_config_load_budget_traced(ftun_budget_t *budget,
  const char *path, ftun_config_t **out, ftun_config_trace_t *trace)
{
  loaded_budget = budget;
  if (reject_load) {
    *out = NULL;
    trace->failed = FTUN_CONFIG_STEP_READ;
    trace->status = FTUN_E_LIMIT;
    return FTUN_E_LIMIT;
  }
  return __real_ftun_config_load_budget_traced(budget, path, out, trace);
}

ftun_status_t __real_ftun_config_destroy(ftun_config_t **config);
ftun_status_t __wrap_ftun_config_destroy(ftun_config_t **config)
{
  if (hold_config && config != NULL && *config != NULL) return FTUN_E_AGAIN;
  return __real_ftun_config_destroy(config);
}

ftun_status_t __real_ftun_core_destroy(ftun_core_t **core);
ftun_status_t __wrap_ftun_core_destroy(ftun_core_t **core)
{
  if (core != NULL && *core != NULL) {
    core_destroy_calls++;
    if (hold_core) return FTUN_E_AGAIN;
  }
  return __real_ftun_core_destroy(core);
}

static int write_config(const char *path, const char *text)
{
  FILE *file = fopen(path, "w");
  CHECK(file != NULL);
  CHECK(fputs(text, file) >= 0);
  CHECK(fclose(file) == 0);
  return 0;
}

static int ownership(const char *path)
{
  ftun_cli_checked_config_t checked = {0};
  ftun_budget_usage_t before, after;
  ftun_budget_t *budget = NULL;
  ftun_core_t *core;
  ftun_config_t *config;
  size_t bytes;
  CHECK(ftun_cli_check_config(path, 0, &checked) == FTUN_OK);
  CHECK(checked.core != NULL && checked.config != NULL);
  CHECK(ftun_core_context_budget(checked.core, &budget) == FTUN_OK);
  CHECK(budget != NULL && loaded_budget == budget);
  CHECK(checked.config->document.budget == budget && (checked.config->document.reservation).budget != NULL);
  CHECK(checked.config->plan != NULL && (checked.config->plan->reservation).budget != NULL);
  bytes = checked.config->document.owned_bytes + checked.config->plan->owned_bytes;
  CHECK(ftun_budget_get_usage(budget, &before) == FTUN_OK);
  CHECK(before.used_resources.memory_bytes >= bytes && before.used_resources.descriptors == 0u);
  core = checked.core;
  config = checked.config;
  CHECK(ftun_cli_check_config(path, 0, &checked) == FTUN_E_INVALID);
  CHECK(checked.core == core && checked.config == config);

  /* 配置清理失败时不得碰预算宿主，第二次可以继续同一拥有链。 */
  core_destroy_calls = 0u;
  hold_config = 1;
  CHECK(ftun_cli_checked_config_destroy(&checked) == FTUN_E_AGAIN);
  CHECK(core_destroy_calls == 0u && checked.core == core && checked.config == config);
  CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK && after.used_resources.memory_bytes == before.used_resources.memory_bytes);
  hold_config = 0;
  hold_core = 1;
  CHECK(ftun_cli_checked_config_destroy(&checked) == FTUN_E_AGAIN);
  CHECK(checked.config == NULL && checked.core == core && core_destroy_calls == 1u);
  CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK && after.used_resources.memory_bytes + bytes == before.used_resources.memory_bytes);
  hold_core = 0;
  CHECK(ftun_cli_checked_config_destroy(&checked) == FTUN_OK);
  CHECK(checked.core == NULL && checked.config == NULL);
  CHECK(ftun_cli_checked_config_destroy(&checked) == FTUN_OK);
  return 0;
}

static int failures(const char *path)
{
  ftun_cli_checked_config_t checked = {0};
  CHECK(ftun_cli_check_config(NULL, 0, &checked) == FTUN_E_INVALID);
  CHECK(ftun_cli_check_config(path, 0, NULL) == FTUN_E_INVALID);
  CHECK(ftun_cli_checked_config_destroy(NULL) == FTUN_E_INVALID);
  reject_load = 1;
  CHECK(ftun_cli_check_config(path, 0, &checked) == FTUN_E_LIMIT);
  CHECK(checked.core != NULL && checked.config == NULL && loaded_budget != NULL);
  CHECK(ftun_cli_checked_config_destroy(&checked) == FTUN_OK);
  reject_load = 0;
  CHECK(ftun_cli_check_config(path, 1, &checked) == FTUN_E_INVALID);
  CHECK(checked.core != NULL && checked.config != NULL);
  CHECK(ftun_cli_checked_config_destroy(&checked) == FTUN_OK);
  CHECK(write_config(path, "{bad}") == 0);
  CHECK(ftun_cli_check_config(path, 0, &checked) == FTUN_E_INVALID);
  CHECK(checked.core != NULL && checked.config == NULL);
  CHECK(ftun_cli_checked_config_destroy(&checked) == FTUN_OK);
  CHECK(unlink(path) == 0);
  CHECK(ftun_cli_check_config(path, 0, &checked) != FTUN_OK);
  CHECK(ftun_cli_checked_config_destroy(&checked) == FTUN_OK);
  return 0;
}

static int random_resources(void)
{
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  ftun_budget_options_t options = {{4096u, 0u, 0u}, {0}, {0}};
  ftun_budget_usage_t usage, before;
  uint8_t uuid[FTUN_FAKEIP_UUID_BYTES];
  force_random_fallback = true;
  CHECK(ftun_budget_create_resources(NULL, &options, &random_budget) == FTUN_OK);
  CHECK(ftun_cli_random_uuid(random_budget, uuid) == FTUN_E_LIMIT && random_opens == 0u);
  CHECK(ftun_budget_destroy(&random_budget) == FTUN_OK);
  options.limit.descriptors = 1u;
  CHECK(ftun_budget_create_resources(NULL, &options, &random_budget) == FTUN_OK);
  CHECK(ftun_budget_get_usage(random_budget, &before) == FTUN_OK);
  CHECK(ftun_cli_random_uuid(random_budget, uuid) == FTUN_OK && random_opens == 1u);
  CHECK((uuid[6] & 0xf0u) == 0x40u && (uuid[8] & 0xc0u) == 0x80u);
  CHECK(ftun_budget_get_usage(random_budget, &usage) == FTUN_OK &&
    usage.used_resources.memory_bytes == 0u && usage.metadata_bytes == before.metadata_bytes && usage.used_resources.descriptors == 0u);
  CHECK(ftun_budget_destroy(&random_budget) == FTUN_OK);
  force_random_fallback = false;
#endif
  return 0;
}

int main(void)
{
  char path[] = "/tmp/ftun-preflight.XXXXXX";
  int descriptor = mkstemp(path);
  CHECK(descriptor >= 0 && close(descriptor) == 0);
  CHECK(random_resources() == 0);
  CHECK(write_config(path, "{\"dns\":{\"enable\":false}}") == 0);
  CHECK(ownership(path) == 0);
  CHECK(failures(path) == 0);
  return 0;
}
