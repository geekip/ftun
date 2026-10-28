#define _XOPEN_SOURCE 700
#include "config.h"
#include "compile.h"
#include "model.h"
#include "parser.h"
#include "validate.h"
#include "util/event_log.h"
#include "core/budget.h"
#include "core/context.h"
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static ftun_status_t ftun_config_read_file(ftun_budget_t *budget,
  const char *path, uint8_t **out, size_t *out_length,
  ftun_reservation_t **out_reservation)
{
  ftun_reservation_t *reservation = NULL;
  ftun_budget_resources_t resources = {0u, 1u, 0u};
  uint8_t *data = NULL;
  size_t length = 0u, capacity = 0u;
  int descriptor = -1;
  struct stat metadata;
  ftun_status_t status = FTUN_E_IO;
  *out = NULL;
  *out_length = 0u;
  *out_reservation = NULL;
  if (budget != NULL) {
    status = ftun_budget_reserve_resources(budget, resources, &reservation);
    if (status != FTUN_OK) return status;
  }
  descriptor = open(path, O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) { status = FTUN_E_IO; goto done; }
  if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode)) {
    status = FTUN_E_IO;
    goto done;
  }
  if (metadata.st_size < 0 || (uintmax_t)metadata.st_size > FTUN_CONFIG_MAX_JSON_BYTES) {
    status = FTUN_E_LIMIT;
    goto done;
  }
  capacity = (size_t)metadata.st_size + 1u;
  resources.memory_bytes = capacity;
  if (reservation != NULL) {
    status = ftun_reservation_resize(reservation, resources);
    if (status != FTUN_OK) goto done;
  }
  data = (uint8_t *)malloc(capacity);
  if (data == NULL) { status = FTUN_E_LIMIT; goto done; }
  while (length <= FTUN_CONFIG_MAX_JSON_BYTES) {
    ssize_t received;
    if (length == capacity) {
      uint8_t *next;
      size_t grown = capacity > (FTUN_CONFIG_MAX_JSON_BYTES + 1u) / 2u
        ? FTUN_CONFIG_MAX_JSON_BYTES + 1u : capacity * 2u;
      resources.memory_bytes = grown;
      if (reservation != NULL) {
        status = ftun_reservation_resize(reservation, resources);
        if (status != FTUN_OK) goto done;
      }
      next = (uint8_t *)realloc(data, grown);
      if (next == NULL) { status = FTUN_E_LIMIT; goto done; }
      data = next;
      capacity = grown;
    }
    received = read(descriptor, data + length, capacity - length);
    if (received > 0) { length += (size_t)received; continue; }
    if (received == 0) break;
    if (errno == EINTR) continue;
    status = FTUN_E_IO;
    goto done;
  }
  status = close(descriptor) == 0 ? FTUN_OK : FTUN_E_IO;
  descriptor = -1;
  if (status != FTUN_OK) goto done;
  if (length > FTUN_CONFIG_MAX_JSON_BYTES) { status = FTUN_E_LIMIT; goto done; }
  resources.descriptors = 0u;
  if (reservation != NULL) {
    status = ftun_reservation_resize(reservation, resources);
    if (status != FTUN_OK) goto done;
  }
  *out = data;
  *out_length = length;
  *out_reservation = reservation;
  return FTUN_OK;
done:
  if (descriptor >= 0) (void)close(descriptor);
  free(data);
  (void)ftun_reservation_release(&reservation);
  return status;
}

static char *ftun_config_copy_span(ftun_config_t *config, const char *value, size_t length)
{
  char *copy;
  if (value == NULL || length > FTUN_CONFIG_MAX_PATH_BYTES) return NULL;
  copy = (char *)ftun_config_allocate(config, length + 1u, 1u);
  if (copy == NULL) return NULL;
  memcpy(copy, value, length);
  copy[length] = '\0';
  return copy;
}

static char *ftun_config_directory(ftun_config_t *config, const char *path)
{
  const char *slash;
  size_t length;
  if (path == NULL) return NULL;
  slash = strrchr(path, '/');
  if (slash == NULL) return NULL;
  length = slash == path ? 1u : (size_t)(slash - path);
  return ftun_config_copy_span(config, path, length);
}

static char *ftun_config_join(ftun_config_t *config, const char *directory, const char *relative)
{
  size_t directory_length;
  size_t relative_length;
  size_t separator;
  char *joined;
  if (directory == NULL || relative == NULL) return NULL;
  directory_length = strlen(directory);
  relative_length = strlen(relative);
  separator = directory_length != 0u && directory[directory_length - 1u] == '/' ? 0u : 1u;
  if (directory_length > FTUN_CONFIG_MAX_PATH_BYTES ||
      relative_length > FTUN_CONFIG_MAX_PATH_BYTES ||
      directory_length + separator > FTUN_CONFIG_MAX_PATH_BYTES - relative_length) {
    return NULL;
  }
  joined = (char *)ftun_config_allocate(config, directory_length + separator + relative_length + 1u, 1u);
  if (joined == NULL) return NULL;
  memcpy(joined, directory, directory_length);
  if (separator != 0u) joined[directory_length] = '/';
  memcpy(joined + directory_length + separator, relative, relative_length + 1u);
  return joined;
}

static ftun_status_t ftun_config_resolve_path(ftun_config_t *config, const char *directory,
                                              const char *value, char **out)
{
  struct passwd user_record;
  struct passwd *user = NULL;
  char *resolved;
  if (out != NULL) *out = NULL;
  if (directory == NULL || value == NULL || value[0] == '\0' || out == NULL) {
    return FTUN_E_INVALID;
  }
  if (value[0] == '/') {
    resolved = ftun_config_copy_span(config, value, strlen(value));
  } else if (value[0] != '~') {
    resolved = ftun_config_join(config, directory, value);
  } else {
    if (value[1] != '\0' && value[1] != '/') return FTUN_E_INVALID;
    size_t capacity = 1024u;
    char *buffer;
    int error;
    /* 使用调用方拥有的有界缓冲，不借用getpwuid的进程级共享结果。 */
    for (;;) {
      buffer = (char *)ftun_config_allocate(config, capacity, 1u);
      if (buffer == NULL) return FTUN_E_LIMIT;
      error = getpwuid_r(geteuid(), &user_record, buffer, capacity, &user);
      if (error != ERANGE) break;
      ftun_config_free_bytes(config, buffer, capacity);
      if (capacity >= FTUN_CONFIG_MAX_JSON_BYTES) return FTUN_E_LIMIT;
      capacity *= 2u;
    }
    if (error != 0 || user == NULL || user->pw_dir == NULL || user->pw_dir[0] == '\0') {
      ftun_config_free_bytes(config, buffer, capacity);
      return FTUN_E_IO;
    }
    if (value[1] == '\0') {
      resolved = ftun_config_copy_span(config, user->pw_dir, strlen(user->pw_dir));
    } else {
      resolved = ftun_config_join(config, user->pw_dir, value + 2);
    }
    ftun_config_free_bytes(config, buffer, capacity);
  }
  if (resolved == NULL) return FTUN_E_LIMIT;
  *out = resolved;
  return FTUN_OK;
}

static ftun_status_t ftun_config_resolve_one(ftun_config_t *config, const char *directory, char **value)
{
  char *resolved;
  ftun_status_t status;
  if (value == NULL || *value == NULL) return FTUN_OK;
  status = ftun_config_resolve_path(config, directory, *value, &resolved);
  if (status != FTUN_OK) return status;
  ftun_config_free_bytes(config, *value, strlen(*value) + 1u);
  *value = resolved;
  return FTUN_OK;
}

static ftun_status_t ftun_config_default_frs_path(ftun_config_t *config, char **out)
{
  char executable[FTUN_CONFIG_MAX_PATH_BYTES + 1u];
  char *directory;
  char *path;
  ssize_t length;
  if (out == NULL) return FTUN_E_INVALID;
  *out = NULL;
  length = readlink("/proc/self/exe", executable, sizeof(executable) - 1u);
  if (length <= 0 || (size_t)length >= sizeof(executable)) return FTUN_E_IO;
  executable[length] = '\0';
  directory = ftun_config_directory(config, executable);
  if (directory == NULL) return FTUN_E_IO;
  path = ftun_config_join(config, directory, "rules.frs");
  ftun_config_free_bytes(config, directory, strlen(directory) + 1u);
  if (path == NULL) return FTUN_E_LIMIT;
  *out = path;
  return FTUN_OK;
}

static ftun_status_t ftun_config_resolve_paths(ftun_config_t *config,
                                               const char *source_path)
{
  ftun_status_t status;
  if (config == NULL || source_path == NULL) return FTUN_E_INVALID;
  config->source_path = ftun_config_copy_span(config, source_path, strlen(source_path));
  if (config->source_path == NULL) return FTUN_E_LIMIT;
  config->base_directory = ftun_config_directory(config, source_path);
  if (config->base_directory == NULL) return FTUN_E_LIMIT;
  status = ftun_config_resolve_one(config, config->base_directory,
                                   &config->base.cache_file);
  if (status == FTUN_OK) {
    status = ftun_config_resolve_one(config, config->base_directory, &config->log.file);
  }
  if (status == FTUN_OK && config->frs.active) {
    if (config->frs.path == NULL) {
      status = ftun_config_default_frs_path(config, &config->frs.path);
    } else {
      status = ftun_config_resolve_one(config, config->base_directory,
                                       &config->frs.path);
    }
  }
  return status;
}

/* 有界配置加载协调。 */
ftun_status_t ftun_config_load_budget_traced(ftun_budget_t *budget,
  const char *path, ftun_config_t **out, ftun_config_trace_t *trace)
{
  ftun_bytes_t bytes;
  ftun_config_t *config = NULL;
  ftun_feature_plan_t *plan = NULL;
  uint8_t *data = NULL;
  char source_path[PATH_MAX];
  ftun_reservation_t *input_reservation = NULL;
  size_t length = 0u;
  ftun_status_t status = FTUN_E_INVALID;
  ftun_config_step_t step = FTUN_CONFIG_STEP_READ;
  ftun_config_trace_t result = {FTUN_CONFIG_STEP_NONE, FTUN_CONFIG_STEP_NONE, FTUN_OK};
  if (out != NULL) *out = NULL;
  if (path == NULL || path[0] == '\0' || out == NULL) goto done;
  if (realpath(path, source_path) == NULL) { status = FTUN_E_IO; goto done; }
  if (strlen(source_path) > FTUN_CONFIG_MAX_PATH_BYTES) {
    status = FTUN_E_LIMIT;
    goto done;
  }
  status = ftun_config_read_file(budget, source_path, &data, &length, &input_reservation);
  if (status != FTUN_OK) goto done;
  result.completed = FTUN_CONFIG_STEP_READ;
  step = FTUN_CONFIG_STEP_PARSE;
  bytes.data = data;
  bytes.length = length;
  status = ftun_config_parse_budget(budget, bytes, &config);
  free(data);
  data = NULL;
  (void)ftun_reservation_release(&input_reservation);
  if (status != FTUN_OK) goto done;
  result.completed = FTUN_CONFIG_STEP_PARSE;
  step = FTUN_CONFIG_STEP_PATHS;
  status = ftun_config_resolve_paths(config, source_path);
  if (status != FTUN_OK) goto done;
  result.completed = FTUN_CONFIG_STEP_PATHS;
  step = FTUN_CONFIG_STEP_VALIDATE;
  status = ftun_config_validate(config, NULL);
  if (status != FTUN_OK) goto done;
  result.completed = FTUN_CONFIG_STEP_VALIDATE;
  step = FTUN_CONFIG_STEP_COMPILE;
  status = ftun_config_compile(config, &plan);
  if (status != FTUN_OK) goto done;
  result.completed = FTUN_CONFIG_STEP_COMPILE;
  config->plan = plan;
  plan = NULL;
  *out = config;
  config = NULL;
done:
  free(data);
  (void)ftun_reservation_release(&input_reservation);
  (void)ftun_feature_plan_destroy(&plan);
  (void)ftun_config_destroy(&config);
  result.status = status;
  if (status != FTUN_OK) result.failed = step;
  if (trace != NULL) *trace = result;
  return status;
}

ftun_status_t ftun_config_load_traced(const char *path, ftun_config_t **out,
  ftun_config_trace_t *trace)
{
  return ftun_config_load_budget_traced(NULL, path, out, trace);
}

ftun_status_t ftun_config_load(ftun_core_t *core, const char *path,
  ftun_config_t **out)
{
  ftun_budget_t *budget = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (core != NULL) {
    status = ftun_core_context_budget(core, &budget);
    if (status != FTUN_OK) return status;
  }
  return ftun_config_load_budget_traced(budget, path, out, NULL);
}

const char *ftun_config_step_name(ftun_config_step_t step)
{
  static const char *const names[] = {"none", "read", "parse", "paths", "validate", "compile"};
  return step >= FTUN_CONFIG_STEP_NONE && step <= FTUN_CONFIG_STEP_COMPILE ? names[step] : "unknown";
}

void ftun_config_trace_emit(ftun_core_t *core, const ftun_config_trace_t *trace,
  uint64_t generation)
{
  static const ftun_lifecycle_kind_t kinds[] = {0, FTUN_LIFECYCLE_CONFIG_READ,
    FTUN_LIFECYCLE_CONFIG_PARSED, 0, FTUN_LIFECYCLE_CONFIG_VALIDATED,
    FTUN_LIFECYCLE_CONFIG_COMPILED};
  static const ftun_lifecycle_reason_t reasons[] = {FTUN_LIFECYCLE_REASON_NONE,
    FTUN_LIFECYCLE_REASON_CONFIG_READ, FTUN_LIFECYCLE_REASON_CONFIG_PARSE,
    FTUN_LIFECYCLE_REASON_CONFIG_PATHS, FTUN_LIFECYCLE_REASON_CONFIG_VALIDATE,
    FTUN_LIFECYCLE_REASON_CONFIG_COMPILE};
  ftun_lifecycle_event_t item = {0};
  int step;
  if (trace == NULL || trace->completed < FTUN_CONFIG_STEP_NONE ||
      trace->completed > FTUN_CONFIG_STEP_COMPILE || trace->failed < FTUN_CONFIG_STEP_NONE ||
      trace->failed > FTUN_CONFIG_STEP_COMPILE) return;
  item.generation = generation;
  for (step = FTUN_CONFIG_STEP_READ; step <= (int)trace->completed; step++) {
    if (kinds[step] == 0) continue;
    item.kind = kinds[step];
    (void)ftun_lifecycle_emit(core, &item);
  }
  if (trace->status != FTUN_OK) {
    item.kind = FTUN_LIFECYCLE_CONFIG_FAILED;
    item.status = trace->status;
    item.reason = reasons[trace->failed];
    (void)ftun_lifecycle_emit(core, &item);
  }
}
