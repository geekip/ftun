#define _XOPEN_SOURCE 700
#include "config.h"
#include "compile.h"
#include "model.h"
#include "parser.h"
#include "validate.h"
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static ftun_status_t ftun_config_read_file(const char *path, uint8_t **out,
                                           size_t *out_length)
{
  uint8_t *data;
  size_t length = 0u;
  int descriptor;
  struct stat metadata;
  if (out != NULL) *out = NULL;
  if (out_length != NULL) *out_length = 0u;
  if (path == NULL || out == NULL || out_length == NULL) return FTUN_E_INVALID;
  descriptor = open(path, O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) return FTUN_E_IO;
  if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode)) {
    (void)close(descriptor);
    return FTUN_E_IO;
  }
  if (metadata.st_size < 0 ||
      (uintmax_t)metadata.st_size > (uintmax_t)FTUN_CONFIG_MAX_JSON_BYTES) {
    (void)close(descriptor);
    return FTUN_E_LIMIT;
  }
  data = (uint8_t *)malloc(FTUN_CONFIG_MAX_JSON_BYTES + 1u);
  if (data == NULL) {
    (void)close(descriptor);
    return FTUN_E_LIMIT;
  }
  while (length <= FTUN_CONFIG_MAX_JSON_BYTES) {
    ssize_t received = read(descriptor, data + length,
                            FTUN_CONFIG_MAX_JSON_BYTES + 1u - length);
    if (received > 0) {
      length += (size_t)received;
      continue;
    }
    if (received == 0) break;
    if (errno == EINTR) continue;
    free(data);
    (void)close(descriptor);
    return FTUN_E_IO;
  }
  if (close(descriptor) != 0) {
    free(data);
    return FTUN_E_IO;
  }
  if (length > FTUN_CONFIG_MAX_JSON_BYTES) {
    free(data);
    return FTUN_E_LIMIT;
  }
  *out = data;
  *out_length = length;
  return FTUN_OK;
}

static char *ftun_config_copy_span(const char *value, size_t length)
{
  char *copy;
  if (value == NULL || length > FTUN_CONFIG_MAX_PATH_BYTES) return NULL;
  copy = (char *)malloc(length + 1u);
  if (copy == NULL) return NULL;
  memcpy(copy, value, length);
  copy[length] = '\0';
  return copy;
}

static char *ftun_config_directory(const char *path)
{
  const char *slash;
  size_t length;
  if (path == NULL) return NULL;
  slash = strrchr(path, '/');
  if (slash == NULL) return NULL;
  length = slash == path ? 1u : (size_t)(slash - path);
  return ftun_config_copy_span(path, length);
}

static char *ftun_config_join(const char *directory, const char *relative)
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
  joined = (char *)malloc(directory_length + separator + relative_length + 1u);
  if (joined == NULL) return NULL;
  memcpy(joined, directory, directory_length);
  if (separator != 0u) joined[directory_length] = '/';
  memcpy(joined + directory_length + separator, relative, relative_length + 1u);
  return joined;
}

static ftun_status_t ftun_config_resolve_path(const char *directory,
                                              const char *value, char **out)
{
  struct passwd *user;
  char *resolved;
  if (out != NULL) *out = NULL;
  if (directory == NULL || value == NULL || value[0] == '\0' || out == NULL) {
    return FTUN_E_INVALID;
  }
  if (value[0] == '/') {
    resolved = ftun_config_copy_span(value, strlen(value));
  } else if (value[0] != '~') {
    resolved = ftun_config_join(directory, value);
  } else {
    if (value[1] != '\0' && value[1] != '/') return FTUN_E_INVALID;
    user = getpwuid(geteuid());
    if (user == NULL || user->pw_dir == NULL || user->pw_dir[0] == '\0') {
      return FTUN_E_IO;
    }
    if (value[1] == '\0') {
      resolved = ftun_config_copy_span(user->pw_dir, strlen(user->pw_dir));
    } else {
      resolved = ftun_config_join(user->pw_dir, value + 2);
    }
  }
  if (resolved == NULL) return FTUN_E_LIMIT;
  *out = resolved;
  return FTUN_OK;
}

static ftun_status_t ftun_config_resolve_one(const char *directory, char **value)
{
  char *resolved;
  ftun_status_t status;
  if (value == NULL || *value == NULL) return FTUN_OK;
  status = ftun_config_resolve_path(directory, *value, &resolved);
  if (status != FTUN_OK) return status;
  free(*value);
  *value = resolved;
  return FTUN_OK;
}

static ftun_status_t ftun_config_default_frs_path(char **out)
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
  directory = ftun_config_directory(executable);
  if (directory == NULL) return FTUN_E_IO;
  path = ftun_config_join(directory, "rules.frs");
  free(directory);
  if (path == NULL) return FTUN_E_LIMIT;
  *out = path;
  return FTUN_OK;
}

static ftun_status_t ftun_config_resolve_paths(ftun_config_t *config,
                                               char *source_path)
{
  ftun_status_t status;
  if (config == NULL || source_path == NULL) return FTUN_E_INVALID;
  config->source_path = source_path;
  config->base_directory = ftun_config_directory(source_path);
  if (config->base_directory == NULL) return FTUN_E_LIMIT;
  status = ftun_config_resolve_one(config->base_directory,
                                   &config->base.cache_file);
  if (status == FTUN_OK) {
    status = ftun_config_resolve_one(config->base_directory, &config->log.file);
  }
  if (status == FTUN_OK && config->frs.active) {
    if (config->frs.path == NULL) {
      status = ftun_config_default_frs_path(&config->frs.path);
    } else {
      status = ftun_config_resolve_one(config->base_directory,
                                       &config->frs.path);
    }
  }
  return status;
}

/* TASK-CONFIG-001 / TEST-CONFIG-001，目标 0.2.0：有界配置加载协调。 */
ftun_status_t ftun_config_load(ftun_core_t *core, const char *path,
                               ftun_config_t **out)
{
  ftun_bytes_t bytes;
  ftun_config_t *config = NULL;
  ftun_feature_plan_t *plan = NULL;
  uint8_t *data = NULL;
  char *source_path;
  size_t length = 0u;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (path == NULL || path[0] == '\0' || out == NULL) return FTUN_E_INVALID;
  (void)core;
  source_path = realpath(path, NULL);
  if (source_path == NULL) return FTUN_E_IO;
  if (strlen(source_path) > FTUN_CONFIG_MAX_PATH_BYTES) {
    free(source_path);
    return FTUN_E_LIMIT;
  }
  status = ftun_config_read_file(source_path, &data, &length);
  if (status != FTUN_OK) {
    free(source_path);
    return status;
  }
  bytes.data = data;
  bytes.length = length;
  status = ftun_config_parse(bytes, &config);
  free(data);
  if (status == FTUN_OK) status = ftun_config_resolve_paths(config, source_path);
  if (status != FTUN_OK) {
    if (config == NULL) free(source_path);
    (void)ftun_config_destroy(&config);
    return status;
  }
  status = ftun_config_validate(config, NULL);
  if (status == FTUN_OK) status = ftun_config_compile(config, &plan);
  if (status != FTUN_OK) {
    (void)ftun_feature_plan_destroy(&plan);
    (void)ftun_config_destroy(&config);
    return status;
  }
  config->plan = plan;
  *out = config;
  return FTUN_OK;
}
