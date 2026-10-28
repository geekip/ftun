#define _XOPEN_SOURCE 700
#include "config/compile.h"
#include "config/config.h"
#include "config/model.h"
#include "config/parser.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "config load failed: %s\n", #x); \
    return 1; \
  } \
} while (0)

static int write_file(const char *path, const char *data, size_t length)
{
  size_t written = 0u;
  int descriptor = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (descriptor < 0) return 0;
  while (written < length) {
    ssize_t result = write(descriptor, data + written, length - written);
    if (result > 0) {
      written += (size_t)result;
      continue;
    }
    if (result < 0 && errno == EINTR) continue;
    (void)close(descriptor);
    return 0;
  }
  return close(descriptor) == 0;
}

static int make_path(char *out, size_t capacity, const char *left,
                     const char *right)
{
  int result = snprintf(out, capacity, "%s/%s", left, right);
  return result >= 0 && (size_t)result < capacity;
}

/* 有界读取、路径固定和失败清理。 */
int main(void)
{
  static const char valid[] =
    "{\"dns\":{\"enable\":false},\"base\":{\"cache-file\":\"../state/cache\"},"
    "\"log\":{\"file\":\"logs/ftun.log\"},\"frs\":{"
    "\"path\":\"./data/rules.frs\"},\"rules\":[\"FRS-IP,CN,DIRECT\"],"
    "\"outbounds\":[{\"name\":\"unused\","
    "\"type\":\"socks5\",\"server\":\"unused.example:1080\"}]}";
  char temporary[] = "/tmp/ftun-config-load-XXXXXX";
  char config_directory[PATH_MAX];
  char config_path[PATH_MAX];
  char default_path[PATH_MAX];
  char invalid_path[PATH_MAX];
  char semantic_path[PATH_MAX];
  char tilde_path[PATH_MAX];
  char bad_tilde_path[PATH_MAX];
  char large_path[PATH_MAX];
  char expected[PATH_MAX];
  char *root;
  char *canonical;
  char executable[PATH_MAX];
  char *separator;
  ssize_t executable_length;
  struct passwd *user;
  ftun_config_t *config = NULL;
  ftun_config_trace_t trace;
  int descriptor;

  root = mkdtemp(temporary);
  CHECK(root != NULL);
  CHECK(make_path(config_directory, sizeof(config_directory), root, "configs"));
  CHECK(mkdir(config_directory, 0700) == 0);
  CHECK(make_path(config_path, sizeof(config_path), config_directory, "valid.json"));
  CHECK(make_path(invalid_path, sizeof(invalid_path), config_directory, "invalid.json"));
  CHECK(make_path(default_path, sizeof(default_path), config_directory, "default.json"));
  CHECK(make_path(semantic_path, sizeof(semantic_path), config_directory, "semantic.json"));
  CHECK(make_path(tilde_path, sizeof(tilde_path), config_directory, "tilde.json"));
  CHECK(make_path(bad_tilde_path, sizeof(bad_tilde_path), config_directory,
                  "bad-tilde.json"));
  CHECK(make_path(large_path, sizeof(large_path), config_directory, "large.json"));
  CHECK(write_file(config_path, valid, strlen(valid)));

  CHECK(ftun_config_load_traced(config_path, &config, &trace) == FTUN_OK && config != NULL);
  CHECK(trace.completed == FTUN_CONFIG_STEP_COMPILE && trace.failed == FTUN_CONFIG_STEP_NONE &&
    trace.status == FTUN_OK);
  canonical = realpath(config_path, NULL);
  CHECK(canonical != NULL);
  CHECK(strcmp(config->source_path, canonical) == 0);
  CHECK(strcmp(config->base_directory, config_directory) == 0);
  CHECK(make_path(expected, sizeof(expected), config_directory, "../state/cache"));
  CHECK(strcmp(config->base.cache_file, expected) == 0);
  CHECK(make_path(expected, sizeof(expected), config_directory, "logs/ftun.log"));
  CHECK(strcmp(config->log.file, expected) == 0);
  CHECK(make_path(expected, sizeof(expected), config_directory, "./data/rules.frs"));
  CHECK(strcmp(config->frs.path, expected) == 0);
  CHECK(config->plan != NULL && config->plan->required_modules ==
        (FTUN_BUILD_MODULE_CORE | FTUN_BUILD_MODULE_PROXY |
         FTUN_BUILD_MODULE_FRS));
  CHECK(config->plan->outbound_count == 1u &&
        config->plan->reachable_outbound_count == 0u);
  free(canonical);
  CHECK(ftun_config_destroy(&config) == FTUN_OK && config == NULL);

  CHECK(write_file(default_path,
    "{\"dns\":{\"enable\":false},\"rules\":[\"FRS-IP,CN,DIRECT\"]}",
    strlen("{\"dns\":{\"enable\":false},\"rules\":[\"FRS-IP,CN,DIRECT\"]}")));
  CHECK(ftun_config_load(NULL, default_path, &config) == FTUN_OK &&
        config != NULL);
  executable_length = readlink("/proc/self/exe", executable,
                               sizeof(executable) - 1u);
  CHECK(executable_length > 0 && (size_t)executable_length < sizeof(executable));
  executable[executable_length] = '\0';
  separator = strrchr(executable, '/');
  CHECK(separator != NULL);
  *separator = '\0';
  CHECK(make_path(expected, sizeof(expected), executable, "rules.frs"));
  CHECK(strcmp(config->frs.path, expected) == 0);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);

  CHECK(write_file(tilde_path, "{\"dns\":{\"enable\":false}}",
                   strlen("{\"dns\":{\"enable\":false}}")));
  CHECK(ftun_config_load(NULL, tilde_path, &config) == FTUN_OK && config != NULL);
  user = getpwuid(geteuid());
  CHECK(user != NULL && user->pw_dir != NULL);
  CHECK(make_path(expected, sizeof(expected), user->pw_dir, ".ftun/ftun.cache"));
  CHECK(strcmp(config->base.cache_file, expected) == 0);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);

  CHECK(write_file(invalid_path, "{", 1u));
  config = (ftun_config_t *)(uintptr_t)1;
  CHECK(ftun_config_load_traced(invalid_path, &config, &trace) == FTUN_E_INVALID && config == NULL);
  CHECK(trace.completed == FTUN_CONFIG_STEP_READ && trace.failed == FTUN_CONFIG_STEP_PARSE);
  CHECK(write_file(semantic_path, "{\"log\":{\"level\":\"bad\"}}",
                   strlen("{\"log\":{\"level\":\"bad\"}}")));
  CHECK(ftun_config_load_traced(semantic_path, &config, &trace) == FTUN_E_INVALID && config == NULL);
  CHECK(trace.completed == FTUN_CONFIG_STEP_PATHS && trace.failed == FTUN_CONFIG_STEP_VALIDATE);
  CHECK(write_file(bad_tilde_path,
                   "{\"dns\":{\"enable\":false},\"log\":{\"file\":\"~other/x\"}}",
                   strlen("{\"dns\":{\"enable\":false},\"log\":{"
                          "\"file\":\"~other/x\"}}")));
  CHECK(ftun_config_load_traced(bad_tilde_path, &config, &trace) == FTUN_E_INVALID &&
        config == NULL);
  CHECK(trace.completed == FTUN_CONFIG_STEP_PARSE && trace.failed == FTUN_CONFIG_STEP_PATHS);

  descriptor = open(large_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  CHECK(descriptor >= 0);
  CHECK(ftruncate(descriptor, (off_t)FTUN_CONFIG_MAX_JSON_BYTES + 1) == 0);
  CHECK(close(descriptor) == 0);
  CHECK(ftun_config_load(NULL, large_path, &config) == FTUN_E_LIMIT && config == NULL);
  CHECK(ftun_config_load(NULL, config_directory, &config) == FTUN_E_IO && config == NULL);
  CHECK(make_path(expected, sizeof(expected), config_directory, "missing.json"));
  CHECK(ftun_config_load_traced(expected, &config, &trace) == FTUN_E_IO && config == NULL);
  CHECK(trace.completed == FTUN_CONFIG_STEP_NONE && trace.failed == FTUN_CONFIG_STEP_READ);
  CHECK(ftun_config_load(NULL, "", &config) == FTUN_E_INVALID && config == NULL);
  CHECK(ftun_config_load(NULL, NULL, &config) == FTUN_E_INVALID && config == NULL);
  CHECK(ftun_config_load(NULL, config_path, NULL) == FTUN_E_INVALID);

  CHECK(unlink(config_path) == 0);
  CHECK(unlink(invalid_path) == 0);
  CHECK(unlink(default_path) == 0);
  CHECK(unlink(semantic_path) == 0);
  CHECK(unlink(tilde_path) == 0);
  CHECK(unlink(bad_tilde_path) == 0);
  CHECK(unlink(large_path) == 0);
  CHECK(rmdir(config_directory) == 0);
  CHECK(rmdir(root) == 0);
  return 0;
}
