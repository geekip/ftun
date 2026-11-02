#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include <sys/types.h>
#include "core/io/file.h"
#include "core/limits.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "platform file contract failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  ftun_file_stage_t fail_at;
  unsigned int calls;
} hook_state_t;

static ftun_bytes_t bytes(const char *value)
{
  return (ftun_bytes_t){(const uint8_t *)value, strlen(value)};
}

static int path_join(char *out, size_t capacity, const char *directory,
                     const char *name)
{
  int result = snprintf(out, capacity, "%s/%s", directory, name);
  return result > 0 && (size_t)result < capacity;
}

static int read_text(const char *path, char *out, size_t capacity)
{
  int descriptor = open(path, O_RDONLY | O_CLOEXEC);
  ssize_t result;
  if (descriptor < 0 || capacity == 0u) return 0;
  result = read(descriptor, out, capacity - 1u);
  (void)close(descriptor);
  if (result < 0) return 0;
  out[(size_t)result] = '\0';
  return 1;
}

static ftun_status_t fail_hook(ftun_file_stage_t stage, void *user)
{
  hook_state_t *state = (hook_state_t *)user;
  state->calls++;
  return stage == state->fail_at ? FTUN_E_IO : FTUN_OK;
}

static int test_atomic_boundaries_and_lock(void)
{
  char directory[] = "/tmp/ftun-file-test.XXXXXX";
  char destination[256];
  char lock_path[256];
  char value[64];
  hook_state_t hook;
  ftun_file_lock_t *first = NULL;
  ftun_file_lock_t *second = NULL;
  CHECK(mkdtemp(directory) != NULL);
  CHECK(path_join(destination, sizeof(destination), directory, "mappings"));
  CHECK(path_join(lock_path, sizeof(lock_path), directory, "identity.lock"));
  CHECK(ftun_file_lock_acquire(lock_path, &first) == FTUN_OK && first != NULL);
  CHECK(ftun_file_lock_acquire(lock_path, &second) == FTUN_E_AGAIN &&
        second == NULL);
  CHECK(ftun_file_write_atomic(destination, bytes("old"), 0600u) == FTUN_OK);
  CHECK(read_text(destination, value, sizeof(value)) &&
        strcmp(value, "old") == 0);

  memset(&hook, 0, sizeof(hook));
  hook.fail_at = FTUN_FILE_STAGE_TEMP_SYNCED;
  CHECK(ftun_file_write_atomic_with_hook(destination, bytes("before"), 0600u,
                                          fail_hook, &hook) == FTUN_E_IO);
  CHECK(hook.calls == 1u && read_text(destination, value, sizeof(value)) &&
        strcmp(value, "old") == 0);

  memset(&hook, 0, sizeof(hook));
  hook.fail_at = FTUN_FILE_STAGE_RENAMED;
  CHECK(ftun_file_write_atomic_with_hook(destination, bytes("renamed"), 0600u,
                                          fail_hook, &hook) == FTUN_E_IO);
  CHECK(hook.calls == 2u && read_text(destination, value, sizeof(value)) &&
        strcmp(value, "renamed") == 0);

  CHECK(ftun_file_write_atomic(destination, bytes("durable"), 0600u) ==
        FTUN_OK);
  CHECK(read_text(destination, value, sizeof(value)) &&
        strcmp(value, "durable") == 0);
  CHECK(ftun_file_lock_release(&first) == FTUN_OK && first == NULL);
  CHECK(ftun_file_lock_acquire(lock_path, &second) == FTUN_OK);
  CHECK(ftun_file_lock_release(&second) == FTUN_OK);
  CHECK(unlink(destination) == 0);
  CHECK(unlink(lock_path) == 0);
  CHECK(rmdir(directory) == 0);
  return 0;
}

static int test_replace_validation(void)
{
  char directory[] = "/tmp/ftun-file-replace.XXXXXX";
  char temporary[256];
  char destination[256];
  char value[32];
  int descriptor;
  CHECK(mkdtemp(directory) != NULL);
  CHECK(path_join(temporary, sizeof(temporary), directory, "temporary"));
  CHECK(path_join(destination, sizeof(destination), directory, "destination"));
  descriptor = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  CHECK(descriptor >= 0);
  CHECK(write(descriptor, "new", 3u) == 3);
  CHECK(close(descriptor) == 0);
  CHECK(ftun_file_replace(temporary, destination) == FTUN_OK);
  CHECK(access(temporary, F_OK) != 0);
  CHECK(read_text(destination, value, sizeof(value)) && strcmp(value, "new") == 0);
  CHECK(ftun_file_replace(destination, destination) == FTUN_E_INVALID);
  CHECK(ftun_file_replace(NULL, destination) == FTUN_E_INVALID);
  CHECK(unlink(destination) == 0);
  CHECK(rmdir(directory) == 0);
  return 0;
}

static int test_lock_pool(void)
{
  char directory[] = "/tmp/ftun-lock-pool.XXXXXX", path[256];
  ftun_budget_t *budget = NULL;
  ftun_file_lock_pool_t *pool = NULL, *other = NULL;
  ftun_file_lock_t *first = NULL, *second = NULL, *contender = NULL;
  ftun_budget_options_t options = {{65536u, 4u, 16u}, {0}, {0}};
  ftun_budget_usage_t baseline, one, shared, released;
  CHECK(mkdtemp(directory) != NULL);
  CHECK(path_join(path, sizeof(path), directory, "cache.lock"));
  CHECK(ftun_budget_create_resources(NULL, &options, &budget) == FTUN_OK);
  CHECK(ftun_file_lock_pool_create(budget, &pool) == FTUN_OK);
  CHECK(ftun_file_lock_pool_create(budget, &other) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &baseline) == FTUN_OK);
  CHECK(ftun_file_lock_pool_acquire(pool, path, &first) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &one) == FTUN_OK);
  CHECK(one.used_resources.descriptors == baseline.used_resources.descriptors + 1u);
  CHECK(ftun_file_lock_pool_acquire(pool, path, &second) == FTUN_OK && second == first);
  CHECK(ftun_budget_get_usage(budget, &shared) == FTUN_OK);
  CHECK(shared.used_resources.memory_bytes == one.used_resources.memory_bytes &&
        shared.used_resources.descriptors == one.used_resources.descriptors);
  CHECK(ftun_file_lock_pool_acquire(other, path, &contender) == FTUN_E_AGAIN && contender == NULL);
  CHECK(ftun_file_lock_pool_destroy(&pool) == FTUN_E_AGAIN && pool != NULL);
  CHECK(ftun_file_lock_release(&first) == FTUN_OK && first == NULL);
  CHECK(ftun_file_lock_acquire(path, &contender) == FTUN_E_AGAIN);
  /* Worker 的引用可晚于当前配置引用结束；最后一个引用结束才允许外部接管。 */
  ftun_file_lock_retain(second);
  first = second;
  CHECK(ftun_file_lock_release(&second) == FTUN_OK);
  CHECK(ftun_file_lock_acquire(path, &contender) == FTUN_E_AGAIN);
  CHECK(ftun_file_lock_release(&first) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &released) == FTUN_OK);
  CHECK(released.used_resources.memory_bytes == baseline.used_resources.memory_bytes &&
        released.used_resources.descriptors == baseline.used_resources.descriptors);
  CHECK(ftun_file_lock_pool_acquire(other, path, &contender) == FTUN_OK);
  CHECK(ftun_file_lock_release(&contender) == FTUN_OK);
  CHECK(ftun_file_lock_pool_destroy(&pool) == FTUN_OK);
  CHECK(ftun_file_lock_pool_destroy(&other) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(unlink(path) == 0 && rmdir(directory) == 0);
  return 0;
}

static int test_create_without_replace(void)
{
  char directory[] = "/tmp/ftun-create-test.XXXXXX";
  char path[256], value[64];
  struct stat info;
  CHECK(mkdtemp(directory) != NULL);
  CHECK(path_join(path, sizeof(path), directory, "config.json"));
  CHECK(ftun_file_create_atomic_budget(NULL, path, bytes("first"), 0600u) == FTUN_OK);
  CHECK(stat(path, &info) == 0 && (info.st_mode & 0777) == 0600);
  CHECK(ftun_file_create_atomic_budget(NULL, path, bytes("second"), 0600u) == FTUN_E_STALE);
  CHECK(read_text(path, value, sizeof(value)) && strcmp(value, "first") == 0);
  CHECK(unlink(path) == 0 && symlink("absent", path) == 0);
  CHECK(ftun_file_create_atomic_budget(NULL, path, bytes("second"), 0600u) == FTUN_E_STALE);
  CHECK(lstat(path, &info) == 0 && S_ISLNK(info.st_mode));
  CHECK(unlink(path) == 0 && rmdir(directory) == 0);
  return 0;
}

int main(void)
{
  CHECK(test_atomic_boundaries_and_lock() == 0);
  CHECK(test_replace_validation() == 0);
  CHECK(test_lock_pool() == 0);
  CHECK(test_create_without_replace() == 0);
  return 0;
}
