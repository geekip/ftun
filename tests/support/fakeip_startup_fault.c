#include "core/io/file.h"
#include "platform/random.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
  ftun_file_stage_hook_fn hook;
  void *user;
  ftun_file_stage_t failed;
} publication_t;

static bool fault(const char *name)
{
  const char *selected = getenv("FTUN_TEST_FAKEIP_FAULT");
  return selected != NULL && strcmp(selected, name) == 0;
}

ftun_status_t __real_ftun_random_bytes(void *buffer, size_t length);
ftun_status_t __wrap_ftun_random_bytes(void *buffer, size_t length)
{
  return fault("random") ? FTUN_E_IO : __real_ftun_random_bytes(buffer, length);
}

ftun_status_t __real_ftun_file_write_atomic_budget(ftun_budget_t *budget,
  const char *path, ftun_bytes_t contents, unsigned int mode,
  ftun_file_stage_hook_fn hook, void *user);
ftun_status_t __wrap_ftun_file_write_atomic_budget(ftun_budget_t *budget,
  const char *path, ftun_bytes_t contents, unsigned int mode,
  ftun_file_stage_hook_fn hook, void *user)
{
  const char *leaf = strrchr(path, '/');
  if (leaf != NULL && fault(leaf + 1u)) return FTUN_E_IO;
  return __real_ftun_file_write_atomic_budget(budget, path, contents, mode, hook, user);
}

static ftun_status_t publication(ftun_file_stage_t stage, void *user)
{
  publication_t *state = user;
  ftun_status_t status = state->hook == NULL ? FTUN_OK : state->hook(stage, state->user);
  return status == FTUN_OK && stage == state->failed ? FTUN_E_IO : status;
}

ftun_status_t __real_ftun_directory_publish(const char *temporary, const char *destination,
  const char *parent, ftun_file_stage_hook_fn hook, void *user, bool *published);
ftun_status_t __wrap_ftun_directory_publish(const char *temporary, const char *destination,
  const char *parent, ftun_file_stage_hook_fn hook, void *user, bool *published)
{
  publication_t state = {hook, user, fault("temp-synced") ? FTUN_FILE_STAGE_TEMP_SYNCED :
    fault("renamed") ? FTUN_FILE_STAGE_RENAMED : fault("dir-synced") ? FTUN_FILE_STAGE_DIRECTORY_SYNCED : 0};
  if (fault("occupied")) {
    ftun_status_t status = ftun_directory_create(destination, 0700u);
    if (status != FTUN_OK) return status;
  }
  return __real_ftun_directory_publish(temporary, destination, parent, publication, &state, published);
}
