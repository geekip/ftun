#include "app/control.h"
#include <stdlib.h>
#include <string.h>

ftun_status_t __real_ftun_app_control_submit(ftun_core_t *, const ftun_app_command_t *,
  ftun_app_command_completion_fn, void *, ftun_operation_t **);

ftun_status_t __wrap_ftun_app_control_submit(ftun_core_t *core, const ftun_app_command_t *command,
  ftun_app_command_completion_fn callback, void *user, ftun_operation_t **out)
{
  static unsigned int reloads;
  const char *failure = getenv("FTUN_TEST_QUEUED_ADMISSION");
  if (command->kind == FTUN_APP_COMMAND_RELOAD && ++reloads == 2u && failure != NULL) {
    *out = NULL;
    return strcmp(failure, "again") == 0 ? FTUN_E_AGAIN : FTUN_E_LIMIT;
  }
  return __real_ftun_app_control_submit(core, command, callback, user, out);
}
