#include <string.h>
#include "ftun/ftun.h"
#include "ftun/error.h"

int main(void)
{
  ftun_core_t *core = NULL;
  ftun_core_info_t info;
  ftun_core_options_t options = {0};
  options.struct_size = sizeof(options);
  options.abi_version = FTUN_ABI_VERSION;
  options.owned_memory_limit = 8u * 1024u * 1024u;
  options.operation_capacity = 8u;
  options.retained_runtime_limit = 2u;
  if (ftun_core_create(&options, &core) != FTUN_OK) return 1;
  if (ftun_core_get_info(core, &info) != FTUN_OK || info.state != FTUN_CORE_CREATED) return 2;
  if (strcmp(ftun_version(), FTUN_VERSION) != 0) return 3;
  if (ftun_core_destroy(&core) != FTUN_OK || core != NULL) return 4;
  return 0;
}
