#include "app/cli/internal.h"
#include "app/cli/render.h"

#include <stdio.h>

static const char *const ftun_cli_modules[] = {
  "core",
#if defined(FTUN_HAVE_MODULE_PROXY)
  "proxy",
#endif
#if defined(FTUN_HAVE_MODULE_DNS)
  "dns",
#endif
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  "fakeip",
#endif
#if defined(FTUN_HAVE_MODULE_TUN)
  "tun",
#endif
#if defined(FTUN_HAVE_MODULE_FRS)
  "frs",
#endif
};

int ftun_cli_print_version(const ftun_cli_args_t *args)
{
  if (args->json) {
    cJSON *object = cJSON_CreateObject();
    if (object == NULL || cJSON_AddStringToObject(object, "result", "ok") == NULL ||
        cJSON_AddStringToObject(object, "version", ftun_version()) == NULL) goto failed;
    if (args->modules) {
      cJSON *modules = cJSON_CreateStringArray(ftun_cli_modules,
        (int)(sizeof(ftun_cli_modules) / sizeof(ftun_cli_modules[0])));
      if (modules == NULL) goto failed;
      if (!cJSON_AddItemToObject(object, "modules", modules)) {
        cJSON_Delete(modules);
        goto failed;
      }
      if (cJSON_AddStringToObject(object, "source", FTUN_SOURCE_REVISION) == NULL ||
          cJSON_AddStringToObject(object, "target", FTUN_BUILD_TARGET) == NULL) goto failed;
    }
    return ftun_cli_json_write(object);
failed:
    cJSON_Delete(object);
    return ftun_cli_json_write(NULL);
  }
  printf("FTUN %s\n", ftun_version());
  if (args->modules) {
    size_t i;
    printf("source: %s\ntarget: %s\ncapabilities: ", FTUN_SOURCE_REVISION, FTUN_BUILD_TARGET);
    for (i = 0u; i < sizeof(ftun_cli_modules) / sizeof(ftun_cli_modules[0]); ++i) {
      printf("%s%s", i == 0u ? "" : ",", ftun_cli_modules[i]);
    }
    putchar('\n');
  }
  return ferror(stdout) == 0 && fflush(stdout) == 0 ? FTUN_EXIT_OK : FTUN_EXIT_FAIL;
}
