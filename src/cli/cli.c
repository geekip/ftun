#include "cli.h"
#include "ftun/ftun.h"
#include <stdio.h>
#include <string.h>
/* REQ-CLI-001 / TASK-DOC-001：只有 help/version 是已实现命令。
 * 后续再接入 config/Core/离线状态工具。未实现路径不能返回检查成功或 ready。 */
int ftun_cli_main(int argc, char **argv) {
  if (argc == 2 && (strcmp(argv[1], "version") == 0 || strcmp(argv[1], "--version") == 0)) {
    printf("FTUN %s (skeleton; proxy features: none)\n", ftun_version());
    return 0;
  }
  if (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "help") == 0)) {
    puts("Usage: ftun version | help\nDesign skeleton only. run/check/reload/fakeip are not implemented.");
    return 0;
  }
  fputs("ftun: not-implemented: this skeleton does not run or validate a proxy configuration\n", stderr);
  return 2;
}
