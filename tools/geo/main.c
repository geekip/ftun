#include <stdio.h>
#include <string.h>
/* REQ-GEO-001：独立 C 工具占位。输入适配须等待用户规则样例。
 * 后续 parse -> normalize -> validate all -> build index -> verify -> atomic publish。
 * 遇到正则/未知类型整个任务失败，不打开或覆盖输出文件。 */
int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "version") == 0) {
    puts("ftun-geo 0.1.0-dev (skeleton; converter: not implemented)"); return 0;
  }
  fputs("ftun-geo: not-implemented: source rules and converter are not available\n", stderr);
  return 2;
}
