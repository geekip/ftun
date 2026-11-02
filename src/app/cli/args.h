#ifndef FTUN_APP_CLI_ARGS_H
#define FTUN_APP_CLI_ARGS_H

#include <stdbool.h>
#include <stdint.h>

enum {
  FTUN_EXIT_OK = 0,
  FTUN_EXIT_FAIL = 1,
  FTUN_EXIT_USAGE = 2,
  FTUN_EXIT_FATAL = 3,
  FTUN_EXIT_WATCHDOG = 4,
  FTUN_EXIT_UNKNOWN = 5
};

enum {
  FTUN_CLI_OPT_CONFIG = 1u << 0,
  FTUN_CLI_OPT_PIDFILE = 1u << 1,
  FTUN_CLI_OPT_BACKGROUND = 1u << 2,
  FTUN_CLI_OPT_VERBOSE = 1u << 3,
  FTUN_CLI_OPT_JSON = 1u << 4,
  FTUN_CLI_OPT_TIMEOUT = 1u << 5,
  FTUN_CLI_OPT_NO_WAIT = 1u << 6,
  FTUN_CLI_OPT_NO_COLOR = 1u << 7,
  FTUN_CLI_OPT_MODULES = 1u << 8,
  FTUN_CLI_ARG_PID = 1u << 9
};

typedef struct {
  const char *config;
  const char *pidfile;
  const char *pid_text;
  uint32_t pid;
  uint32_t timeout_seconds;
  unsigned int verbose;
  bool background;
  bool json;
  bool no_wait;
  bool no_color;
  bool modules;
  bool help;
} ftun_cli_args_t;

/* argv 以命令/动作为首项并以 NULL 结尾；原地重排，字符串借用至命令结束。
 * 无分配、无 I/O（错误诊断除外）；失败返回 USAGE，不执行任何命令。 */
int ftun_cli_args_parse(char **argv, unsigned int allowed,
  ftun_cli_args_t *out);

#endif
