#include "app/cli/cli.h"
#include "app/cli/internal.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>

static void ftun_cli_usage(FILE *output)
{
  fputs(
    "Usage:\n"
    "  ftun version\n"
    "  ftun help\n"
    "  ftun check -c CONFIG\n"
    "  ftun run -c CONFIG\n"
    "  ftun stop PID\n"
    "  ftun reload PID\n"
    "  ftun fakeip init -c CONFIG\n",
    output);
}

static const char *ftun_cli_config_argument(int argc, char **argv, int start)
{
  if (argc == start + 1) return argv[start];
  if (argc == start + 2 &&
      (strcmp(argv[start], "-c") == 0 ||
       strcmp(argv[start], "--config") == 0)) return argv[start + 1];
  return NULL;
}

int ftun_cli_main(int argc, char **argv)
{
  const char *path;
  if (argc == 2 &&
      (strcmp(argv[1], "version") == 0 || strcmp(argv[1], "--version") == 0)) {
    ftun_cli_print_version();
    return 0;
  }
  if (argc == 2 &&
      (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0 ||
       strcmp(argv[1], "-h") == 0)) {
    ftun_cli_usage(stdout);
    return 0;
  }
  if (argc >= 2 && strcmp(argv[1], "check") == 0) {
    path = ftun_cli_config_argument(argc, argv, 2);
    if (path != NULL) return ftun_cli_check(path);
  } else if (argc >= 2 && strcmp(argv[1], "run") == 0) {
    path = ftun_cli_config_argument(argc, argv, 2);
    if (path != NULL) return ftun_cli_run(path);
  } else if (argc == 3 && strcmp(argv[1], "stop") == 0) {
    return ftun_cli_signal_process(argv[2], SIGTERM, "stop");
  } else if (argc == 3 && strcmp(argv[1], "reload") == 0) {
    return ftun_cli_signal_process(argv[2], SIGHUP, "reload");
  } else if (argc >= 3 && strcmp(argv[1], "fakeip") == 0 &&
             strcmp(argv[2], "init") == 0) {
    path = ftun_cli_config_argument(argc, argv, 3);
    if (path != NULL) return ftun_cli_fakeip_init(path);
  }
  ftun_cli_usage(stderr);
  return 2;
}
