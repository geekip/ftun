#include "app/cli/cli.h"
#include "app/cli/internal.h"
#include "app/cli/args.h"
#include "app/cli/render.h"

#include "platform/process.h"
#include <stdio.h>
#include <string.h>

#define FTUN_CLI_INSTANCE (FTUN_CLI_OPT_PIDFILE | FTUN_CLI_ARG_PID | FTUN_CLI_OPT_JSON)

typedef struct {
  const char *name;
  const char *action;
  unsigned int options;
  bool built;
  int (*handler)(const ftun_cli_args_t *args);
  const char *usage;
} ftun_cli_command_t;

static int ftun_cli_run_command(const ftun_cli_args_t *args)
{
  return ftun_cli_run(args->config, args->pidfile, args->no_color, args->verbose, args->background);
}

static int ftun_cli_check_command(const ftun_cli_args_t *args)
{
  return ftun_cli_check(args->config, args->json);
}

static int ftun_cli_stop_command(const ftun_cli_args_t *args)
{
  return ftun_cli_control(args, "stop");
}

static int ftun_cli_reload_command(const ftun_cli_args_t *args)
{
  return ftun_cli_control(args, "reload");
}

static int ftun_cli_status_command(const ftun_cli_args_t *args)
{
  return ftun_cli_control(args, "status");
}

static int ftun_cli_dns_status_command(const ftun_cli_args_t *args)
{
  return ftun_cli_control(args, "dns.status");
}

static int ftun_cli_proxy_status_command(const ftun_cli_args_t *args)
{
  return ftun_cli_control(args, "proxy.status");
}

static const ftun_cli_command_t ftun_cli_commands[] = {
  {"run", NULL, FTUN_CLI_OPT_CONFIG | FTUN_CLI_OPT_PIDFILE |
    FTUN_CLI_OPT_BACKGROUND | FTUN_CLI_OPT_VERBOSE | FTUN_CLI_OPT_NO_COLOR,
    true, ftun_cli_run_command,
    "ftun run [-c FILE] [-p FILE] [-b] [-v|-vv] [--no-color]"},
  {"check", NULL, FTUN_CLI_OPT_CONFIG | FTUN_CLI_OPT_JSON,
    true, ftun_cli_check_command, "ftun check [-c FILE] [--json]"},
  {"stop", NULL, FTUN_CLI_INSTANCE | FTUN_CLI_OPT_TIMEOUT | FTUN_CLI_OPT_NO_WAIT,
    true, ftun_cli_stop_command,
    "ftun stop [PID | -p FILE] [--timeout SEC] [--no-wait] [--json]"},
  {"reload", NULL, FTUN_CLI_INSTANCE | FTUN_CLI_OPT_TIMEOUT | FTUN_CLI_OPT_NO_WAIT,
    true, ftun_cli_reload_command,
    "ftun reload [PID | -p FILE] [--timeout SEC] [--no-wait] [--json]"},
  {"status", NULL, FTUN_CLI_INSTANCE, true, ftun_cli_status_command,
    "ftun status [PID | -p FILE] [--json]"},
  {"dns", "status", FTUN_CLI_INSTANCE,
#if defined(FTUN_HAVE_MODULE_DNS)
    true,
#else
    false,
#endif
    ftun_cli_dns_status_command, "ftun dns status [PID | -p FILE] [--json]"},
  {"proxy", "status", FTUN_CLI_INSTANCE,
#if defined(FTUN_HAVE_MODULE_PROXY)
    true,
#else
    false,
#endif
    ftun_cli_proxy_status_command, "ftun proxy status [PID | -p FILE] [--json]"},
  {"version", NULL, FTUN_CLI_OPT_MODULES | FTUN_CLI_OPT_JSON,
    true, ftun_cli_print_version, "ftun version [--modules] [--json]"}
};

static void ftun_cli_usage(FILE *output)
{
  size_t i;
  fputs("Usage:\n", output);
  for (i = 0u; i < sizeof(ftun_cli_commands) / sizeof(ftun_cli_commands[0]); ++i) {
    if (ftun_cli_commands[i].built) fprintf(output, "  %s\n", ftun_cli_commands[i].usage);
  }
  fputs("  ftun help [COMMAND [ACTION]]\n", output);
}

static const ftun_cli_command_t *ftun_cli_find_command(const char *name)
{
  size_t i;
  for (i = 0u; i < sizeof(ftun_cli_commands) / sizeof(ftun_cli_commands[0]); ++i) {
    if (strcmp(name, ftun_cli_commands[i].name) == 0) return &ftun_cli_commands[i];
  }
  return NULL;
}

static int ftun_cli_command_help(const ftun_cli_command_t *command)
{
  printf("Usage:\n  %s\nOptions:\n", command->usage);
  if ((command->options & FTUN_CLI_OPT_CONFIG) != 0u) {
    puts("  -c, --config FILE   Configuration file (default: ~/.ftun/config.json)");
  }
  if ((command->options & FTUN_CLI_OPT_PIDFILE) != 0u) puts("  -p, --pidfile FILE  Instance PID file");
  if ((command->options & FTUN_CLI_OPT_BACKGROUND) != 0u) puts("  -b, --background    Run in the background");
  if ((command->options & FTUN_CLI_OPT_VERBOSE) != 0u) puts("  -v, --verbose       Debug logging; repeat for trace");
  if ((command->options & FTUN_CLI_OPT_JSON) != 0u) puts("      --json          Output one JSON object");
  if ((command->options & FTUN_CLI_OPT_TIMEOUT) != 0u) puts("      --timeout SEC   Wait from 1 to 3600 seconds");
  if ((command->options & FTUN_CLI_OPT_NO_WAIT) != 0u) puts("      --no-wait       Return after request admission");
  if ((command->options & FTUN_CLI_OPT_NO_COLOR) != 0u) puts("      --no-color      Disable log colors");
  if ((command->options & FTUN_CLI_OPT_MODULES) != 0u) puts("      --modules       Include source, target and built-in modules");
  puts("  -h, --help          Show this help");
  return FTUN_EXIT_OK;
}

int ftun_cli_main(int argc, char **argv)
{
  const ftun_cli_command_t *command;
  ftun_cli_args_t args;
  const char *name;
  int start = 1, result;
  bool help;
  if (argc < 2) {
    ftun_cli_usage(stderr);
    return FTUN_EXIT_USAGE;
  }
  help = strcmp(argv[1], "help") == 0;
  if (argc == 2 && (help || strcmp(argv[1], "--help") == 0 ||
      strcmp(argv[1], "-h") == 0)) {
    ftun_cli_usage(stdout);
    return FTUN_EXIT_OK;
  }
  if (help && argc == 3 && (strcmp(argv[2], "help") == 0 || strcmp(argv[2], "-h") == 0 ||
      strcmp(argv[2], "--help") == 0)) {
    ftun_cli_usage(stdout);
    return FTUN_EXIT_OK;
  }
  if (help) ++start;
  name = strcmp(argv[start], "--version") == 0 && !help ? "version" : argv[start];
  command = ftun_cli_find_command(name);
  if (command == NULL) {
    fprintf(stderr, "ftun: unknown command: %s\n", argv[start]);
    return FTUN_EXIT_USAGE;
  }
  if (help) {
    if (argc > start + 2 || (argc == start + 2 &&
        (command->action == NULL || strcmp(argv[start + 1], command->action) != 0))) {
      fputs("ftun: help: unexpected argument\n", stderr);
      return FTUN_EXIT_USAGE;
    }
    if (!command->built) {
      return ftun_cli_failure(command->name, "failed", "not built in this binary", false);
    }
    return ftun_cli_command_help(command);
  }
  if (command->action != NULL) {
    if (argc == start + 2 && (strcmp(argv[start + 1], "help") == 0 ||
        strcmp(argv[start + 1], "--help") == 0 || strcmp(argv[start + 1], "-h") == 0)) {
      if (!command->built) {
        return ftun_cli_failure(command->name, "failed", "not built in this binary", false);
      }
      return ftun_cli_command_help(command);
    }
    if (argc <= start + 1 || strcmp(argv[start + 1], command->action) != 0) {
      if (!command->built) {
        return ftun_cli_failure(command->name, "failed", "not built in this binary", false);
      }
      fprintf(stderr, "ftun: %s: expected %s\n", command->name, command->action);
      return FTUN_EXIT_USAGE;
    }
    ++start;
  }
  result = ftun_cli_args_parse(argv + start, command->options, &args);
  if (result != FTUN_EXIT_OK) return result;
  if (!command->built) {
    return ftun_cli_failure(command->name, "failed", "not built in this binary", args.json);
  }
  if (args.help) return ftun_cli_command_help(command);
  return command->handler(&args);
}
