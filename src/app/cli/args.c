#include "app/cli/args.h"

#define OPTPARSE_IMPLEMENTATION
#include "optparse.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

typedef struct {
  struct optparse_long option;
  unsigned int flag;
} ftun_cli_option_t;

static const ftun_cli_option_t ftun_cli_options[] = {
  {{"config", 'c', OPTPARSE_REQUIRED}, FTUN_CLI_OPT_CONFIG},
  {{"pidfile", 'p', OPTPARSE_REQUIRED}, FTUN_CLI_OPT_PIDFILE},
  {{"background", 'b', OPTPARSE_NONE}, FTUN_CLI_OPT_BACKGROUND},
  {{"verbose", 'v', OPTPARSE_NONE}, FTUN_CLI_OPT_VERBOSE},
  {{"json", 128, OPTPARSE_NONE}, FTUN_CLI_OPT_JSON},
  {{"timeout", 129, OPTPARSE_REQUIRED}, FTUN_CLI_OPT_TIMEOUT},
  {{"no-wait", 130, OPTPARSE_NONE}, FTUN_CLI_OPT_NO_WAIT},
  {{"no-color", 131, OPTPARSE_NONE}, FTUN_CLI_OPT_NO_COLOR},
  {{"modules", 132, OPTPARSE_NONE}, FTUN_CLI_OPT_MODULES},
  {{"help", 'h', OPTPARSE_NONE}, 0u}
};

static bool ftun_cli_decimal(const char *text, uint32_t minimum,
  uint32_t maximum, uint32_t *out)
{
  uint32_t value = 0u;
  if (*text == '\0') return false;
  for (; *text != '\0'; ++text) {
    uint32_t digit;
    if (*text < '0' || *text > '9') return false;
    digit = (uint32_t)(*text - '0');
    if (value > (maximum - digit) / 10u) return false;
    value = value * 10u + digit;
  }
  if (value < minimum) return false;
  *out = value;
  return true;
}

static int ftun_cli_args_error(const char *command, const char *message)
{
  fprintf(stderr, "ftun: %s: %s\n", command, message);
  return FTUN_EXIT_USAGE;
}

int ftun_cli_args_parse(char **argv, unsigned int allowed,
  ftun_cli_args_t *out)
{
  struct optparse parser;
  struct optparse_long options[sizeof(ftun_cli_options) / sizeof(ftun_cli_options[0]) + 1u];
  unsigned int seen = 0u;
  size_t i, count = 0u;
  int option, index;
  const char *argument;
  memset(out, 0, sizeof(*out));
  for (i = 0u; i < sizeof(ftun_cli_options) / sizeof(ftun_cli_options[0]); ++i) {
    if (ftun_cli_options[i].flag == 0u ||
        (allowed & ftun_cli_options[i].flag) != 0u) {
      options[count++] = ftun_cli_options[i].option;
    }
  }
  options[count] = (struct optparse_long){NULL, 0, OPTPARSE_NONE};
  optparse_init(&parser, argv);
  while ((option = optparse_long(&parser, options, &index)) != -1) {
    unsigned int flag;
    if (option == '?') return ftun_cli_args_error(argv[0], parser.errmsg);
    flag = 1u << (unsigned int)index;
    if ((seen & flag) != 0u && option != 'v') {
      return ftun_cli_args_error(argv[0], "duplicate option");
    }
    seen |= flag;
    if (parser.optarg != NULL && parser.optarg[0] == '\0') {
      return ftun_cli_args_error(argv[0], "option requires a nonempty value");
    }
    switch (option) {
      case 'c': out->config = parser.optarg; break;
      case 'p': out->pidfile = parser.optarg; break;
      case 'b': out->background = true; break;
      case 'v':
        if (++out->verbose > 2u) {
          return ftun_cli_args_error(argv[0], "at most two verbose options are allowed");
        }
        break;
      case 'h': out->help = true; break;
      case 128: out->json = true; break;
      case 129:
        if (!ftun_cli_decimal(parser.optarg, 1u, 3600u, &out->timeout_seconds)) {
          return ftun_cli_args_error(argv[0], "timeout must be an integer from 1 to 3600 seconds");
        }
        break;
      case 130: out->no_wait = true; break;
      case 131: out->no_color = true; break;
      case 132: out->modules = true; break;
    }
  }
  argument = optparse_arg(&parser);
  if (argument != NULL) {
    if ((allowed & FTUN_CLI_ARG_PID) == 0u) {
      return ftun_cli_args_error(argv[0], "unexpected argument");
    }
    if (!ftun_cli_decimal(argument, 2u, (uint32_t)INT_MAX, &out->pid)) {
      return ftun_cli_args_error(argv[0], "invalid PID");
    }
    out->pid_text = argument;
    if (out->pidfile != NULL) {
      return ftun_cli_args_error(argv[0], "PID and -p cannot be used together");
    }
    if (optparse_arg(&parser) != NULL) {
      return ftun_cli_args_error(argv[0], "unexpected argument");
    }
  }
  return FTUN_EXIT_OK;
}
