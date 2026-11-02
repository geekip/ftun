#ifndef FTUN_APP_CLI_INTERNAL_H
#define FTUN_APP_CLI_INTERNAL_H

#include "ftun/ftun.h"
#include "app/config/model.h"
#include "app/cli/args.h"
#include "cJSON.h"
#include "core/config/error.h"

int ftun_cli_error(const char *operation, ftun_status_t status);
ftun_status_t ftun_cli_core_create(const ftun_config_t *config,
                                   ftun_core_t **out);
/* 配置借用此 Core 的预算，两个句柄一起拥有。调用前清零；即使检查失败，
 * 也须 destroy。释放失败保留未消费句柄，配置先于预算宿主销毁。 */
typedef struct {
  ftun_core_t *core;
  ftun_config_t *config;
  ftun_config_error_t error;
  size_t frs_sets;
} ftun_cli_checked_config_t;
ftun_status_t ftun_cli_check_config(const char *path, int require_inbound,
  ftun_cli_checked_config_t *out);
ftun_status_t ftun_cli_checked_config_destroy(ftun_cli_checked_config_t *checked);
ftun_status_t ftun_cli_config_path(const char *path, char *output, size_t capacity);
int ftun_cli_config_error(const char *operation, const ftun_config_error_t *error, bool json);
int ftun_cli_check(const char *path, bool json);
int ftun_cli_run(const char *path, const char *pidfile, bool no_color, unsigned int verbosity, bool background);
int ftun_cli_status_render(const char *operation, const cJSON *root);
int ftun_cli_control(const ftun_cli_args_t *args, const char *operation);
int ftun_cli_print_version(const ftun_cli_args_t *args);

#endif
