#ifndef FTUN_APP_CLI_INTERNAL_H
#define FTUN_APP_CLI_INTERNAL_H

#include "ftun/ftun.h"
#include "config/model.h"

int ftun_cli_error(const char *operation, ftun_status_t status);
ftun_status_t ftun_cli_core_create(const ftun_config_t *config,
                                   ftun_core_t **out);
/* 配置借用此 Core 的预算，两个句柄一起拥有。调用前清零；即使检查失败，
 * 也须 destroy。释放失败保留未消费句柄，配置先于预算宿主销毁。 */
typedef struct {
  ftun_core_t *core;
  ftun_config_t *config;
} ftun_cli_checked_config_t;
ftun_status_t ftun_cli_check_config(const char *path, int require_inbound,
  ftun_cli_checked_config_t *out);
ftun_status_t ftun_cli_checked_config_destroy(ftun_cli_checked_config_t *checked);
void ftun_cli_warn_deprecated_config(const ftun_config_t *config);
int ftun_cli_check(const char *path);
int ftun_cli_run(const char *path);
int ftun_cli_signal_process(const char *text, int signal_number,
                            const char *operation);
int ftun_cli_fakeip_init(const char *path);
void ftun_cli_print_version(void);

#endif
