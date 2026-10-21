#ifndef FTUN_APP_CLI_INTERNAL_H
#define FTUN_APP_CLI_INTERNAL_H

#include "ftun/ftun.h"
#include "config/model.h"

int ftun_cli_error(const char *operation, ftun_status_t status);
ftun_status_t ftun_cli_core_create(const ftun_config_t *config,
                                   ftun_core_t **out);
ftun_status_t ftun_cli_check_config(const char *path, int require_inbound,
                                    ftun_config_t **out_config);
void ftun_cli_warn_deprecated_config(const ftun_config_t *config);
int ftun_cli_check(const char *path);
int ftun_cli_run(const char *path);
int ftun_cli_signal_process(const char *text, int signal_number,
                            const char *operation);
int ftun_cli_fakeip_init(const char *path);
void ftun_cli_print_version(void);

#endif
