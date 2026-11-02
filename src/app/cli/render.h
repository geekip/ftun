#ifndef FTUN_APP_CLI_RENDER_H
#define FTUN_APP_CLI_RENDER_H

#include "cJSON.h"
#include <stdbool.h>

/* 独立命令输出：分块推进并共享2秒单调期限；满/断管道有界失败。 */
int ftun_cli_output(int descriptor, const char *text);

/* 拥有并消费 object；仅命令进程使用，不从业务 owner 调用阻塞输出。 */
int ftun_cli_json_write(cJSON *object);
int ftun_cli_failure(const char *operation, const char *result,
  const char *message, bool json);

#endif
