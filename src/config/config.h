#ifndef FTUN_CONFIG_CONFIG_H
#define FTUN_CONFIG_CONFIG_H
#include "internal/contracts.h"
/* 配置加载协调。
 * 需求 REQ-CONF-001；任务 TASK-CONFIG-001；目标 0.2.0；验收 TEST-CONFIG-001。
 * 实现路径：有界读取后依次调用 parser/validate/compile；路径相对配置目录；失败不替换 active Runtime。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；core 当前仅保留为后续预算接入点，可为 NULL。
 * 成功返回拥有型配置及其 plan；失败不转移所有权并清空输出。
 */
ftun_status_t ftun_config_load(ftun_core_t *core, const char *path, ftun_config_t **out);
#endif
