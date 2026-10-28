#ifndef FTUN_CONFIG_VALIDATE_H
#define FTUN_CONFIG_VALIDATE_H
#include "internal/contracts.h"
/* 无副作用语义校验，diagnostic 中的字符串为静态借用视图。
 * 实现路径：验证名称、端口冲突、能力、引用和组环；校验不 bind、不解析网络、不创建闲置节点资源。
 * 调用边界：不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；不转移输入所有权，不执行文件或网络 I/O。
 */
ftun_status_t ftun_config_validate(const ftun_config_t *config, ftun_diagnostic_t *out);
#endif
