#ifndef FTUN_CONFIG_PARSER_H
#define FTUN_CONFIG_PARSER_H
#include "internal/contracts.h"

#define FTUN_CONFIG_MAX_JSON_BYTES (1024u * 1024u)
#define FTUN_CONFIG_MAX_DEPTH 32u
#define FTUN_CONFIG_MAX_NODES 16384u
#define FTUN_CONFIG_MAX_ARRAY_ITEMS 1024u
#define FTUN_CONFIG_MAX_STRING_BYTES FTUN_CONFIG_MAX_JSON_BYTES
#define FTUN_CONFIG_MAX_PATH_BYTES 4096u
/* JSON 到类型配置。
 * 需求 REQ-CONF-001；任务 TASK-CONFIG-002；目标 0.2.0；验收 TEST-CONFIG-002。
 * 实现路径：拒绝重复键、未知字段、深度/长度/整数溢出；解析树只在控制阶段存在；关闭 DNS 时不建立无效 DNS 选择依赖。
 * 根 $schema 是编辑器元数据：检查为字符串后忽略，不下载、不参与 Runtime 身份。
 * 字段结构与根 schema.json 保持一致；引用、环、文件等仍交 validate 校验。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；成功返回拥有型模型，owner loop 可显式 retain 给不可变 Runtime。
 * 不调用回调；失败输出清空，所有部分分配均在返回前回滚。
 */
ftun_status_t ftun_config_parse(ftun_bytes_t json, ftun_config_t **out);
/* owner-loop 引用；成功后配置须由对应次数 destroy 释放。 */
ftun_status_t ftun_config_retain(ftun_config_t *config);
/* 销毁拥有型配置；空句柄幂等成功。 */
ftun_status_t ftun_config_destroy(ftun_config_t **config);
#endif
