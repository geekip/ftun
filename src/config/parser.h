#ifndef FTUN_CONFIG_PARSER_H
#define FTUN_CONFIG_PARSER_H
#include "internal/contracts.h"
/* JSON 到类型配置。
 * 需求 REQ-CONF-001；任务 TASK-CONFIG-002；目标 0.2.0；验收 TEST-CONFIG-002。
 * 实现路径：拒绝重复键、未知字段、深度/长度/整数溢出；解析树只在控制阶段存在；关闭 DNS 时不建立无效 DNS 选择依赖。
 * 根 $schema 是编辑器元数据：检查为字符串后忽略，不下载、不参与 Runtime 身份。
 * 字段结构与根 schema.json 保持一致；引用、环、文件等仍交 validate 校验。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_config_parse(ftun_bytes_t json, ftun_config_t **out);
#endif
