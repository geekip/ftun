#ifndef FTUN_PROTOCOL_ANYTLS_H
#define FTUN_PROTOCOL_ANYTLS_H
#include "internal/contracts.h"
/* AnyTLS 帧扩展。
 * 需求 REQ-FUTURE-001；任务 TASK-PROTOCOL-003；目标 1.1.0；验收 TEST-PROTOCOL-003。
 * 实现路径：后续固定协议版本和长度边界；纯解析不操作 Core；协议成功证据由出站适配解释。
 * 调用边界：不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_anytls_decode(ftun_bytes_t input, ftun_protocol_result_t *out);
#endif
