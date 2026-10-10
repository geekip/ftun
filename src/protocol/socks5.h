#ifndef FTUN_PROTOCOL_SOCKS5_H
#define FTUN_PROTOCOL_SOCKS5_H
#include "internal/contracts.h"
/* 共享 SOCKS5 编解码。
 * 需求 REQ-OUT-001；任务 TASK-PROTOCOL-001；目标 0.2.0；验收 TEST-PROTOCOL-001。
 * 实现路径：纯增量 parser，区分需更多字节/非法/完成；显式网络字节序；入出站共用而不共享认证状态。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_socks5_decode(ftun_bytes_t input, ftun_protocol_result_t *out);
#endif
