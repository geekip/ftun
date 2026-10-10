#ifndef FTUN_TRANSPORT_STREAM_H
#define FTUN_TRANSPORT_STREAM_H
#include "internal/contracts.h"
/* 可保留引用的字节流。
 * 需求 REQ-CORE-001；任务 TASK-TRANSPORT-002；目标 0.2.0；验收 TEST-TRANSPORT-002。
 * 实现路径：同步未接纳不借出缓冲；接纳后保留引用至完成事件；lwIP 可延至 ACK，不能将排队成功等同缓冲可释放。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_stream_write_ref(ftun_stream_t *stream, const ftun_buffer_slice_t *slice, size_t *accepted, ftun_operation_t **out);
#endif
