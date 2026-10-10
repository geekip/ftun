#include "buffer.h"
#include <string.h>

/* 引用缓冲与池。
 * 需求 REQ-PERF-001；任务 TASK-UTIL-002；目标 0.2.0；验收 TEST-UTIL-002。
 * 实现路径：按需分档申请，有界闲置保留；slice 持有所有者而非栈指针；协议/lwIP/TLS 内部队列一起计账。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_buffer_acquire(ftun_budget_t *budget, size_t capacity, ftun_buffer_t **out)
{
  if (out != NULL) *out = NULL;
  (void)budget;
  (void)capacity;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
