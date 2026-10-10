#include "fakeip_store.h"
#include <string.h>

/* 预留范围持久化。
 * 需求 REQ-PERSIST-001；任务 TASK-STATE-001；目标 0.3.0；验收 TEST-STATE-001。
 * 实现路径：独占 writer 追加单调高水位并同步；owner loop 收到耐久完成才发布新地址；写入不确定立即停止新发号。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_fakeip_store_reserve(ftun_fakeip_store_t *store, uint32_t end_exclusive, ftun_operation_t **out)
{
  if (out != NULL) *out = NULL;
  (void)store;
  (void)end_exclusive;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
