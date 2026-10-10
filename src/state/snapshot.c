#include "snapshot.h"
#include <string.h>

/* 批量映射快照。
 * 需求 REQ-PERSIST-001；任务 TASK-STATE-002；目标 0.3.0；验收 TEST-STATE-002。
 * 实现路径：流式复制固定序号视图，临时文件同步后原子替换；恢复仅接收对应池身份且位于预留范围的映射。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_fakeip_snapshot_save(ftun_fakeip_store_t *store, const ftun_fakeip_snapshot_t *snapshot, ftun_operation_t **out)
{
  if (out != NULL) *out = NULL;
  (void)store;
  (void)snapshot;
  (void)out;
  return FTUN_E_NOT_IMPLEMENTED;
}
