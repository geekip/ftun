#include "file.h"
#include <string.h>

/* 持久文件替换。
 * 需求 REQ-PERSIST-001；任务 TASK-PLATFORM-005；目标 0.3.0；验收 TEST-PLATFORM-005。
 * 实现路径：独占身份锁，同文件系统写入/同步/原子替换/目录同步；错误保留权威旧文件，不把 rename 等同于全部耐久性。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_file_replace(const char *temporary, const char *destination)
{
  (void)temporary;
  (void)destination;
  return FTUN_E_NOT_IMPLEMENTED;
}
