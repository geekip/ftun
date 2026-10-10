#ifndef FTUN_GROUP_SELECT_H
#define FTUN_GROUP_SELECT_H
#include "internal/contracts.h"
/* 人工组状态。
 * 需求 REQ-GROUP-001；任务 TASK-GROUP-001；目标 0.4.0；验收 TEST-GROUP-001。
 * 实现路径：在 owner loop 校验成员身份和配置代次，更新新请求选择；保存状态不覆盖新 default，旧 Session 不迁移。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_select_set(ftun_core_t *core, uint32_t group_id, uint32_t member_id);
#endif
