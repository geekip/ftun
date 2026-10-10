#ifndef FTUN_STATE_GROUP_CACHE_H
#define FTUN_STATE_GROUP_CACHE_H
#include "internal/contracts.h"
/* 可丢弃组缓存。
 * 需求 REQ-STATE-001；任务 TASK-STATE-003；目标 0.5.0；验收 TEST-STATE-003。
 * 实现路径：仅 base.state-cache 开启写入；记录配置摘要和合法成员，Health 过期不当新样本；不处理 FakeIP 身份。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_group_cache_save(ftun_core_t *core, const char *path);
#endif
