#ifndef FTUN_API_API_H
#define FTUN_API_API_H
#include "internal/contracts.h"
/* 管理 API 扩展。
 * 需求 REQ-FUTURE-001；任务 TASK-API-001；目标 1.2.0；验收 TEST-API-001。
 * 实现路径：后续独立认证、请求大小、分页与慢客户端预算；当前不监听，不因 C 宿主接口存在而报告管理 API 可用。
 * 调用边界：不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_api_start(ftun_core_t *core, const ftun_api_spec_t *spec);
#endif
