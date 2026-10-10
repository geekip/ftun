#ifndef FTUN_GEO_GEOSITE_H
#define FTUN_GEO_GEOSITE_H
#include "internal/contracts.h"
/* 域名集合成员查询。
 * 需求 REQ-GEO-001；任务 TASK-GEO-003；目标 0.4.0；验收 TEST-GEO-003。
 * 实现路径：exact 核对完整键，suffix 按标签边界，keyword 为字节子串；无正则引擎，未知能力拒绝加载。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_geosite_contains(const ftun_geo_view_t *view, uint32_t set_id, ftun_string_t domain, bool *out);
#endif
