#ifndef FTUN_SNIFF_SNIFF_H
#define FTUN_SNIFF_SNIFF_H
#include "internal/contracts.h"
/* 有界域名提示。
 * 需求 REQ-SNIFF-001；任务 TASK-SNIFF-001；目标 0.5.0；验收 TEST-SNIFF-001。
 * 实现路径：仅缺少域名时分派 SNI/Host；超时/无结果继续原信息；所有预读返回 relay，原始真实 IP 不变。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_sniff_domain(const ftun_metadata_t *metadata, ftun_bytes_t preread, ftun_sniff_result_t *out);
#endif
