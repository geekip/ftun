#ifndef FTUN_SNIFF_HTTP_HOST_H
#define FTUN_SNIFF_HTTP_HOST_H
#include "internal/contracts.h"
/* HTTP Host 提示。
 * 需求 REQ-SNIFF-001；任务 TASK-SNIFF-003；目标 0.5.0；验收 TEST-SNIFF-003。
 * 实现路径：有界读取头部并规范化；与原目标冲突时保留原目标；不消费或改写业务字节。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_sniff_http_host(ftun_bytes_t preread, ftun_sniff_result_t *out);
#endif
