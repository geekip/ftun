#ifndef FTUN_SNIFF_TLS_SNI_H
#define FTUN_SNIFF_TLS_SNI_H
#include "internal/contracts.h"
/* TLS ClientHello 解析。
 * 需求 REQ-SNIFF-001；任务 TASK-SNIFF-002；目标 0.5.0；验收 TEST-SNIFF-002。
 * 实现路径：处理 record/handshake 分片与长度边界；不能解密 ECH；无明文 SNI 返回无结果，不创建 TLS 握手库。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；将来异步接纳前复制并保留所有依赖，owner loop 一次终结。
 * 当前为骨架：不接纳请求、不转移输入所有权、不调用回调；失败输出清空。
 */
ftun_status_t ftun_sniff_tls_sni(ftun_bytes_t preread, ftun_sniff_result_t *out);
#endif
