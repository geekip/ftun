#ifndef FTUN_LIBS_RESOLVER_DNSWIRE_H
#define FTUN_LIBS_RESOLVER_DNSWIRE_H
#include "util/dnswire.h"
/* DNS 有界报文解析。
 * 只接纳一个 Question；名称展开后最多 255 octet，压缩指针必须向后且
 * 不得成环。成功 message 拥有 wire、名称和 RR 数组；未知普通 RR 的
 * RDATA 原样保留。OPT 只允许唯一 additional root 记录，TTL 位域单独解析。
 * 失败清空 out。纯函数层无异步回调或取消，release 为幂等消费。
 */
ftun_status_t ftun_dns_message_parse(ftun_bytes_t wire,
                                     ftun_dns_message_t **out);
/* 生产解析按实际拥有字节准入，release 同时归还额度。 */
ftun_status_t ftun_dns_message_parse_with_budget(ftun_budget_t *budget,
  ftun_bytes_t wire, ftun_dns_message_t **out);
ftun_status_t ftun_dns_message_release(ftun_dns_message_t **message);

#endif
