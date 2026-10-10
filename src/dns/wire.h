#ifndef FTUN_DNS_WIRE_H
#define FTUN_DNS_WIRE_H

#include "internal/contracts.h"

#define FTUN_DNS_HEADER_BYTES 12u
#define FTUN_DNS_MAX_MESSAGE_BYTES 65535u
#define FTUN_DNS_MAX_NAME_BYTES 255u
#define FTUN_DNS_MAX_RECORDS 256u
#define FTUN_DNS_TYPE_OPT 41u
#define FTUN_DNS_EDNS_FLAG_DO 0x8000u

typedef struct {
  const uint8_t *data; /* 未压缩 wire name，包含末尾 root octet。 */
  size_t length;
} ftun_dns_name_t;

typedef struct {
  ftun_dns_name_t name;
  uint16_t type;
  uint16_t class_code;
} ftun_dns_question_t;

typedef enum {
  FTUN_DNS_SECTION_ANSWER = 1,
  FTUN_DNS_SECTION_AUTHORITY,
  FTUN_DNS_SECTION_ADDITIONAL
} ftun_dns_section_t;

typedef enum {
  FTUN_DNS_RECORD_ORDINARY = 1,
  FTUN_DNS_RECORD_OPT
} ftun_dns_record_kind_t;

typedef struct {
  ftun_dns_record_kind_t kind;
  ftun_dns_section_t section;
  ftun_dns_name_t name;
  uint16_t type;
  uint16_t class_code; /* OPT 时为 0，实际 UDP size 见 udp_payload_size。 */
  uint32_t ttl;        /* OPT 时为 0，实际位域见下列 EDNS 字段。 */
  ftun_bytes_t rdata;
  uint16_t udp_payload_size;
  uint8_t extended_rcode;
  uint8_t edns_version;
  uint16_t edns_flags;
} ftun_dns_record_t;

typedef enum {
  FTUN_DNS_TRANSPORT_UDP = 1,
  FTUN_DNS_TRANSPORT_TCP
} ftun_dns_transport_t;

struct ftun_dns_query {
  uint16_t id;
  ftun_dns_transport_t transport;
  ftun_endpoint_t upstream;
  ftun_dns_question_t question;
};

struct ftun_dns_message {
  uint16_t id;
  uint16_t flags;
  uint16_t rcode; /* 含 EDNS 扩展 RCODE 高 8 位。 */
  ftun_dns_question_t question;
  const ftun_dns_record_t *records;
  size_t record_count;
  size_t answer_count;
  size_t authority_count;
  size_t additional_count;
  const uint8_t *wire;
  size_t wire_length;
};

/* DNS 有界报文解析。
 * 需求 REQ-DNSWIRE-001；任务 TASK-DNS-008；目标 0.2.0；验收 TEST-DNS-008。
 * 只接纳一个 Question；名称展开后最多 255 octet，压缩指针必须向后且
 * 不得成环。成功 message 拥有 wire、名称和 RR 数组；未知普通 RR 的
 * RDATA 原样保留。OPT 只允许唯一 additional root 记录，TTL 位域单独解析。
 * 失败清空 out。纯函数层无异步回调或取消，release 为幂等消费。
 */
ftun_status_t ftun_dns_message_parse(ftun_bytes_t wire,
                                     ftun_dns_message_t **out);
ftun_status_t ftun_dns_message_release(ftun_dns_message_t **message);

/* 只在 ID、完整 Question、transport 和实际上游端点均一致时匹配；
 * 名称按 DNS ASCII 大小写不敏感比较。普通不匹配返回 OK/false。 */
ftun_status_t ftun_dns_message_matches(
  const ftun_dns_message_t *message, const ftun_dns_query_t *query,
  ftun_dns_transport_t transport, const ftun_endpoint_t *source,
  bool *out_matches);

#endif
