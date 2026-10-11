#ifndef FTUN_INTERNAL_CONTRACTS_H
#define FTUN_INTERNAL_CONTRACTS_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "ftun/ftun.h"
/* 内部设计值类型，均不是磁盘/网络布局或稳定 ABI。所有借用视图带长度。
 * DEC-025：可选实现仅按构建选择静态内置；这些类型不作为动态插件 ABI。
 * 基础参数同步借用；将来异步接纳时复制输入并 retain 依赖。
 * 完成回调统一由 owner loop 延迟投递一次，取消不提前释放 user。
 * 未交付的骨架入口返回 NOT_IMPLEMENTED/UNSUPPORTED；已交付入口以各模块头文件
 * 的所有权、失败输出和回调契约为准。 */
typedef struct ftun_api_spec ftun_api_spec_t;
typedef struct ftun_budget ftun_budget_t;
typedef struct ftun_buffer ftun_buffer_t;
typedef struct ftun_buffer_pool ftun_buffer_pool_t;
typedef struct ftun_config ftun_config_t;
typedef struct ftun_datagram ftun_datagram_t;
typedef struct ftun_dial_request ftun_dial_request_t;
typedef struct ftun_direct_request ftun_direct_request_t;
typedef struct ftun_dns_answer ftun_dns_answer_t;
typedef struct ftun_dns_cache ftun_dns_cache_t;
typedef struct ftun_dns_connection ftun_dns_connection_t;
typedef struct ftun_dns_dispatcher ftun_dns_dispatcher_t;
typedef struct ftun_dns_listener_spec ftun_dns_listener_spec_t;
typedef struct ftun_dns_listener ftun_dns_listener_t;
typedef struct ftun_dns_message ftun_dns_message_t;
typedef struct ftun_dns_query ftun_dns_query_t;
typedef struct ftun_dns_server ftun_dns_server_t;
typedef struct ftun_event_loop ftun_event_loop_t;
typedef struct ftun_event_source ftun_event_source_t;
typedef struct ftun_fakeip_handle ftun_fakeip_handle_t;
typedef struct ftun_fakeip_service ftun_fakeip_service_t;
typedef struct ftun_fakeip_snapshot ftun_fakeip_snapshot_t;
typedef struct ftun_fakeip_store ftun_fakeip_store_t;
typedef struct ftun_feature_plan ftun_feature_plan_t;
typedef struct ftun_frs_set ftun_frs_set_t;
typedef struct ftun_frs_update_request ftun_frs_update_request_t;
typedef struct ftun_frs_view ftun_frs_view_t;
typedef struct ftun_group_spec ftun_group_spec_t;
typedef struct ftun_health_snapshot ftun_health_snapshot_t;
typedef struct ftun_inbound_spec ftun_inbound_spec_t;
typedef struct ftun_inbound ftun_inbound_t;
typedef struct ftun_index ftun_index_t;
typedef struct ftun_lwip ftun_lwip_t;
typedef struct ftun_operation_queue ftun_operation_queue_t;
typedef struct ftun_packet_port ftun_packet_port_t;
typedef struct ftun_packet ftun_packet_t;
typedef struct ftun_probe_request ftun_probe_request_t;
typedef struct ftun_proxy_spec ftun_proxy_spec_t;
typedef struct ftun_reservation ftun_reservation_t;
typedef struct ftun_resolve_request ftun_resolve_request_t;
typedef struct ftun_relay ftun_relay_t;
typedef struct ftun_route_policy ftun_route_policy_t;
typedef struct ftun_route_table ftun_route_table_t;
typedef struct ftun_route_transaction ftun_route_transaction_t;
typedef struct ftun_rule ftun_rule_t;
typedef struct ftun_runtime ftun_runtime_t;
typedef struct ftun_session ftun_session_t;
typedef struct ftun_socket_policy ftun_socket_policy_t;
typedef struct ftun_stream ftun_stream_t;
typedef struct ftun_tls_context ftun_tls_context_t;
typedef struct ftun_tls_options ftun_tls_options_t;
typedef struct ftun_tun_spec ftun_tun_spec_t;
typedef struct ftun_worker_job ftun_worker_job_t;
typedef struct ftun_worker ftun_worker_t;
typedef uintptr_t ftun_native_socket_t; /* 仅内部平台包装，不假定为 POSIX fd。 */
typedef struct { const char *data; size_t length; } ftun_string_t;
typedef struct { const uint8_t *data; size_t length; } ftun_bytes_t;
typedef enum { FTUN_ADDRESS_NONE=0, FTUN_ADDRESS_IPV4, FTUN_ADDRESS_DOMAIN,
               FTUN_ADDRESS_IPV6_RESERVED } ftun_address_kind_t;
typedef struct {
  ftun_address_kind_t kind;
  uint8_t address[16]; /* 网络字节序；IPv6 仅类型预留。 */
  ftun_string_t domain;
  uint16_t port; /* 主机字节序；序列化必须逐字段转换。 */
} ftun_endpoint_t;
typedef enum { FTUN_DOMAIN_NONE=0, FTUN_DOMAIN_EXPLICIT, FTUN_DOMAIN_FAKEIP,
               FTUN_DOMAIN_SNIFF } ftun_domain_source_t;
#define FTUN_META_SOURCE 1u
#define FTUN_META_PORT 2u
#define FTUN_META_NETWORK 4u
#define FTUN_META_DOMAIN 8u
typedef struct {
  uint64_t generation;
  uint32_t known_fields;
  uint32_t inbound_id;
  uint8_t network; /* 0 unknown, 1 TCP, 2 UDP；DNS 阶段不可伪造业务 network。 */
  ftun_endpoint_t source, original_target;
  ftun_string_t domain;
  ftun_domain_source_t domain_source;
  bool original_is_fake;
  const ftun_endpoint_t *resolved;
  size_t resolved_count;
} ftun_metadata_t;
typedef enum { FTUN_ROUTE_UNSET=0, FTUN_ROUTE_READY, FTUN_ROUTE_NEED_RESOLVE,
               FTUN_ROUTE_DENY } ftun_route_kind_t;
/* 与 Session 的首版解析上限一致，避免 Router 产生下游无法保存的集合。 */
#define FTUN_ROUTE_MAX_CANDIDATES 16u
typedef struct {
  ftun_route_kind_t kind;
  uint64_t generation;
  size_t rule_index, resume_rule;
  uint32_t outbound_id;
  const ftun_endpoint_t *allowed;
  size_t allowed_count;
  /* IP/FRS-IP 规则可能从非连续候选中选择子集。指针指向这里时，result
   * 不得按值复制后继续使用旧 allowed 指针。 */
  ftun_endpoint_t allowed_storage[FTUN_ROUTE_MAX_CANDIDATES];
} ftun_route_result_t;
typedef struct { bool matched, needs_resolve; } ftun_match_result_t;
typedef struct {
  uint64_t generation;
  ftun_endpoint_t original;
  ftun_string_t identity;
  ftun_domain_source_t identity_source;
  const ftun_endpoint_t *candidates;
  size_t candidate_count;
  const ftun_endpoint_t *allowed;
  size_t allowed_count;
  ftun_endpoint_t dial;
  bool original_is_fake;
  bool dial_selected;
} ftun_target_t;
typedef struct {
  uint64_t generation;
  uint32_t leaf_id; /* 0 是合法的内置 DIRECT，generation 表示有效性。 */
  bool degraded;
  ftun_string_t dns_server; /* 借用不可变 Runtime，外层显式值优先。 */
} ftun_group_choice_t;
/* message 与 path 均为静态借用视图；path 使用 JSON Pointer。 */
typedef struct {
  ftun_error_t error;
  ftun_string_t message;
  ftun_string_t path;
} ftun_diagnostic_t;
typedef enum {
  FTUN_BUILD_MODULE_CORE = 1u << 0,
  FTUN_BUILD_MODULE_DNS = 1u << 1,
  FTUN_BUILD_MODULE_TUN = 1u << 2,
  FTUN_BUILD_MODULE_FRS = 1u << 3
} ftun_build_module_t;
#define FTUN_BUILD_MODULE_ALL \
  (FTUN_BUILD_MODULE_CORE | FTUN_BUILD_MODULE_DNS | FTUN_BUILD_MODULE_TUN | \
   FTUN_BUILD_MODULE_FRS)
typedef struct {
  uint32_t builtins;
  const char *const *names;
  size_t name_count;
} ftun_build_capabilities_t;
typedef struct { ftun_buffer_t *owner; size_t offset, length; } ftun_buffer_slice_t;
typedef struct { bool complete; size_t consumed; ftun_endpoint_t target; } ftun_protocol_result_t;
typedef struct { bool found, need_more; ftun_string_t domain; } ftun_sniff_result_t;
#endif
