#ifndef FTUN_OUTBOUND_OUTBOUND_H
#define FTUN_OUTBOUND_OUTBOUND_H

#include "outbound/direct.h"
#include "outbound/reject.h"
#include "outbound/socks5.h"

typedef enum {
  FTUN_OUTBOUND_LEAF_DIRECT = 1,
  FTUN_OUTBOUND_LEAF_REJECT,
  FTUN_OUTBOUND_LEAF_SOCKS5,
  FTUN_OUTBOUND_LEAF_GROUP
} ftun_outbound_leaf_kind_t;

typedef struct {
  uint64_t generation;
  uint32_t id;
  ftun_outbound_leaf_kind_t kind;
  bool supports_tcp;
  bool supports_udp;
} ftun_outbound_leaf_t;

typedef struct {
  const ftun_route_result_t *route;
  const ftun_target_t *target;
  const ftun_outbound_leaf_t *leaf;
  ftun_dial_transport_t transport;
  const ftun_direct_request_t *direct;
  const ftun_socks5_connect_request_t *socks5;
  const ftun_metadata_t *metadata;
} ftun_outbound_request_t;

typedef struct {
  ftun_status_t (*direct_open)(void *context, ftun_core_t *core,
                               const ftun_direct_request_t *request,
                               ftun_operation_t **out);
  ftun_status_t (*socks5_open)(void *context, ftun_core_t *core,
                               const ftun_socks5_connect_request_t *request,
                               ftun_operation_t **out);
  ftun_status_t (*reject_classify)(void *context,
                                   const ftun_metadata_t *metadata,
                                   bool dns_query,
                                   ftun_reject_result_t *out);
  void *context;
} ftun_outbound_backend_t;

/* 出站分派。
 * 需求 REQ-OUT-001；任务 TASK-OUTBOUND-001；目标 0.2.0；验收 TEST-OUTBOUND-001。
 * route、target 和 leaf 必须同代且精确对应；route.allowed 必须与
 * target.allowed 完全一致。本层只分派已固定叶子，不展开组、不
 * 重新路由，也不在选中出站失败后改走 DIRECT。
 * direct/socks5 的异步所有权与取消契约原样转交子模块；REJECT
 * 同步返回 REJECTED、out=NULL 并填充 reject_result。
 */
ftun_status_t ftun_outbound_open(ftun_core_t *core,
                                  const ftun_outbound_request_t *request,
                                  ftun_reject_result_t *reject_result,
                                  ftun_operation_t **out);

/* 测试与受控宿主注入；分派器不获取 backend context 所有权。 */
ftun_status_t ftun_outbound_open_with_backend(
  ftun_core_t *core, const ftun_outbound_request_t *request,
  const ftun_outbound_backend_t *backend,
  ftun_reject_result_t *reject_result, ftun_operation_t **out);

#endif
