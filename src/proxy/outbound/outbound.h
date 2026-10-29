#ifndef FTUN_PROXY_OUTBOUND_OUTBOUND_H
#define FTUN_PROXY_OUTBOUND_OUTBOUND_H

#include "libs/transport/connector.h"
#include "proxy/outbound/direct.h"
#include "proxy/outbound/reject.h"
#include "proxy/outbound/socks5.h"

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

/* 出站分派。
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

/* 默认登记表：direct 与 socks5 两个真实 Connector。 */
const ftun_connector_registry_t *ftun_outbound_default_registry(void);

/* 用指定登记表分派（测试与受控宿主注入）；分派器不获取登记项 context 的所有权。
 * 叶子的类型决定查哪一项，登记项的能力位必须覆盖本次传输（TCP/UDP），否则
 * UNSUPPORTED。REJECT 不是 Connector：它只做分类，同步返回。 */
ftun_status_t ftun_outbound_open_with_registry(
  ftun_core_t *core, const ftun_outbound_request_t *request,
  const ftun_connector_registry_t *registry,
  ftun_reject_result_t *reject_result, ftun_operation_t **out);

#endif
