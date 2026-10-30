#ifndef FTUN_PROXY_OUTBOUND_CONNECTOR_H
#define FTUN_PROXY_OUTBOUND_CONNECTOR_H
#include "libs/transport/path.h"

/* 出站登记表属于 Proxy；每个实现接收同一个类型化出站请求。
 * 请求在 open 返回前借用；异步拥有权由具体连接器复制与保留。 */
typedef struct ftun_outbound_request ftun_outbound_request_t;
#define FTUN_CONNECTOR_MAX 8u
#define FTUN_CONNECTOR_TCP 0x01u
#define FTUN_CONNECTOR_UDP 0x02u
/* 可以把域名当作目标交给对端解析（没有本地真实候选时）。 */
#define FTUN_CONNECTOR_DOMAIN_TARGET 0x04u
/* 协议自身带心跳（例如 Mesh 承载）。 */
#define FTUN_CONNECTOR_KEEPALIVE 0x08u

typedef struct {
  const char *kind;
  uint32_t capabilities;
  ftun_status_t (*open)(void *context, ftun_core_t *core, const ftun_outbound_request_t *request,
                        ftun_operation_t **out);
  void *context;
} ftun_connector_ops_t;

typedef struct {
  ftun_connector_ops_t entries[FTUN_CONNECTOR_MAX];
  size_t count;
} ftun_connector_registry_t;

/* 名字不能为空或重复，open 不能为空，能力位至少含 TCP 或 UDP；满了返回 LIMIT。 */
/* 没有该名字返回 NULL。返回的项借用登记表。 */
const ftun_connector_ops_t *ftun_connector_lookup(
  const ftun_connector_registry_t *registry, const char *kind);
#endif
