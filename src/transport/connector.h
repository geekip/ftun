#ifndef FTUN_TRANSPORT_CONNECTOR_H
#define FTUN_TRANSPORT_CONNECTOR_H
#include "transport/path.h"

/* Connector：出站“怎么连上对端”的扩展点。每种出站协议（direct、socks5，以后的
 * tls、anytls、mesh 承载……）是登记表里的一项：名字、能力位和 open。
 * 登记表由组合层静态建立，取代只服务于测试的写死字段的函数表；加一种协议时
 * 登记一项，不改结构体。
 *
 * open 的 request 是该 Connector 约定的具体请求类型（direct 为
 * ftun_direct_request_t，socks5 为 ftun_socks5_connect_request_t）；调用方按名字
 * 查到项就知道类型。完成方式沿用各自的契约：返回 Operation，接纳后由 Event/Operation
 * 恰好一次终结，同步拒绝清空 out 且零回调。 */
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
  ftun_status_t (*open)(void *context, ftun_core_t *core, const void *request,
                        ftun_operation_t **out);
  void *context;
} ftun_connector_ops_t;

typedef struct {
  ftun_connector_ops_t entries[FTUN_CONNECTOR_MAX];
  size_t count;
} ftun_connector_registry_t;

/* 名字不能为空或重复，open 不能为空，能力位至少含 TCP 或 UDP；满了返回 LIMIT。 */
ftun_status_t ftun_connector_register(ftun_connector_registry_t *registry,
                                      const ftun_connector_ops_t *ops);
/* 没有该名字返回 NULL。返回的项借用登记表。 */
const ftun_connector_ops_t *ftun_connector_lookup(
  const ftun_connector_registry_t *registry, const char *kind);
#endif
