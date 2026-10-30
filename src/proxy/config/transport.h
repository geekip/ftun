#ifndef FTUN_PROXY_CONFIG_TRANSPORT_H
#define FTUN_PROXY_CONFIG_TRANSPORT_H
#include "core/config/document.h"
#include "platform/protect.h"
enum {
  FTUN_CONFIG_SECTION_BASE = 1u,
  FTUN_CONFIG_SECTION_INBOUNDS = 2u,
  FTUN_CONFIG_SECTION_INBOUND_COUNT = 3u,
  FTUN_CONFIG_SECTION_OUTBOUNDS = 4u,
  FTUN_CONFIG_SECTION_OUTBOUND_COUNT = 5u
};

typedef struct {
  char *name;
  char *password;
} ftun_config_user_t;

typedef enum {
  FTUN_CONFIG_INBOUND_MIXED = 1,
  FTUN_CONFIG_INBOUND_SOCKS5,
  FTUN_CONFIG_INBOUND_TUN
} ftun_config_inbound_kind_t;

typedef struct {
  ftun_config_inbound_kind_t kind;
  char *name;
  char *outbound;
  char *listen;
  ftun_config_user_t *users;
  size_t user_count;
  bool udp;
  char *interface_name;
  uint32_t mtu;
  char *stack;
  char *ipv4_address;
  char *ipv6_address;
  bool tcp;
  bool auto_route;
  bool strict_route;
  bool dns_hijack;
  /* 0 表示继承 base.timeouts.tcp_idle_ms。 */
  uint32_t tcp_idle_ms;
} ftun_config_inbound_t;

typedef enum {
  FTUN_CONFIG_OUTBOUND_SOCKS5 = 1,
  FTUN_CONFIG_OUTBOUND_SELECT,
  FTUN_CONFIG_OUTBOUND_URL_TEST
} ftun_config_outbound_kind_t;

typedef struct {
  ftun_config_outbound_kind_t kind;
  char *name;
  char *dns_server;
  char *server;
  char *username;
  char *password;
  bool udp;
  ftun_config_string_list_t members;
  char *default_member;
  char *url;
  char *interval;
  char *timeout;
  uint32_t tolerance_ms;
  bool lazy;
  uint16_t expected_status;
} ftun_config_outbound_t;

typedef struct {
  bool ipv6;
  bool allow_lan;
  char *cache_file;
  bool state_cache;
  struct {
    uint32_t tcp_flows;
    uint32_t udp_flows;
    uint32_t udp_associations;
  } capacity;
  /* 超时与存活：全部以毫秒（keepalive 以秒）保存，0 的含义见各字段。 */
  struct {
    uint32_t handshake_ms;
    uint32_t connect_ms;
    uint32_t reply_ms;
    /* 已发送的数据有积压，且对端在这个期限内没有确认任何新字节，则判为失联。
     * Proxy 转发连接由应用层按确认进展扫描（慢速但仍在读的对端不受影响）；
     * 其他业务的短连接仍以 TCP_USER_TIMEOUT 设置。 */
    uint32_t write_progress_ms;
    /* 0 表示关闭空闲回收（默认）。 */
    uint32_t tcp_idle_ms;
    uint32_t udp_idle_ms;
    struct {
      bool enabled;
      uint32_t idle_s;
      uint32_t interval_s;
      uint32_t count;
    } keepalive;
  } timeouts;
  /* 出站 socket 的 fwmark，同时是 TUN 路由保护规则的匹配值。 */
  uint32_t routing_mark;
} ftun_config_proxy_base_t;

static inline const ftun_config_proxy_base_t *ftun_config_base(const ftun_config_t *config)
{
  return ftun_config_document_section(config, FTUN_CONFIG_SECTION_BASE);
}
static inline const ftun_config_inbound_t *ftun_config_inbounds(const ftun_config_t *config)
{
  return ftun_config_document_section(config, FTUN_CONFIG_SECTION_INBOUNDS);
}
static inline size_t ftun_config_inbound_count(const ftun_config_t *config)
{
  return *(const size_t *)ftun_config_document_section(config, FTUN_CONFIG_SECTION_INBOUND_COUNT);
}
static inline const ftun_config_outbound_t *ftun_config_outbounds(const ftun_config_t *config)
{
  return ftun_config_document_section(config, FTUN_CONFIG_SECTION_OUTBOUNDS);
}
static inline size_t ftun_config_outbound_count(const ftun_config_t *config)
{
  return *(const size_t *)ftun_config_document_section(config, FTUN_CONFIG_SECTION_OUTBOUND_COUNT);
}
#define FTUN_CONFIG_CAPACITY_DEFAULT UINT32_C(256)
#define FTUN_CONFIG_CAPACITY_MINIMUM UINT32_C(1)
#define FTUN_CONFIG_CAPACITY_MAXIMUM UINT32_C(10000)

/* 把 base.timeouts 转成套接字存活策略；各业务据此给自己创建/接纳的 TCP socket 设置。 */
static inline ftun_socket_liveness_t ftun_config_socket_liveness(
  const ftun_config_t *config)
{
  ftun_socket_liveness_t liveness = {0};
  if (config == NULL) return liveness;
  liveness.keepalive_enabled = ftun_config_base(config)->timeouts.keepalive.enabled;
  liveness.idle_s = ftun_config_base(config)->timeouts.keepalive.idle_s;
  liveness.interval_s = ftun_config_base(config)->timeouts.keepalive.interval_s;
  liveness.count = ftun_config_base(config)->timeouts.keepalive.count;
  liveness.user_timeout_ms = ftun_config_base(config)->timeouts.write_progress_ms;
  return liveness;
}

#endif
