#ifndef FTUN_CONFIG_MODEL_H
#define FTUN_CONFIG_MODEL_H

#include "internal/contracts.h"

#define FTUN_CONFIG_CAPACITY_DEFAULT UINT32_C(256)
#define FTUN_CONFIG_CAPACITY_MINIMUM UINT32_C(1)
#define FTUN_CONFIG_CAPACITY_MAXIMUM UINT32_C(10000)

typedef struct {
  char **items;
  size_t count;
} ftun_config_string_list_t;

typedef struct {
  char *name;
  char *password;
} ftun_config_user_t;

typedef struct {
  char *listen;
  char *server;
} ftun_config_dns_listener_t;

typedef struct {
  char *name;
  char *type;
  ftun_config_string_list_t addresses;
  char *outbound;
  bool fake_ip;
} ftun_config_dns_server_t;

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

struct ftun_config {
  size_t reference_count;
  /* 分配时记录实际请求容量，不以规范化后的字符串长度反推。 */
  size_t owned_bytes;
  ftun_budget_t *budget;
  ftun_reservation_t *reservation;
  char *source_path;
  char *base_directory;
  ftun_feature_plan_t *plan;
  struct {
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
    /* owner 心跳看门狗：超过这个时长没有响应就停止进程；0 关闭判定。 */
    uint32_t watchdog_ms;
    /* 同时保留的旧代次数量；满了以后拒绝 reload。只在启动时读取。 */
    uint32_t reload_retain_count;
  } base;
  struct {
    char *level;
    char *file;
    /* 单个日志文件的大小上限（字节，0 不轮转）与保留的文件总数（含当前文件）。 */
    uint32_t max_size;
    uint32_t max_files;
  } log;
  struct {
    bool enable;
    bool cache;
    ftun_config_string_list_t bootstrap;
    char *default_server;
    struct {
      bool enable;
      char *range;
      bool persist;
    } fake_ip;
    ftun_config_dns_listener_t *listeners;
    size_t listener_count;
    ftun_config_dns_server_t *servers;
    size_t server_count;
  } dns;
  struct {
    bool active;
    bool present;
    bool auto_update;
    char *path;
    char *url;
    char *update_interval;
    char *update_outbound;
    char *dns_server;
  } frs;
  struct {
    bool enable;
    bool tls_sni;
    bool http_host;
  } sniff;
  struct {
    bool present;
    char *interface_name;
    uint32_t mtu;
    char *ipv4_address;
    bool auto_route;
    bool strict_route;
    /* 策略路由表号与规则优先级：同机多实例时必须各不相同。 */
    uint32_t route_table;
    uint32_t rule_priority;
  } tun;
  ftun_config_inbound_t *inbounds;
  size_t inbound_count;
  ftun_config_outbound_t *outbounds;
  size_t outbound_count;
  ftun_config_string_list_t rules;
};

/* 仅供配置构造：新增存储先准入；free_bytes的大小必须是原请求容量。
 * budget借用至最后配置引用销毁，NULL用于独立的未绑定解析调用。 */
ftun_status_t ftun_config_create_owned(ftun_budget_t *budget, ftun_config_t **out);
/* 超时与存活的默认值（候选值）；空闲回收默认关闭。解析器和手工构造配置的
 * 测试共用这一份。 */
#define FTUN_CONFIG_LOG_MAX_SIZE_DEFAULT UINT32_C(10485760)
#define FTUN_CONFIG_LOG_MAX_SIZE_MINIMUM UINT32_C(65536)
#define FTUN_CONFIG_LOG_MAX_FILES_DEFAULT UINT32_C(3)
#define FTUN_CONFIG_LOG_MAX_FILES_MAXIMUM UINT32_C(32)
#define FTUN_CONFIG_RELOAD_RETAIN_DEFAULT UINT32_C(4)
#define FTUN_CONFIG_RELOAD_RETAIN_MAXIMUM UINT32_C(64)
#define FTUN_CONFIG_WATCHDOG_DEFAULT_MS UINT32_C(30000)
#define FTUN_CONFIG_WATCHDOG_MINIMUM_MS UINT32_C(1000)
#define FTUN_CONFIG_WATCHDOG_MAXIMUM_MS UINT32_C(600000)
#define FTUN_CONFIG_ROUTING_MARK_DEFAULT UINT32_C(0x4654)
#define FTUN_CONFIG_ROUTE_TABLE_DEFAULT UINT32_C(18004)
#define FTUN_CONFIG_RULE_PRIORITY_DEFAULT UINT32_C(11000)
/* 系统保留表号：unspec/default/main/local 和内核规则优先级上限之外的值。 */
#define FTUN_CONFIG_ROUTE_TABLE_MAXIMUM UINT32_C(0xfffffff0)
#define FTUN_CONFIG_RULE_PRIORITY_MAXIMUM UINT32_C(32000)

void ftun_config_timeouts_default(ftun_config_t *config);
void *ftun_config_allocate(ftun_config_t *config, size_t count, size_t size);
void ftun_config_free_bytes(ftun_config_t *config, void *value, size_t bytes);

#endif
