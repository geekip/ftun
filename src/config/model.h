#ifndef FTUN_CONFIG_MODEL_H
#define FTUN_CONFIG_MODEL_H

#include "internal/contracts.h"

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

typedef struct {
  bool present;
  char *path;
  char *url;
} ftun_config_geo_data_t;

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
  char *source_path;
  char *base_directory;
  ftun_feature_plan_t *plan;
  struct {
    bool ipv6;
    bool allow_lan;
    char *cache_file;
    bool state_cache;
  } base;
  struct {
    char *level;
    char *file;
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
    bool present;
    bool auto_update;
    char *update_interval;
    char *update_outbound;
    char *dns_server;
    ftun_config_geo_data_t geoip;
    ftun_config_geo_data_t geosite;
  } geo;
  struct {
    bool enable;
    bool tls_sni;
    bool http_host;
  } sniff;
  ftun_config_inbound_t *inbounds;
  size_t inbound_count;
  ftun_config_outbound_t *outbounds;
  size_t outbound_count;
  ftun_config_string_list_t rules;
};

#endif
