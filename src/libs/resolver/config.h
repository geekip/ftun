#ifndef FTUN_LIBS_RESOLVER_CONFIG_H
#define FTUN_LIBS_RESOLVER_CONFIG_H
#include "core/config/document.h"
#define FTUN_CONFIG_SECTION_RESOLVER 15u
typedef struct {
  char *name;
  char *type;
  ftun_config_string_list_t addresses;
  char *outbound;
  bool fake_ip;
} ftun_config_dns_server_t;

typedef struct {
  bool enable;
  char *range;
  bool persist;
} ftun_config_fakeip_t;
typedef struct {
  bool enable;
  ftun_config_string_list_t bootstrap;
  const char *default_server;
  ftun_config_fakeip_t fake_ip;
  bool ipv6;
  const ftun_config_dns_server_t *servers;
  size_t server_count;
} ftun_config_resolver_t;
/* 同步只读投影；列表和字符串借用文档，不拥有业务运行时。 */
typedef struct {
  ftun_config_resolver_t (*get)(const ftun_config_t *config);
} ftun_config_resolver_ops_t;
static inline ftun_config_resolver_t ftun_config_resolver(const ftun_config_t *config)
{
  const ftun_config_resolver_ops_t *ops = ftun_config_document_section(config, FTUN_CONFIG_SECTION_RESOLVER);
  return ops->get(config);
}
#endif
