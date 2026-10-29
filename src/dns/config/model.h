#ifndef FTUN_DNS_CONFIG_MODEL_H
#define FTUN_DNS_CONFIG_MODEL_H
#include "libs/resolver/config.h"
#include "platform/protect.h"
#define FTUN_CONFIG_SECTION_DNS 8u
#define FTUN_CONFIG_SECTION_DNS_BINDING 16u
typedef struct {
  char *listen;
  char *server;
} ftun_config_dns_listener_t;
typedef struct {
  bool enable;
  bool cache;
  ftun_config_string_list_t bootstrap;
  char *default_server;
  ftun_config_fakeip_t fake_ip;
  ftun_config_dns_listener_t *listeners;
  size_t listener_count;
  ftun_config_dns_server_t *servers;
  size_t server_count;
} ftun_config_dns_t;
static inline const ftun_config_dns_t *ftun_config_dns(const ftun_config_t *config)
{
  return ftun_config_document_section(config, FTUN_CONFIG_SECTION_DNS);
}
/* app 根据入站与公共设置装配，不让 DNS 读取其他业务的私有模型。 */
typedef struct {
  ftun_socket_liveness_t liveness;
  uint32_t hijack_id;
} ftun_dns_config_binding_t;
typedef struct {
  ftun_dns_config_binding_t (*get)(const ftun_config_t *config);
} ftun_dns_config_binding_ops_t;
static inline ftun_dns_config_binding_t ftun_dns_config_binding(const ftun_config_t *config)
{
  const ftun_dns_config_binding_ops_t *ops = ftun_config_document_section(config, FTUN_CONFIG_SECTION_DNS_BINDING);
  return ops->get(config);
}
#endif
