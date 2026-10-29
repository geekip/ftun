#ifndef FTUN_PROXY_CONFIG_MODEL_H
#define FTUN_PROXY_CONFIG_MODEL_H
#include "proxy/config/transport.h"
enum {
  FTUN_CONFIG_SECTION_FRS = 9u,
  FTUN_CONFIG_SECTION_SNIFF = 10u,
  FTUN_CONFIG_SECTION_RULES = 11u
};

typedef struct {
  bool active;
  bool present;
  bool auto_update;
  char *path;
  char *url;
  char *update_interval;
  char *update_outbound;
  char *dns_server;
} ftun_config_frs_t;
typedef struct {
  bool enable;
  bool tls_sni;
  bool http_host;
} ftun_config_sniff_t;
static inline const ftun_config_frs_t *ftun_config_frs(const ftun_config_t *config)
{
  return ftun_config_document_section(config, FTUN_CONFIG_SECTION_FRS);
}
static inline const ftun_config_sniff_t *ftun_config_sniff(const ftun_config_t *config)
{
  return ftun_config_document_section(config, FTUN_CONFIG_SECTION_SNIFF);
}
static inline const ftun_config_string_list_t *ftun_config_rules(const ftun_config_t *config)
{
  return ftun_config_document_section(config, FTUN_CONFIG_SECTION_RULES);
}

#endif
