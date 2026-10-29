#include "core/config/fields.h"
#include "core/limits.h"
#include "dns/config/parse.h"
#include "dns/config/validate.h"
#include "proxy/config/validate.h"
#include "libs/tun/config/validate.h"
#include "libs/tun/config/parse.h"
#include "proxy/config/parse.h"
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "config sections failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

/* 独立宿主布局，配置段实现不能读取 app 聚合模型。 */
struct ftun_config {
  ftun_config_document_t document;
  ftun_config_dns_t dns;
  ftun_config_frs_t frs;
  ftun_config_sniff_t sniff;
  ftun_config_tun_t tun;
  ftun_config_inbound_t *inbounds;
  size_t inbound_count;
  ftun_config_outbound_t *outbounds;
  size_t outbound_count;
};
static ftun_status_t prepare(ftun_config_t *config)
{
  (void)config;
  return FTUN_OK;
}
static void destroy(ftun_config_t *config)
{
  ftun_config_clear_dns(&config->dns);
  ftun_config_clear_frs(&config->frs);
  ftun_config_clear_tun(&config->tun);
  ftun_config_clear_inbounds(config->inbounds, config->inbound_count);
  ftun_config_clear_outbounds(config->outbounds, config->outbound_count);
}
static const void *section(const ftun_config_t *config, uint32_t section_id)
{
  (void)config;
  (void)section_id;
  return NULL;
}
static ftun_status_t parse(ftun_config_t *config, const cJSON *root)
{
  const cJSON *item;
  ftun_config_defaults_tun(&config->tun);
  ftun_status_t status = ftun_config_defaults_dns(config, &config->dns);
  if (status == FTUN_OK) status = ftun_config_defaults_frs(config, &config->frs);
  item = cJSON_GetObjectItemCaseSensitive(root, "dns");
  if (status == FTUN_OK && item != NULL) status = ftun_config_parse_dns(item, config, &config->dns);
  item = cJSON_GetObjectItemCaseSensitive(root, "frs");
  if (status == FTUN_OK && item != NULL) status = ftun_config_parse_frs(item, config, &config->frs);
  item = cJSON_GetObjectItemCaseSensitive(root, "sniff");
  if (status == FTUN_OK && item != NULL) status = ftun_config_parse_sniff(item, &config->sniff);
  item = cJSON_GetObjectItemCaseSensitive(root, "inbounds");
  if (status == FTUN_OK && item != NULL) status = ftun_config_parse_inbounds(item, config,
    &config->inbounds, &config->inbound_count);
  item = cJSON_GetObjectItemCaseSensitive(root, "outbounds");
  if (status == FTUN_OK && item != NULL) status = ftun_config_parse_outbounds(item, config,
    &config->outbounds, &config->outbound_count);
  item = cJSON_GetObjectItemCaseSensitive(root, "tun");
  if (status == FTUN_OK && item != NULL) status = ftun_config_parse_tun_device(item, config, &config->tun);
  return status;
}
int main(void)
{
  static const ftun_config_document_ops_t ops = {prepare, destroy, section};
  static const struct {
    const char *json;
    ftun_status_t expected;
  } cases[] = {
    {"{}", FTUN_OK},
    {"{\"dns\":{\"servers\":[{\"name\":\"up\",\"type\":\"udp\",\"address\":[\"1.1.1.1:53\"]}],"
     "\"listeners\":[{\"listen\":\"127.0.0.1:5353\"}]},"
     "\"inbounds\":[{\"name\":\"in\",\"type\":\"mixed\",\"listen\":\"127.0.0.1:1080\",\"tcp-idle\":\"30s\"}],"
     "\"outbounds\":[{\"name\":\"out\",\"type\":\"socks5\",\"server\":\"proxy.test:1080\"}]}", FTUN_OK},
    {"{\"dns\":{\"listeners\":[{\"listen\":\"127.0.0.1:5353\"}],"
     "\"servers\":[{\"name\":\"bad\",\"type\":\"https\",\"address\":[\"1.1.1.1\"]}]}}", FTUN_E_UNSUPPORTED},
    {"{\"inbounds\":[{\"name\":\"good\",\"type\":\"socks5\",\"listen\":\"127.0.0.1:1080\"},"
     "{\"name\":\"bad\",\"type\":\"unknown\"}]}", FTUN_E_UNSUPPORTED},
    {"{\"outbounds\":[{\"name\":\"bad\",\"type\":\"socks5\",\"server\":\"proxy.test:1080\",\"username\":\"user\"}]}", FTUN_E_INVALID},
    {"{\"frs\":{\"path\":\"rules.frs\",\"unknown\":true}}", FTUN_E_INVALID},
    {"{\"sniff\":{\"enable\":1}}", FTUN_E_INVALID},
    {"{\"tun\":{\"interface\":\"ftun0\",\"ipv4\":{\"address\":\"172.19.0.1/30\"}}}", FTUN_OK},
    {"{\"tun\":{\"interface\":\"ftun0\",\"ipv4\":{\"address\":42}}}", FTUN_E_INVALID},
    {"{\"dns\":{\"bootstrap\":[\"1.1.1.1\",42]}}", FTUN_E_INVALID}
  };
  size_t index, capacity;
  for (capacity = 512u; capacity <= 32768u; capacity *= 2u) {
    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); index++) {
      ftun_budget_t *budget = NULL;
      ftun_budget_usage_t usage;
      ftun_config_t *config = NULL;
      ftun_config_json_t json;
      ftun_status_t status;
      CHECK(ftun_budget_create(NULL, capacity, 0u, &budget) == FTUN_OK);
      status = ftun_config_json_open(budget,
        (ftun_bytes_t){(const uint8_t *)cases[index].json, strlen(cases[index].json)}, &json);
      if (status == FTUN_OK) status = ftun_config_document_create(sizeof(*config), budget, &ops, &config);
      if (status == FTUN_OK) status = parse(config, json.root);
      CHECK(status == cases[index].expected || (capacity < 32768u && status == FTUN_E_LIMIT));
      if (status == FTUN_OK && capacity == 32768u) {
        ftun_diagnostic_t diagnostic;
        CHECK(ftun_config_validate_dns(&config->dns, &diagnostic) == FTUN_OK);
        CHECK(ftun_config_validate_outbounds(budget, config->outbounds,
          config->outbound_count, &diagnostic) == FTUN_OK);
        CHECK(ftun_config_validate_inbounds(config->inbounds, config->inbound_count,
          config->outbounds, config->outbound_count, &diagnostic) == FTUN_OK);
        CHECK(ftun_config_validate_tun_device(&config->tun, &diagnostic) == FTUN_OK);
        CHECK(ftun_config_validate_frs(&config->frs, config->outbounds,
          config->outbound_count, &diagnostic) == FTUN_OK);
        CHECK(ftun_config_validate_rule(config->outbounds, config->outbound_count,
          "MATCH,DIRECT", &diagnostic) == FTUN_OK);
        CHECK(ftun_config_validate_rule(config->outbounds, config->outbound_count,
          "MATCH,missing", &diagnostic) == FTUN_E_INVALID);
        if (index == 1u) {
          char *name = config->dns.servers[0].name;
          ftun_config_outbound_t group = {0};
          char *members[] = {"loop"};
          ftun_budget_usage_t before, after;
          config->dns.servers[0].name = "bad,name";
          CHECK(ftun_config_validate_dns(&config->dns, &diagnostic) == FTUN_E_INVALID);
          CHECK(diagnostic.path.length == strlen("/dns/servers") &&
            memcmp(diagnostic.path.data, "/dns/servers", diagnostic.path.length) == 0);
          config->dns.servers[0].name = name;
          group.kind = FTUN_CONFIG_OUTBOUND_SELECT;
          group.name = "loop";
          group.default_member = "loop";
          group.members.items = members;
          group.members.count = 1u;
          CHECK(ftun_budget_get_usage(budget, &before) == FTUN_OK);
          CHECK(ftun_config_validate_outbounds(budget, &group, 1u, &diagnostic) == FTUN_E_INVALID);
          CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK && after.used == before.used &&
            after.metadata_bytes == before.metadata_bytes);
        }
      }
      if (status == FTUN_OK && index == 1u) {
        CHECK(config->dns.server_count == 1u && config->dns.listener_count == 1u);
        CHECK(config->inbound_count == 1u && config->outbound_count == 1u);
        CHECK(config->inbounds[0].tcp_idle_ms == 30000u);
        CHECK(strcmp(config->dns.servers[0].outbound, "DIRECT") == 0);
      }
      ftun_config_json_close(&json);
      CHECK(ftun_config_destroy(&config) == FTUN_OK);
      CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == 0u);
      CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
    }
  }
  return 0;
}
