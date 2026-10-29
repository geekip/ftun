#include "libs/transport/config.h"
#include "libs/resolver/config.h"
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "config views failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

/* 与 app 不同的宿主布局；共享读取器不能假定业务模型或其字段偏移。 */
struct ftun_config {
  ftun_config_document_t document;
  uint64_t marker;
  ftun_channel_config_t channel;
  ftun_config_resolver_t resolver;
};
static size_t count(const ftun_config_t *config)
{
  (void)config;
  return 1u;
}
static ftun_channel_config_t at(const ftun_config_t *config, size_t index)
{
  (void)index;
  return config->channel;
}
static ftun_config_resolver_t resolver(const ftun_config_t *config)
{
  return config->resolver;
}
static const void *section(const ftun_config_t *config, uint32_t id)
{
  static const ftun_channel_catalog_t channels = {count, at};
  static const ftun_config_resolver_ops_t resolvers = {resolver};
  (void)config;
  if (id == FTUN_CONFIG_SECTION_CHANNELS) return &channels;
  if (id == FTUN_CONFIG_SECTION_RESOLVER) return &resolvers;
  return NULL;
}
int main(void)
{
  static const ftun_config_document_ops_t ops = {NULL, NULL, section};
  char *addresses[] = {"1.1.1.1:53"};
  char *members[] = {"DIRECT"};
  ftun_config_dns_server_t server = {0};
  ftun_config_t config = {0};
  ftun_channel_config_t channel;
  ftun_config_resolver_t view;
  config.document.ops = &ops;
  config.marker = UINT64_C(0xabcdef0123456789);
  config.channel.kind = FTUN_CHANNEL_CONFIG_GROUP;
  config.channel.name = "group";
  config.channel.members = (ftun_config_string_list_t){members, 1u};
  server.name = "real";
  server.addresses = (ftun_config_string_list_t){addresses, 1u};
  config.resolver.enable = true;
  config.resolver.servers = &server;
  config.resolver.server_count = 1u;
  CHECK(ftun_config_channel_count(&config) == 1u);
  channel = ftun_config_channel(&config, 0u);
  CHECK(channel.kind == FTUN_CHANNEL_CONFIG_GROUP && channel.name == config.channel.name);
  CHECK(channel.members.items == members && strcmp(channel.members.items[0], "DIRECT") == 0);
  channel.kind = FTUN_CHANNEL_CONFIG_SOCKS5;
  CHECK(config.channel.kind == FTUN_CHANNEL_CONFIG_GROUP);
  view = ftun_config_resolver(&config);
  CHECK(view.enable && view.server_count == 1u && view.servers == &server);
  CHECK(view.servers[0].addresses.items == addresses && config.marker == UINT64_C(0xabcdef0123456789));
  return 0;
}
