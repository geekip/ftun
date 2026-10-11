#include "core/control_resolver.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#define CHECK(expression) do { \
  if (!(expression)) { \
    fprintf(stderr, "check failed: %s (%s:%d)\n", #expression, \
            __FILE__, __LINE__); \
    return 1; \
  } \
} while (0)

static int endpoint_contract(void)
{
  ftun_endpoint_t endpoint;
  char domain[FTUN_CONTROL_ENDPOINT_TEXT_BYTES];
  struct in_addr loopback;
  CHECK(inet_pton(AF_INET, "127.0.0.1", &loopback) == 1);
  CHECK(ftun_control_parse_endpoint("127.0.0.1", 53u, &endpoint,
                                    domain) == FTUN_OK);
  CHECK(endpoint.kind == FTUN_ADDRESS_IPV4 && endpoint.port == 53u);
  CHECK(memcmp(endpoint.address, &loopback.s_addr, 4u) == 0);
  CHECK(ftun_control_parse_endpoint("Example.COM:443", 53u, &endpoint,
                                    domain) == FTUN_OK);
  CHECK(endpoint.kind == FTUN_ADDRESS_DOMAIN && endpoint.port == 443u);
  CHECK(endpoint.domain.length == strlen("Example.COM"));
  CHECK(memcmp(endpoint.domain.data, "Example.COM",
               endpoint.domain.length) == 0);
  CHECK(ftun_control_parse_endpoint("example.com:0", 53u, &endpoint,
                                    domain) == FTUN_E_INVALID);
  CHECK(ftun_control_parse_endpoint("[::1]:53", 53u, &endpoint,
                                    domain) == FTUN_E_INVALID);
  return 0;
}

static int system_contract(void)
{
  ftun_config_t config;
  ftun_control_resolver_plan_t plan;
  ftun_endpoint_t endpoint;
  memset(&config, 0, sizeof(config));
  CHECK(ftun_control_resolver_plan(&config, NULL,
    (ftun_string_t){"ignored-while-disabled", 22u}, UINT32_C(0x4654),
    &plan) == FTUN_OK);
  CHECK(!plan.named && plan.bootstrap_count == 0u);
  CHECK(ftun_control_resolve(&plan,
    (ftun_string_t){"localhost", 9u}, 8080u, &endpoint) == FTUN_OK);
  CHECK(endpoint.kind == FTUN_ADDRESS_IPV4 && endpoint.port == 8080u);
  return 0;
}

static int named_plan_contract(void)
{
  char *bootstrap[] = {(char *)"127.0.0.1:5300"};
  char *addresses[] = {(char *)"dns.internal:5353"};
  ftun_config_dns_server_t dns_server;
  ftun_config_outbound_t outbound;
  ftun_config_t config;
  ftun_control_resolver_plan_t plan;
  memset(&dns_server, 0, sizeof(dns_server));
  dns_server.name = (char *)"real";
  dns_server.type = (char *)"tcp";
  dns_server.addresses.items = addresses;
  dns_server.addresses.count = 1u;
  dns_server.outbound = (char *)"proxy";
  memset(&outbound, 0, sizeof(outbound));
  outbound.kind = FTUN_CONFIG_OUTBOUND_SOCKS5;
  outbound.name = (char *)"proxy";
  outbound.server = (char *)"proxy.internal:1080";
  outbound.username = (char *)"user";
  outbound.password = (char *)"pass";
  memset(&config, 0, sizeof(config));
  config.dns.enable = true;
  config.dns.bootstrap.items = bootstrap;
  config.dns.bootstrap.count = 1u;
  config.dns.servers = &dns_server;
  config.dns.server_count = 1u;
  config.outbounds = &outbound;
  config.outbound_count = 1u;
  CHECK(ftun_control_resolver_plan(&config, NULL,
    (ftun_string_t){"real", 4u}, UINT32_C(0x4654), &plan) == FTUN_OK);
  CHECK(plan.named && plan.tcp && plan.use_proxy);
  CHECK(plan.bootstrap_count == 1u);
  CHECK(strcmp(plan.upstream, "dns.internal:5353") == 0);
  CHECK(strcmp(plan.proxy, "proxy.internal:1080") == 0);
  CHECK(strcmp(plan.proxy_username, "user") == 0);
  CHECK(strcmp(plan.proxy_password, "pass") == 0);
  CHECK(ftun_control_resolver_plan(&config, NULL,
    (ftun_string_t){"missing", 7u}, UINT32_C(0x4654),
    &plan) == FTUN_E_REJECTED);
  return 0;
}

int main(void)
{
  CHECK(endpoint_contract() == 0);
  CHECK(system_contract() == 0);
  CHECK(named_plan_contract() == 0);
  puts("control resolver contract tests passed");
  return 0;
}
