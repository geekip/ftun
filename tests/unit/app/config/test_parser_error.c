#include "app/config/parser.h"
#include "app/config/model.h"
#include "core/config/document.h"
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "parser error at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

int main(void)
{
  static const struct { const char *json, *pointer, *field; } cases[] = {
    {"{\"outbounds\":[{},{}]}", "/outbounds/0/type", "outbounds[0].type"},
    {"{\"outbounds\":[{\"type\":\"socks5\",\"name\":\"a\",\"server\":\"a:1\"},{\"type\":\"socks5\",\"name\":\"b\"}]}",
      "/outbounds/1/server", "outbounds[1].server"},
    {"{\"outbounds\":[{\"type\":\"socks5\",\"name\":\"a\",\"server\":\"a:1\",\"username\":\"user\"}]}",
      "/outbounds/0/password", "outbounds[0].password"},
    {"{\"outbounds\":[{\"type\":\"select\",\"name\":\"a\"}]}", "/outbounds/0/outbounds", "outbounds[0].outbounds"},
    {"{\"inbounds\":[42]}", "/inbounds/0", "inbounds[0]"},
    {"{\"inbounds\":[{\"type\":\"unknown\"}]}", "/inbounds/0/type", "inbounds[0].type"},
    {"{\"inbounds\":[{\"type\":\"socks5\",\"name\":\"a\",\"listen\":\"127.0.0.1:1\",\"users\":{\"a~/b\":42}}]}",
      "/inbounds/0/users/a~0~1b", "inbounds[0].users[\"a~/b\"]"},
    {"{\"dns\":{\"servers\":[{\"name\":\"up\",\"type\":\"udp\",\"address\":[\"1.1.1.1\",42]}]}}",
      "/dns/servers/0/address/1", "dns.servers[0].address[1]"},
    {"{\"dns\":{\"servers\":42}}", "/dns/servers", "dns.servers"},
    {"{\"dns\":{\"servers\":[{\"name\":\"up\",\"type\":\"udp\"}]}}",
      "/dns/servers/0/address", "dns.servers[0].address"},
    {"{\"base\":{\"timeouts\":{\"tcp-keepalive\":{\"idle\":\"1ms\"}}}}",
      "/base/timeouts/tcp-keepalive/idle", "base.timeouts.tcp-keepalive.idle"},
    {"{\"log\":{\"max-files\":1.5}}", "/log/max-files", "log.max-files"},
    {"{\"tun\":{\"interface\":\"tun0\"}}", "/tun/ipv4", "tun.ipv4"},
    {"{\"inbounds\":[{\"type\":\"tun\",\"name\":\"a\"}]}", "/tun", "tun"},
    {"{\"$schema\":false}", "/$schema", "[\"$schema\"]"},
    {"{\"api\":{}}", "/api", "api"},
    {"{\"a~/b\":{},\"log\":{\"level\":42}}", "/a~0~1b", "[\"a~/b\"]"}
  };
  size_t index;
  for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); index++) {
    ftun_config_t *config = NULL;
    ftun_config_error_t error, copy;
    ftun_bytes_t input = {(const uint8_t *)cases[index].json, strlen(cases[index].json)};
    ftun_status_t status = ftun_config_parse_budget_error(NULL, input, &config, &error);
    CHECK(status != FTUN_OK && error.error.status == status && config == NULL);
    CHECK(error.phase == FTUN_CONFIG_STEP_PARSE && !error.truncated);
    CHECK(strcmp(error.pointer, cases[index].pointer) == 0);
    CHECK(strcmp(error.field, cases[index].field) == 0);
    copy = error;
    CHECK(ftun_config_error_set(&error, FTUN_E_LIMIT, "/later", "later error") == status);
    CHECK(memcmp(&copy, &error, sizeof(copy)) == 0);
  }
  ftun_config_t *config = NULL;
  ftun_config_error_t error;
  CHECK(ftun_config_parse_budget_error(NULL, (ftun_bytes_t){(const uint8_t *)"{}", 2u},
    &config, &error) == FTUN_OK);
  CHECK(config->document.parse_error == NULL && config->document.parse_root == NULL);
  CHECK(error.error.status == FTUN_OK);
  CHECK(ftun_config_destroy(&config) == FTUN_OK && config == NULL);
  return 0;
}
