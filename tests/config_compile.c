#include "config/compile.h"
#include "config/parser.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "config compile failed: %s\n", #x); \
    return 1; \
  } \
} while (0)

static ftun_status_t parse_text(const char *text, ftun_config_t **out)
{
  ftun_bytes_t bytes;
  bytes.data = (const uint8_t *)text;
  bytes.length = strlen(text);
  return ftun_config_parse(bytes, out);
}

static char *read_file(const char *path, size_t *length)
{
  FILE *file;
  long size;
  char *data;
  *length = 0u;
  file = fopen(path, "rb");
  if (file == NULL || fseek(file, 0L, SEEK_END) != 0) {
    if (file != NULL) (void)fclose(file);
    return NULL;
  }
  size = ftell(file);
  if (size < 0L || (unsigned long)size > FTUN_CONFIG_MAX_JSON_BYTES ||
      fseek(file, 0L, SEEK_SET) != 0) {
    (void)fclose(file);
    return NULL;
  }
  data = (char *)malloc((size_t)size + 1u);
  if (data == NULL) {
    (void)fclose(file);
    return NULL;
  }
  if (fread(data, 1u, (size_t)size, file) != (size_t)size || fclose(file) != 0) {
    free(data);
    return NULL;
  }
  data[size] = '\0';
  *length = (size_t)size;
  return data;
}

static int feature(uint64_t features, uint64_t value)
{
  return (features & value) == value;
}

static int no_feature(uint64_t features, uint64_t value)
{
  return (features & value) == 0u;
}

static int compile_text(const char *text, ftun_feature_plan_t **out)
{
  ftun_config_t *config = NULL;
  ftun_status_t status = parse_text(text, &config);
  if (status != FTUN_OK || config == NULL) return 0;
  status = ftun_config_compile(config, out);
  if (ftun_config_destroy(&config) != FTUN_OK) return 0;
  return status == FTUN_OK && *out != NULL;
}

/* TASK-CONFIG-004 / TEST-CONFIG-004：依赖闭包、阶段和原规则顺序。 */
int main(int argc, char **argv)
{
  static const char unused[] =
    "{\"dns\":{\"enable\":false},\"outbounds\":[{\"name\":\"unused\","
    "\"type\":\"socks5\",\"server\":\"unused.example:1080\"}]}";
  static const char forced_proxy[] =
    "{\"dns\":{\"enable\":false},\"inbounds\":[{\"name\":\"i\","
    "\"type\":\"mixed\",\"listen\":\"127.0.0.1:1\",\"outbound\":\"p\"}],"
    "\"outbounds\":[{\"name\":\"p\",\"type\":\"socks5\","
    "\"server\":\"proxy.example:1080\"}]}";
  static const char group[] =
    "{\"dns\":{\"enable\":false},\"inbounds\":[{\"name\":\"i\","
    "\"type\":\"mixed\",\"listen\":\"127.0.0.1:1\",\"outbound\":\"g\"}],"
    "\"outbounds\":[{\"name\":\"p1\",\"type\":\"socks5\","
    "\"server\":\"192.0.2.1:1\"},{\"name\":\"p2\",\"type\":\"socks5\","
    "\"server\":\"192.0.2.2:1\"},{\"name\":\"g\",\"type\":\"select\","
    "\"outbounds\":[\"p1\",\"p2\"],\"default\":\"p1\"}]}";
  static const char active_health[] =
    "{\"dns\":{\"enable\":false},\"inbounds\":[{\"name\":\"i\","
    "\"type\":\"mixed\",\"listen\":\"127.0.0.1:1\",\"outbound\":\"g\"}],"
    "\"outbounds\":[{\"name\":\"p\",\"type\":\"socks5\","
    "\"server\":\"192.0.2.1:1\"},{\"name\":\"g\",\"type\":\"url-test\","
    "\"outbounds\":[\"p\"],\"default\":\"p\",\"url\":\"http://192.0.2.2/x\","
    "\"lazy\":false}]}";
  static const char disabled_dns[] =
    "{\"dns\":{\"enable\":false,\"default-server\":\"missing\","
    "\"servers\":[{\"name\":\"s\",\"type\":\"udp\","
    "\"address\":[\"dns.example\"],\"outbound\":\"missing\"}]},"
    "\"outbounds\":[{\"name\":\"p\",\"type\":\"socks5\","
    "\"server\":\"proxy.example:1\",\"dns-server\":\"missing\"}]}";
  static const char frs_update[] =
    "{\"dns\":{\"enable\":false},\"frs\":{\"auto-update\":true,"
    "\"update-outbound\":\"p\",\"path\":\"rules.frs\","
    "\"url\":\"https://frs.example/rules.frs\"},\"outbounds\":[{\"name\":\"p\","
    "\"type\":\"socks5\",\"server\":\"192.0.2.1:1\"}],"
    "\"rules\":[\"FRS-IP,CN,DIRECT\"]}";
  static const char frs_rule[] =
    "{\"dns\":{\"enable\":false},\"frs\":{\"path\":\"rules.frs\"},"
    "\"rules\":[\"frs-domain,ads,REJECT\",\"MATCH,DIRECT\"]}";
  static const char frs_dns[] =
    "{\"dns\":{\"servers\":[{\"name\":\"frs-dns\",\"type\":\"udp\","
    "\"address\":[\"192.0.2.53\"]}]},\"frs\":{\"auto-update\":true,"
    "\"dns-server\":\"frs-dns\",\"path\":\"rules.frs\","
    "\"url\":\"https://frs.example/rules.frs\"},"
    "\"rules\":[\"FRS-DOMAIN,CN,REJECT\"]}";
  static const char dns_root[] =
    "{\"dns\":{\"default-server\":\"real\",\"servers\":[{\"name\":\"real\","
    "\"type\":\"udp\",\"address\":[\"192.0.2.53\"]}]},\"inbounds\":[{"
    "\"name\":\"i\",\"type\":\"mixed\",\"listen\":\"127.0.0.1:1\"}]}";
  ftun_feature_plan_t *plan = NULL;
  ftun_config_t *config = NULL;
  ftun_bytes_t bytes;
  char *file_data;
  size_t file_length;
  size_t index;

  CHECK(argc == 2);
  file_data = read_file(argv[1], &file_length);
  CHECK(file_data != NULL);
  bytes.data = (const uint8_t *)file_data;
  bytes.length = file_length;
  CHECK(ftun_config_parse(bytes, &config) == FTUN_OK && config != NULL);
  CHECK(ftun_config_compile(config, &plan) == FTUN_OK && plan != NULL);
  CHECK((plan->required_modules & FTUN_BUILD_MODULE_ALL) == FTUN_BUILD_MODULE_ALL);
  CHECK(plan->built_modules == ftun_build_capabilities()->builtins);
  CHECK(plan->outbound_count == 4u && plan->reachable_outbound_count == 4u &&
        plan->lazy_outbound_count == 2u);
  CHECK(plan->dns_server_count == 2u && plan->reachable_dns_server_count == 2u);
  CHECK(plan->prepare_listener_count == 4u && plan->prepare_tun_count == 1u &&
        plan->prepare_frs_count == 1u);
  CHECK(plan->lazy_health_count == 1u && plan->active_health_count == 0u);
  CHECK(feature(plan->compiled, FTUN_PLAN_RULES | FTUN_PLAN_INBOUND |
                FTUN_PLAN_TUN | FTUN_PLAN_OUTBOUND | FTUN_PLAN_GROUP |
                FTUN_PLAN_DNS | FTUN_PLAN_HEALTH));
  CHECK(feature(plan->prepare, FTUN_PLAN_INBOUND | FTUN_PLAN_TUN |
                FTUN_PLAN_DNS | FTUN_PLAN_DNS_LISTENER | FTUN_PLAN_DNS_CACHE |
                FTUN_PLAN_FAKE_IP | FTUN_PLAN_STATE_CACHE));
  CHECK(no_feature(plan->prepare, FTUN_PLAN_OUTBOUND | FTUN_PLAN_HEALTH));
  CHECK(feature(plan->lazy, FTUN_PLAN_OUTBOUND | FTUN_PLAN_HEALTH |
                FTUN_PLAN_BOOTSTRAP));
  CHECK(feature(plan->active, FTUN_PLAN_RULES | FTUN_PLAN_GROUP |
                FTUN_PLAN_DNS | FTUN_PLAN_FAKE_IP));
  CHECK(feature(plan->retained, FTUN_PLAN_RUNTIME | FTUN_PLAN_OUTBOUND |
                FTUN_PLAN_GROUP | FTUN_PLAN_FAKE_IP | FTUN_PLAN_STATE_CACHE));
  for (index = 0u; index < plan->rule_count; index++) {
    CHECK(plan->rule_order[index] == index);
  }
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(plan->rule_count == 6u && plan->outbound_states[3] & FTUN_PLAN_ITEM_ACTIVE);
  CHECK(ftun_feature_plan_destroy(&plan) == FTUN_OK && plan == NULL);
  free(file_data);

  CHECK(compile_text("{}", &plan));
  CHECK(feature(plan->compiled, FTUN_PLAN_DNS));
  CHECK(no_feature(plan->prepare, FTUN_PLAN_DNS));
  CHECK(plan->required_modules == (FTUN_BUILD_MODULE_CORE | FTUN_BUILD_MODULE_DNS));
  CHECK(ftun_feature_plan_destroy(&plan) == FTUN_OK);

  CHECK(compile_text(unused, &plan));
  CHECK(plan->outbound_count == 1u && plan->reachable_outbound_count == 0u);
  CHECK(plan->outbound_states[0] == FTUN_PLAN_ITEM_COMPILED);
  CHECK(no_feature(plan->lazy, FTUN_PLAN_OUTBOUND | FTUN_PLAN_SYSTEM_RESOLVER));
  CHECK(ftun_feature_plan_destroy(&plan) == FTUN_OK);

  CHECK(compile_text(forced_proxy, &plan));
  CHECK(plan->prepare_listener_count == 1u && plan->reachable_outbound_count == 1u &&
        plan->lazy_outbound_count == 1u);
  CHECK(feature(plan->lazy, FTUN_PLAN_OUTBOUND | FTUN_PLAN_SYSTEM_RESOLVER));
  CHECK(no_feature(plan->prepare, FTUN_PLAN_OUTBOUND));
  CHECK(ftun_feature_plan_destroy(&plan) == FTUN_OK);

  CHECK(compile_text(group, &plan));
  CHECK(plan->reachable_outbound_count == 3u && plan->lazy_outbound_count == 2u);
  CHECK((plan->outbound_states[0] & FTUN_PLAN_ITEM_REACHABLE) != 0u &&
        (plan->outbound_states[1] & FTUN_PLAN_ITEM_REACHABLE) != 0u &&
        (plan->outbound_states[2] & FTUN_PLAN_ITEM_ACTIVE) != 0u);
  CHECK(feature(plan->prepare, FTUN_PLAN_STATE_CACHE));
  CHECK(ftun_feature_plan_destroy(&plan) == FTUN_OK);

  CHECK(compile_text(active_health, &plan));
  CHECK(plan->active_health_count == 1u && plan->lazy_health_count == 0u);
  CHECK(feature(plan->active, FTUN_PLAN_HEALTH));
  CHECK(no_feature(plan->lazy, FTUN_PLAN_HEALTH));
  CHECK(ftun_feature_plan_destroy(&plan) == FTUN_OK);

  CHECK(compile_text(disabled_dns, &plan));
  CHECK(feature(plan->compiled, FTUN_PLAN_DNS | FTUN_PLAN_OUTBOUND));
  CHECK(no_feature(plan->prepare, FTUN_PLAN_DNS));
  CHECK(plan->reachable_dns_server_count == 0u && plan->reachable_outbound_count == 0u);
  CHECK(no_feature(plan->lazy, FTUN_PLAN_BOOTSTRAP | FTUN_PLAN_SYSTEM_RESOLVER));
  CHECK(ftun_feature_plan_destroy(&plan) == FTUN_OK);

  CHECK(compile_text(frs_update, &plan));
  CHECK(plan->prepare_frs_count == 1u && plan->reachable_outbound_count == 1u);
  CHECK(feature(plan->prepare, FTUN_PLAN_FRS));
  CHECK(feature(plan->active, FTUN_PLAN_FRS_UPDATE));
  CHECK(feature(plan->lazy, FTUN_PLAN_SYSTEM_RESOLVER));
  CHECK(ftun_feature_plan_destroy(&plan) == FTUN_OK);

  CHECK(compile_text(frs_rule, &plan));
  CHECK(plan->prepare_frs_count == 1u && plan->rule_count == 2u);
  CHECK(feature(plan->prepare, FTUN_PLAN_FRS));
  CHECK(plan->rule_order[0] == 0u && plan->rule_order[1] == 1u);
  CHECK(ftun_feature_plan_destroy(&plan) == FTUN_OK);

  CHECK(compile_text(frs_dns, &plan));
  CHECK(plan->reachable_dns_server_count == 1u && plan->prepare_frs_count == 1u);
  CHECK(feature(plan->prepare, FTUN_PLAN_DNS | FTUN_PLAN_DNS_CACHE |
                FTUN_PLAN_FRS));
  CHECK(no_feature(plan->lazy, FTUN_PLAN_BOOTSTRAP));
  CHECK(ftun_feature_plan_destroy(&plan) == FTUN_OK);

  CHECK(compile_text(dns_root, &plan));
  CHECK(plan->reachable_dns_server_count == 1u);
  CHECK(feature(plan->prepare, FTUN_PLAN_DNS | FTUN_PLAN_DNS_CACHE));
  CHECK(no_feature(plan->lazy, FTUN_PLAN_BOOTSTRAP));
  CHECK(ftun_feature_plan_destroy(&plan) == FTUN_OK);

  plan = (ftun_feature_plan_t *)(uintptr_t)1;
  CHECK(ftun_config_compile(NULL, &plan) == FTUN_E_INVALID && plan == NULL);
  CHECK(parse_text("{\"log\":{\"level\":\"bad\"}}", &config) == FTUN_OK);
  CHECK(ftun_config_compile(config, &plan) == FTUN_E_INVALID && plan == NULL);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(ftun_config_compile(NULL, NULL) == FTUN_E_INVALID);
  CHECK(ftun_feature_plan_destroy(NULL) == FTUN_E_INVALID);
  CHECK(ftun_feature_plan_destroy(&plan) == FTUN_OK);
  return 0;
}
