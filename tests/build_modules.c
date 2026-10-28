#include "config/compile.h"
#include "config/parser.h"
#include "config/validate.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "module contract failed: %s\n", #x); \
    return 1; \
  } \
} while (0)

static int has_name(const ftun_build_capabilities_t *capabilities, const char *name)
{
  size_t index;
  for (index = 0; index < capabilities->name_count; index++) {
    if (strcmp(capabilities->names[index], name) == 0) return 1;
  }
  return 0;
}

static int check_module(const ftun_build_capabilities_t *capabilities,
                        uint32_t module, const char *name, int expected)
{
  ftun_diagnostic_t diagnostic;
  ftun_status_t status = ftun_build_require_modules(module, &diagnostic);
  CHECK(((capabilities->builtins & module) != 0u) == expected);
  CHECK(has_name(capabilities, name) == expected);
  if (expected) {
    CHECK(status == FTUN_OK);
    CHECK(diagnostic.error.status == FTUN_OK);
    CHECK(diagnostic.message.data == NULL && diagnostic.message.length == 0u);
  } else {
    CHECK(status == FTUN_E_UNSUPPORTED);
    CHECK(diagnostic.error.status == FTUN_E_UNSUPPORTED);
    CHECK(diagnostic.message.data != NULL && diagnostic.message.length > 0u);
  }
  return 0;
}

static int check_config_capability(const char *text, int expected)
{
  ftun_bytes_t bytes;
  ftun_config_t *config = NULL;
  ftun_feature_plan_t *plan = NULL;
  ftun_diagnostic_t diagnostic;
  ftun_status_t status;
  bytes.data = (const uint8_t *)text;
  bytes.length = strlen(text);
  CHECK(ftun_config_parse(bytes, &config) == FTUN_OK && config != NULL);
  status = ftun_config_validate(config, &diagnostic);
  if (expected) {
    CHECK(status == FTUN_OK);
    CHECK(diagnostic.message.data == NULL && diagnostic.path.data == NULL);
    CHECK(ftun_config_compile(config, &plan) == FTUN_OK && plan != NULL);
    CHECK((plan->required_modules & ~plan->built_modules) == 0u);
    CHECK(ftun_feature_plan_destroy(&plan) == FTUN_OK && plan == NULL);
  } else {
    CHECK(status == FTUN_E_UNSUPPORTED);
    CHECK(diagnostic.error.status == FTUN_E_UNSUPPORTED);
    CHECK(diagnostic.message.data != NULL && diagnostic.path.data != NULL);
    CHECK(ftun_config_compile(config, &plan) == FTUN_E_UNSUPPORTED && plan == NULL);
  }
  CHECK(ftun_config_destroy(&config) == FTUN_OK && config == NULL);
  return 0;
}

static int check_required_modules(const char *text, uint32_t expected)
{
  ftun_bytes_t bytes;
  ftun_config_t *config = NULL;
  ftun_feature_plan_t *plan = NULL;
  bytes.data = (const uint8_t *)text;
  bytes.length = strlen(text);
  CHECK(ftun_config_parse(bytes, &config) == FTUN_OK && config != NULL);
  CHECK(ftun_config_compile(config, &plan) == FTUN_OK && plan != NULL);
  CHECK(plan->required_modules == expected);
  CHECK(ftun_feature_plan_destroy(&plan) == FTUN_OK && plan == NULL);
  CHECK(ftun_config_destroy(&config) == FTUN_OK && config == NULL);
  return 0;
}

int main(void)
{
  const ftun_build_capabilities_t *capabilities = ftun_build_capabilities();
  ftun_diagnostic_t diagnostic;
  size_t left, right;
  int expect_proxy = 0;
  int expect_dns = 0;
  int expect_fakeip = 0;
  int expect_tun = 0;
  int expect_frs = 0;
#if defined(FTUN_EXPECT_PROXY)
  expect_proxy = 1;
#endif
#if defined(FTUN_EXPECT_DNS)
  expect_dns = 1;
#endif
#if defined(FTUN_EXPECT_FAKEIP)
  expect_fakeip = 1;
#endif
#if defined(FTUN_EXPECT_TUN)
  expect_tun = 1;
#endif
#if defined(FTUN_EXPECT_FRS)
  expect_frs = 1;
#endif
  CHECK(capabilities != NULL);
  CHECK((capabilities->builtins & FTUN_BUILD_MODULE_CORE) != 0u);
  CHECK(has_name(capabilities, "core"));
  CHECK(check_module(capabilities, FTUN_BUILD_MODULE_PROXY, "proxy",
                     expect_proxy) == 0);
  CHECK(capabilities->name_count ==
        (size_t)(1 + expect_proxy + expect_dns + expect_fakeip +
                 expect_tun + expect_frs));
  for (left = 0; left < capabilities->name_count; left++) {
    CHECK(capabilities->names[left] != NULL && capabilities->names[left][0] != '\0');
    for (right = left + 1; right < capabilities->name_count; right++) {
      CHECK(strcmp(capabilities->names[left], capabilities->names[right]) != 0);
    }
  }
  CHECK(check_module(capabilities, FTUN_BUILD_MODULE_DNS, "dns", expect_dns) == 0);
  CHECK(check_module(capabilities, FTUN_BUILD_MODULE_FAKEIP, "fakeip",
                     expect_fakeip) == 0);
  CHECK(check_module(capabilities, FTUN_BUILD_MODULE_TUN, "tun", expect_tun) == 0);
  CHECK(check_module(capabilities, FTUN_BUILD_MODULE_FRS, "frs", expect_frs) == 0);
  CHECK(ftun_build_require_modules(FTUN_BUILD_MODULE_CORE, &diagnostic) == FTUN_OK);
  CHECK(ftun_build_require_modules(1u << 31, &diagnostic) == FTUN_E_INVALID);
  CHECK(diagnostic.error.status == FTUN_E_INVALID);
  CHECK(diagnostic.message.data != NULL && diagnostic.message.length > 0u);
  CHECK(check_config_capability("{\"dns\":{\"enable\":false}}", 1) == 0);
  CHECK(check_config_capability("{}", expect_dns) == 0);
  CHECK(check_config_capability(
    "{\"dns\":{\"servers\":[{\"name\":\"f\",\"type\":\"udp\","
    "\"address\":[\"192.0.2.53\"],\"fake-ip\":true}],"
    "\"default-server\":\"f\"}}",
    expect_proxy && expect_dns && expect_fakeip) == 0);
  CHECK(check_config_capability(
    "{\"dns\":{\"enable\":false},\"tun\":{\"interface\":\"t0\","
    "\"ipv4\":{\"address\":\"10.0.0.1/30\"}},"
    "\"inbounds\":[{\"name\":\"t\",\"type\":\"tun\"}]}",
    expect_proxy && expect_tun) == 0);
  CHECK(check_config_capability(
    "{\"dns\":{\"enable\":false},\"frs\":42}", 1) == 0);
  CHECK(check_config_capability(
    "{\"dns\":{\"enable\":false},\"rules\":[\"FRS-IP,CN,DIRECT\"]}",
    expect_proxy && expect_frs) == 0);
  CHECK(check_required_modules("{\"dns\":{\"enable\":false}}",
        FTUN_BUILD_MODULE_CORE) == 0);
  CHECK(check_required_modules(
    "{\"dns\":{\"enable\":false},\"outbounds\":[{\"name\":\"unused\","
    "\"type\":\"socks5\",\"server\":\"unused.example:1080\"}]}",
    FTUN_BUILD_MODULE_CORE) == 0);
  if (expect_dns) {
    CHECK(check_required_modules(
      "{\"dns\":{\"enable\":true,\"default-server\":\"d\","
      "\"listeners\":[{\"listen\":\"127.0.0.1:5353\","
      "\"server\":\"d\"}],\"servers\":[{\"name\":\"d\","
      "\"type\":\"udp\",\"address\":[\"192.0.2.53:53\"],"
      "\"outbound\":\"DIRECT\"}]}}",
      FTUN_BUILD_MODULE_CORE | FTUN_BUILD_MODULE_DNS) == 0);
  }
  if (expect_proxy) {
    CHECK(check_required_modules(
      "{\"dns\":{\"enable\":false},\"inbounds\":[{\"name\":\"p\","
      "\"type\":\"mixed\",\"listen\":\"127.0.0.1:1080\"}]}",
      FTUN_BUILD_MODULE_CORE | FTUN_BUILD_MODULE_PROXY) == 0);
  }
  return 0;
}
