#include "config/compile.h"
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

int main(void)
{
  const ftun_build_capabilities_t *capabilities = ftun_build_capabilities();
  ftun_diagnostic_t diagnostic;
  size_t left, right;
  int expect_dns = 0;
  int expect_tun = 0;
#if defined(FTUN_EXPECT_DNS)
  expect_dns = 1;
#endif
#if defined(FTUN_EXPECT_TUN)
  expect_tun = 1;
#endif
  CHECK(capabilities != NULL);
  CHECK((capabilities->builtins & FTUN_BUILD_MODULE_CORE) != 0u);
  CHECK(has_name(capabilities, "core"));
  CHECK(capabilities->name_count == (size_t)(1 + expect_dns + expect_tun));
  for (left = 0; left < capabilities->name_count; left++) {
    CHECK(capabilities->names[left] != NULL && capabilities->names[left][0] != '\0');
    for (right = left + 1; right < capabilities->name_count; right++) {
      CHECK(strcmp(capabilities->names[left], capabilities->names[right]) != 0);
    }
  }
  CHECK(check_module(capabilities, FTUN_BUILD_MODULE_DNS, "dns", expect_dns) == 0);
  CHECK(check_module(capabilities, FTUN_BUILD_MODULE_TUN, "tun", expect_tun) == 0);
  CHECK(ftun_build_require_modules(FTUN_BUILD_MODULE_CORE, &diagnostic) == FTUN_OK);
  CHECK(ftun_build_require_modules(1u << 31, &diagnostic) == FTUN_E_INVALID);
  CHECK(diagnostic.error.status == FTUN_E_INVALID);
  CHECK(diagnostic.message.data != NULL && diagnostic.message.length > 0u);
  return 0;
}
