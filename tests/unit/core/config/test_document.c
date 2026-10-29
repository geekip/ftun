#include "core/config/document.h"
#include "core/limits.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "config document failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

/* 自定义宿主布局，刻意不依赖 app 的聚合模型或 feature plan。 */
struct ftun_config {
  ftun_config_document_t document;
  char *payload;
  bool pending;
};
static size_t prepares, destroys;
static ftun_status_t prepare(ftun_config_t *config)
{
  prepares++;
  return config->pending ? FTUN_E_AGAIN : FTUN_OK;
}
static void destroy(ftun_config_t *config)
{
  destroys++;
  free(config->payload);
}

static const void *custom_section(const ftun_config_t *config, uint32_t section_id)
{
  return section_id == UINT32_C(0x1122) ? config->payload : NULL;
}

static int ownership(void)
{
  static const ftun_config_document_ops_t ops = {prepare, destroy, custom_section};
  ftun_config_modules_t modules = {UINT32_C(0x80000000), UINT32_C(0x80000000), UINT32_C(0x80000000)};
  ftun_config_t *config = NULL, *alias;
  ftun_budget_t *budget = NULL;
  ftun_budget_usage_t usage;
  size_t bytes;
  CHECK(ftun_budget_create(NULL, 4096u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_config_document_create(sizeof(*config), budget, &ops, &config) == FTUN_OK);
  config->payload = ftun_config_allocate(config, 16u, 1u);
  CHECK(config->payload != NULL);
  strcpy(config->payload, "custom module");
  CHECK(ftun_config_document_section(config, UINT32_C(0x1122)) == config->payload);
  CHECK(ftun_config_document_section(config, UINT32_C(0x9999)) == NULL);
  config->document.modules = &modules;
  CHECK(ftun_config_document_modules(config) == &modules);
  CHECK(ftun_config_document_modules(config)->required_modules == UINT32_C(0x80000000));
  bytes = sizeof(*config) + 16u;
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == bytes);
  CHECK(ftun_config_retain(config) == FTUN_OK);
  alias = config;
  CHECK(ftun_config_destroy(&alias) == FTUN_OK && alias == NULL);
  CHECK(prepares == 0u && destroys == 0u);
  config->pending = true;
  CHECK(ftun_config_destroy(&config) == FTUN_E_AGAIN && config != NULL);
  CHECK(config->document.reference_count == 1u && prepares == 1u && destroys == 0u);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == bytes);
  config->pending = false;
  CHECK(ftun_config_destroy(&config) == FTUN_OK && config == NULL);
  CHECK(prepares == 2u && destroys == 1u);
  CHECK(ftun_config_destroy(&config) == FTUN_OK && prepares == 2u && destroys == 1u);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

static int json_boundary(void)
{
  const char *inputs[] = {
    "{\"new_module\":{\"value\":1}}",
    "{\"new_module\":1,\"new_module\":2}",
    "{\"bad\":\"\\u0000\"}",
    "{\"bad\":1e999}",
    "{\"bad\":\"\xc0\xaf\"}",
    "\xef\xbb\xbf{\"new_module\":true}",
    "\xef\xbb\xbf\xef\xbb\xbf{}"
  };
  ftun_budget_t *budget = NULL;
  ftun_budget_usage_t usage;
  size_t index;
  CHECK(ftun_budget_create(NULL, 16384u, 0u, &budget) == FTUN_OK);
  for (index = 0; index < sizeof(inputs) / sizeof(inputs[0]); index++) {
    ftun_config_json_t document;
    bool valid = index == 0u || index == 5u;
    ftun_status_t status = ftun_config_json_open(budget,
      (ftun_bytes_t){(const uint8_t *)inputs[index], strlen(inputs[index])}, &document);
    CHECK(status == (valid ? FTUN_OK : FTUN_E_INVALID));
    if (valid) {
      CHECK(cJSON_GetObjectItemCaseSensitive(document.root, "new_module") != NULL);
      CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes > 0u);
      ftun_config_json_close(&document);
      ftun_config_json_close(&document);
    } else CHECK(document.root == NULL && (document.reservation).budget == NULL);
    CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u);
  }
  ftun_config_json_close(NULL);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}
int main(void)
{
  CHECK(ownership() == 0);
  CHECK(json_boundary() == 0);
  return 0;
}
