#define _POSIX_C_SOURCE 200809L
#include "app/config/compile.h"
#include "app/config/config.h"
#include "app/config/model.h"
#include "app/config/parser.h"
#include "app/config/validate.h"
#include "core/limits.h"
#include "proxy/runtime_state.h"
#include "proxy/state/restore.h"
#include "proxy/route/rule.h"
#include "proxy/state/group_cache.h"
#include "platform/clock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "core state contract failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

static ftun_config_t *make_config(const char *path, int remove_node_b)
{
  char text[2048];
  ftun_bytes_t bytes;
  ftun_config_t *config = NULL;
  ftun_feature_plan_t *plan = NULL;
  ftun_diagnostic_t diagnostic;
  int length = snprintf(text, sizeof(text),
    "{\"base\":{\"cache-file\":\"%s\",\"state-cache\":true},"
    "\"dns\":{\"enable\":false},\"outbounds\":["
    "{\"name\":\"node-a\",\"type\":\"socks5\",\"server\":\"127.0.0.1:1080\"}%s,"
    "{\"name\":\"manual\",\"type\":\"select\",\"outbounds\":[\"node-a\"%s],"
    "\"default\":\"node-a\"},"
    "{\"name\":\"auto\",\"type\":\"url-test\",\"outbounds\":[\"node-a\"%s],"
    "\"default\":\"node-a\",\"url\":\"http://example.com/health\"}]}",
    path,
    remove_node_b ? "" :
      ",{\"name\":\"node-b\",\"type\":\"socks5\",\"server\":\"127.0.0.1:1081\"}",
    remove_node_b ? "" : ",\"node-b\"",
    remove_node_b ? "" : ",\"node-b\"");
  if (length <= 0 || (size_t)length >= sizeof(text)) return NULL;
  bytes = (ftun_bytes_t){(const uint8_t *)text, (size_t)length};
  if (ftun_config_parse(bytes, &config) != FTUN_OK ||
      ftun_config_validate(config, &diagnostic) != FTUN_OK ||
      ftun_config_compile(config, &plan) != FTUN_OK) {
    (void)ftun_config_destroy(&config);
    return NULL;
  }
  ftun_config_bind_plan(config, plan);
  return config;
}

static int activate(ftun_core_t *core, ftun_config_t *config)
{
  ftun_runtime_t *candidate = NULL;
  CHECK(ftun_runtime_prepare(core, config, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK);
  return 0;
}

static int selected(ftun_core_t *core, uint32_t group, uint32_t expected,
                    bool expected_health)
{
  ftun_runtime_t *runtime = NULL;
  ftun_runtime_group_record_t records[2];
  size_t count = 0u;
  size_t index;
  CHECK(ftun_runtime_active_acquire(core, &runtime) == FTUN_OK);
  CHECK(ftun_runtime_group_records(core, records, 2u, &count) == FTUN_OK);
  CHECK(count == 2u);
  for (index = 0u; index < count; index++) {
    if ((group == 4u && records[index].group.length == 6u &&
         memcmp(records[index].group.data, "manual", 6u) == 0) ||
        (group == 5u && records[index].group.length == 4u &&
         memcmp(records[index].group.data, "auto", 4u) == 0)) {
      uint32_t actual = records[index].member.length == 6u &&
        memcmp(records[index].member.data, "node-b", 6u) == 0 ? 3u : 2u;
      CHECK(actual == expected);
      CHECK(records[index].health_valid == expected_health);
    }
  }
  CHECK(ftun_runtime_release(&runtime) == FTUN_OK);
  return 0;
}

int main(void)
{
  char directory[] = "/tmp/ftun-core-state-XXXXXX";
  char path[256];
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_config_t *config = NULL;
  ftun_group_choice_t choice;
  ftun_health_sample_t sample;
  ftun_state_restore_info_t info;
  uint64_t observed_ms;
  uint64_t restore_ms;
  CHECK(mkdtemp(directory) != NULL);
  CHECK(snprintf(path, sizeof(path), "%s/state.cache", directory) > 0);

  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 2u, &core) == FTUN_OK);
  config = make_config(path, 0);
  CHECK(config != NULL && activate(core, config) == 0);
  CHECK(ftun_runtime_select_set(core, 4u, 3u) == FTUN_OK);
  memset(&choice, 0, sizeof(choice));
  choice.generation = 1u;
  choice.leaf_id = 3u;
  memset(&sample, 0, sizeof(sample));
  CHECK(ftun_monotonic_now(&observed_ms) == FTUN_OK);
  sample.member_id = 3u;
  sample.latency_ms = 25u;
  sample.observed_ms = observed_ms;
  sample.success = true;
  sample.tcp_only = true;
  CHECK(ftun_runtime_group_publish_health(core, 5u, &choice, &sample) == FTUN_OK);
  CHECK(ftun_group_cache_save(core, path) == FTUN_OK);
  CHECK(ftun_monotonic_now(&restore_ms) == FTUN_OK &&
        restore_ms >= observed_ms);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);

  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 2u, &core) == FTUN_OK);
  config = make_config(path, 0);
  CHECK(config != NULL && activate(core, config) == 0);
  CHECK(selected(core, 4u, 2u, false) == 0);
  CHECK(ftun_state_restore_at(core, config, restore_ms, 500u, &info) == FTUN_OK);
  CHECK(info.restored_groups == 2u && info.restored_health == 1u &&
        !info.cache_discarded && !info.fingerprint_mismatch);
  CHECK(selected(core, 4u, 3u, false) == 0);
  CHECK(selected(core, 5u, 3u, true) == 0);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);

  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 2u, &core) == FTUN_OK);
  config = make_config(path, 0);
  CHECK(config != NULL && activate(core, config) == 0);
  CHECK(ftun_state_restore_at(core, config, restore_ms + 1000u,
                              500u, &info) == FTUN_OK);
  CHECK(info.restored_groups == 2u && info.restored_health == 0u);
  CHECK(selected(core, 5u, 3u, false) == 0);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);

  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 2u, &core) == FTUN_OK);
  config = make_config(path, 1);
  CHECK(config != NULL && activate(core, config) == 0);
  CHECK(ftun_state_restore_at(core, config, restore_ms, 500u, &info) == FTUN_OK);
  CHECK(info.fingerprint_mismatch && info.cache_discarded &&
        info.restored_groups == 0u);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);

  CHECK(unlink(path) == 0 && rmdir(directory) == 0);
  return 0;
}
