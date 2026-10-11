#include "group/health.h"
#include "group/select.h"
#include "group/url_test.h"
#include "config/compile.h"
#include "config/model.h"
#include "config/parser.h"
#include "config/validate.h"
#include "core/budget.h"
#include "core/operation.h"
#include "core/runtime.h"
#include "route/group.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "group contract failed: %s\n", #x); return 1; \
} } while (0)

typedef struct { size_t calls; ftun_status_t status; } completion_state_t;

static void completed(ftun_operation_t *operation, ftun_error_t error,
                      void *user)
{
  completion_state_t *state = (completion_state_t *)user;
  (void)operation;
  state->calls++;
  state->status = error.status;
}

static ftun_status_t perform_probe(void *user, ftun_string_t url,
                                   uint32_t member_id, uint64_t deadline_ms,
                                   ftun_probe_result_t *out)
{
  bool verified = *(const bool *)user;
  (void)url;
  memset(out, 0, sizeof(*out));
  out->http_status = 204u;
  out->latency_ms = 20u;
  out->finished_ms = deadline_ms - 1u;
  out->path_member_id = member_id;
  out->tls_verified = verified;
  return FTUN_OK;
}

static ftun_config_t *group_config(void)
{
  static const char json[] =
    "{\"dns\":{\"enable\":false},\"outbounds\":["
    "{\"name\":\"s1\",\"type\":\"socks5\",\"server\":\"192.0.2.1:1080\"},"
    "{\"name\":\"s2\",\"type\":\"socks5\",\"server\":\"192.0.2.2:1080\"},"
    "{\"name\":\"g1\",\"type\":\"select\",\"outbounds\":[\"s1\",\"s2\"],"
    "\"default\":\"s1\"},"
    "{\"name\":\"outer\",\"type\":\"select\",\"outbounds\":[\"g1\"],"
    "\"default\":\"g1\"},"
    "{\"name\":\"g2\",\"type\":\"select\","
    "\"outbounds\":[\"DIRECT\",\"s1\"],\"default\":\"DIRECT\","
    "\"dns-server\":\"inner-dns\"},"
    "{\"name\":\"outer2\",\"type\":\"select\","
    "\"outbounds\":[\"g2\"],\"default\":\"g2\","
    "\"dns-server\":\"outer-dns\"}],\"rules\":[\"MATCH,outer\"]}";
  ftun_bytes_t input;
  ftun_config_t *config = NULL;
  ftun_feature_plan_t *plan = NULL;
  ftun_diagnostic_t diagnostic;
  input.data = (const uint8_t *)json;
  input.length = strlen(json);
  if (ftun_config_parse(input, &config) != FTUN_OK || config == NULL ||
      ftun_config_validate(config, &diagnostic) != FTUN_OK ||
      ftun_config_compile(config, &plan) != FTUN_OK || plan == NULL) {
    (void)ftun_config_destroy(&config);
    return NULL;
  }
  config->plan = plan;
  return config;
}

int main(void)
{
  const uint32_t members[] = {10u, 20u, 30u};
  ftun_select_state_t select;
  ftun_group_choice_t choice;
  ftun_group_spec_t group;
  ftun_health_snapshot_t snapshot;
  ftun_health_sample_t samples[3];
  ftun_health_schedule_t schedule;
  ftun_budget_t *budget = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_core_t *core = NULL;
  ftun_config_t *config = NULL;
  ftun_runtime_t *candidate = NULL;
  ftun_runtime_t *runtime = NULL;
  ftun_operation_t *operation = NULL;
  ftun_probe_request_t probe;
  ftun_health_sample_t probe_sample;
  completion_state_t completion;
  size_t dispatched = 0u;
  bool verified = false;
  {
    const uint32_t direct_members[] = {0u, 10u};
    CHECK(ftun_select_state_init(&select, 6u, 4u, direct_members, 2u, 0u) ==
          FTUN_OK);
    CHECK(ftun_select_state_choice(&select, &choice) == FTUN_OK &&
          choice.leaf_id == 0u);
    CHECK(ftun_select_state_set(&select, 6u, 0u) == FTUN_OK);
  }
  CHECK(ftun_select_state_init(&select, 7u, 5u, members, 3u, 20u) == FTUN_OK);
  CHECK(ftun_select_state_choice(&select, &choice) == FTUN_OK &&
        choice.generation == 7u && choice.leaf_id == 20u);
  CHECK(ftun_select_state_set(&select, 6u, 10u) == FTUN_E_STALE);
  CHECK(ftun_select_state_set(&select, 7u, 99u) == FTUN_E_REJECTED);
  CHECK(ftun_select_state_set(&select, 7u, 10u) == FTUN_OK);
  memset(&group, 0, sizeof(group));
  group.generation = 7u;
  group.group_id = 5u;
  group.members = members;
  group.member_count = 3u;
  group.default_member_id = 20u;
  group.previous_member_id = 10u;
  group.previous_since_ms = 900u;
  group.now_ms = 1000u;
  group.sample_max_age_ms = 500u;
  group.minimum_hold_ms = 200u;
  group.tolerance_ms = 10u;
  memset(samples, 0, sizeof(samples));
  samples[0].member_id = 10u; samples[0].success = true;
  samples[0].latency_ms = 100u; samples[0].observed_ms = 999u;
  samples[1].member_id = 20u; samples[1].success = true;
  samples[1].latency_ms = 50u; samples[1].observed_ms = 999u;
  samples[2].member_id = 30u; samples[2].success = false;
  snapshot.generation = 7u;
  snapshot.samples = samples;
  snapshot.sample_count = 3u;
  CHECK(ftun_url_test_choose(&group, &snapshot, &choice) == FTUN_OK);
  CHECK(choice.leaf_id == 10u && !choice.degraded); /* 最短保持时间。 */
  group.now_ms = 1200u;
  CHECK(ftun_url_test_choose(&group, &snapshot, &choice) == FTUN_OK);
  CHECK(choice.leaf_id == 20u);
  samples[0].success = false; samples[1].success = false;
  CHECK(ftun_url_test_choose(&group, &snapshot, &choice) == FTUN_OK);
  CHECK(choice.leaf_id == 10u && choice.degraded);
  memset(&schedule, 0, sizeof(schedule));
  schedule.consumers = 1u;
  CHECK(ftun_health_schedule(&schedule, 100u, 1000u, 8000u, 5u,
                             false) == FTUN_OK);
  CHECK(schedule.failures == 1u && schedule.next_due_ms >= 2100u);
  schedule.consumers = 0u;
  CHECK(ftun_health_schedule(&schedule, 200u, 1000u, 8000u, 5u,
                             false) == FTUN_OK);
  CHECK(schedule.next_due_ms == 0u && schedule.failures == 0u);

  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 4u, &operations) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 1u, &core) == FTUN_OK);
  memset(&probe, 0, sizeof(probe));
  memset(&completion, 0, sizeof(completion));
  probe.generation = 1u;
  probe.member_id = 2u;
  probe.url.data = "https://probe.example/204";
  probe.url.length = strlen(probe.url.data);
  probe.expected_status = 204u;
  probe.now_ms = 100u;
  probe.deadline_ms = 200u;
  probe.operations = operations;
  probe.completion = completed;
  probe.completion_user = &completion;
  probe.perform = perform_probe;
  probe.perform_user = &verified;
  probe.sample = &probe_sample;
  CHECK(ftun_health_probe(core, &probe, &operation) == FTUN_OK &&
        operation != NULL && !probe_sample.success && probe_sample.tcp_only);
  CHECK(ftun_operation_dispatch(operations, 1u, &dispatched) == FTUN_OK &&
        dispatched == 1u && completion.calls == 1u &&
        completion.status == FTUN_E_REJECTED);
  verified = true;
  operation = NULL;
  CHECK(ftun_health_probe(core, &probe, &operation) == FTUN_OK &&
        probe_sample.success);
  CHECK(ftun_operation_dispatch(operations, 1u, &dispatched) == FTUN_OK &&
        completion.calls == 2u && completion.status == FTUN_OK);

  config = group_config();
  CHECK(config != NULL);
  CHECK(ftun_runtime_prepare(core, config, &candidate) == FTUN_OK);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(ftun_runtime_commit(core, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_active_acquire(core, &runtime) == FTUN_OK);
  CHECK(ftun_group_expand(runtime, 5u, &choice) == FTUN_OK &&
        choice.generation == 1u && choice.leaf_id == 2u);
  CHECK(ftun_select_set(core, 4u, 3u) == FTUN_OK);
  CHECK(ftun_group_expand(runtime, 5u, &choice) == FTUN_OK &&
        choice.leaf_id == 3u);
  CHECK(ftun_select_set(core, 4u, 99u) == FTUN_E_REJECTED);
  CHECK(ftun_group_expand(runtime, 7u, &choice) == FTUN_OK &&
        choice.leaf_id == 0u && choice.dns_server.length == 9u &&
        memcmp(choice.dns_server.data, "outer-dns", 9u) == 0);
  CHECK(ftun_select_set(core, 6u, 2u) == FTUN_OK);
  CHECK(ftun_group_expand(runtime, 7u, &choice) == FTUN_OK &&
        choice.leaf_id == 2u && choice.dns_server.length == 9u &&
        memcmp(choice.dns_server.data, "outer-dns", 9u) == 0);
  CHECK(ftun_runtime_release(&runtime) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(operations) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}
