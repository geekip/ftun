#include "frs_fixture.h"

#include "core/limits.h"
#include "core/operation.h"
#include "proxy/runtime_state.h"
#include "proxy/frs/domain.h"
#include "proxy/frs/frs.h"
#include "proxy/outbound/group/health.h"
#include "proxy/outbound/group/url_test.h"
#include "proxy/inbound/mixed.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "v0.4 integration failed: %s\n", #x); return 1; \
} } while (0)

typedef struct {
  size_t calls;
  ftun_status_t status;
} completion_t;

static ftun_bytes_t raw(const void *data, size_t length)
{
  return (ftun_bytes_t){(const uint8_t *)data, length};
}

static ftun_string_t text(const char *value)
{
  return (ftun_string_t){value, strlen(value)};
}

static void completed(ftun_operation_t *operation, ftun_error_t error,
                      void *user)
{
  completion_t *completion = (completion_t *)user;
  (void)operation;
  completion->calls++;
  completion->status = error.status;
}

static ftun_status_t perform_unverified_https(
  void *user, ftun_string_t url, uint32_t member_id,
  uint64_t deadline_ms, ftun_probe_result_t *out)
{
  (void)user;
  (void)url;
  memset(out, 0, sizeof(*out));
  out->http_status = 204u;
  out->latency_ms = 7u;
  out->finished_ms = deadline_ms - 1u;
  out->path_member_id = member_id;
  out->tls_verified = false;
  return FTUN_OK;
}

int main(void)
{
  static const uint8_t username[] = {'u'};
  static const uint8_t password[] = {'p'};
  static const char request_text[] =
    "CONNECT api.example.org:443 HTTP/1.1\r\n"
    "Host: api.example.org:443\r\n"
    "Proxy-Authorization: Basic dTpw\r\n\r\n";
  const uint32_t members[] = {11u, 22u};
  uint8_t *fixture = NULL;
  size_t fixture_bytes = 0u;
  ftun_frs_view_t *view = NULL;
  ftun_frs_set_t *domain = NULL;
  ftun_inbound_user_t user;
  ftun_inbound_spec_t inbound;
  ftun_mixed_connection_t *mixed = NULL;
  ftun_mixed_event_t mixed_event;
  ftun_group_spec_t group;
  ftun_health_sample_t failed_samples[2];
  ftun_health_snapshot_t health;
  ftun_group_choice_t choice;
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_operation_queue_t *operations = NULL;
  ftun_operation_t *operation = NULL;
  completion_t completion;
  ftun_probe_request_t probe;
  ftun_health_sample_t probe_sample;
  size_t consumed = 0u;
  size_t dispatched = 0u;
  bool matched = false;

  CHECK(ftun_test_frs_fixture(&fixture, &fixture_bytes));
  CHECK(ftun_frs_open_bytes(raw(fixture, fixture_bytes), &view) == FTUN_OK);
  CHECK(ftun_frs_bind(view, FTUN_FRS_SET_DOMAIN, text("CN"), &domain) == FTUN_OK);

  memset(&inbound, 0, sizeof(inbound));
  user.username = raw(username, sizeof(username));
  user.password = raw(password, sizeof(password));
  inbound.kind = FTUN_INBOUND_MIXED;
  inbound.tcp = true;
  inbound.udp = true;
  inbound.users = &user;
  inbound.user_count = 1u;
  CHECK(ftun_mixed_connection_create(&inbound, &mixed) == FTUN_OK);
  CHECK(ftun_mixed_connection_feed(mixed,
          raw(request_text, strlen(request_text)), &consumed,
          &mixed_event) == FTUN_OK &&
        mixed_event.kind == FTUN_MIXED_EVENT_HTTP_REQUEST);
  CHECK(ftun_frs_domain_contains(domain, mixed_event.http.target.domain,
                                 &matched) == FTUN_OK && matched);

  memset(&group, 0, sizeof(group));
  memset(failed_samples, 0, sizeof(failed_samples));
  group.generation = 9u;
  group.group_id = 8u;
  group.members = members;
  group.member_count = 2u;
  group.default_member_id = 11u;
  group.now_ms = 1000u;
  group.sample_max_age_ms = 500u;
  failed_samples[0].member_id = 11u;
  failed_samples[0].observed_ms = 999u;
  failed_samples[1].member_id = 22u;
  failed_samples[1].observed_ms = 999u;
  health.generation = 9u;
  health.samples = failed_samples;
  health.sample_count = 2u;
  CHECK(ftun_url_test_choose(&group, &health, &choice) == FTUN_OK &&
        choice.leaf_id == 11u && choice.degraded);
  CHECK(ftun_mixed_http_finish(mixed, FTUN_OK, &mixed_event) == FTUN_OK &&
        mixed_event.wire.length != 0u);
  CHECK(ftun_mixed_connection_destroy(&mixed) == FTUN_OK);

  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 1u, &core) == FTUN_OK);
  CHECK(ftun_operation_queue_create(budget, 4u, &operations) == FTUN_OK);
  memset(&completion, 0, sizeof(completion));
  memset(&probe, 0, sizeof(probe));
  probe.generation = 9u;
  probe.member_id = choice.leaf_id;
  probe.url = text("https://probe.example/204");
  probe.expected_status = 204u;
  probe.now_ms = 100u;
  probe.deadline_ms = 200u;
  probe.operations = operations;
  probe.completion = completed;
  probe.completion_user = &completion;
  probe.perform = perform_unverified_https;
  probe.sample = &probe_sample;
  CHECK(ftun_health_probe(core, &probe, &operation) == FTUN_OK &&
        operation != NULL && !probe_sample.success);
  CHECK(ftun_operation_dispatch(operations, 1u, &dispatched) == FTUN_OK &&
        dispatched == 1u && completion.calls == 1u &&
        completion.status == FTUN_E_REJECTED);

  CHECK(ftun_frs_set_release(&domain) == FTUN_OK);
  CHECK(ftun_frs_view_release(&view) == FTUN_OK);
  free(fixture);
  CHECK(ftun_operation_queue_stop(operations) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&operations) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}
