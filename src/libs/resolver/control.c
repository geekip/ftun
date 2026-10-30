#define _GNU_SOURCE 1

#include "util/endpoint.h"
#include "libs/resolver/control.h"
#include "platform/sysresolve.h"

#include "util/ip.h"

#if defined(FTUN_HAVE_MODULE_DNS)
#include "libs/resolver/dnswire.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FTUN_CONTROL_DNS_RESPONSE_BYTES 4096u

ftun_status_t ftun_control_parse_endpoint(
  const char *text, uint16_t default_port, ftun_endpoint_t *out,
  char domain[FTUN_CONTROL_ENDPOINT_TEXT_BYTES])
{
  ftun_host_port_t value;
  char host[FTUN_CONTROL_ENDPOINT_TEXT_BYTES];
  size_t length;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (domain != NULL) domain[0] = '\0';
  if (text == NULL || text[0] == '\0' || default_port == 0u || out == NULL) {
    return FTUN_E_INVALID;
  }
  if (!ftun_host_port_split(text, strlen(text), &value) ||
      value.host_length > 253u || value.host_length >= sizeof(host)) {
    return FTUN_E_INVALID;
  }
  length = value.host_length;
  memcpy(host, value.host, length);
  host[length] = '\0';
  out->port = value.has_port ? value.port : default_port;
  ftun_ip_t ip;
  if (ftun_ip_parse(host, length, &ip)) {
    ftun_endpoint_set_ip(out, &ip, out->port);
    return FTUN_OK;
  }
  if (domain == NULL) return FTUN_E_RESOLVE;
  {
    size_t start = 0u;
    size_t index;
    size_t effective = length;
    if (host[effective - 1u] == '.') effective--;
    if (effective == 0u) return FTUN_E_INVALID;
    for (index = 0u; index <= effective; index++) {
      if (index == effective || host[index] == '.') {
        size_t label = index - start;
        size_t cursor;
        if (label == 0u || label > 63u || host[start] == '-' ||
            host[index - 1u] == '-') return FTUN_E_INVALID;
        for (cursor = start; cursor < index; cursor++) {
          unsigned char byte = (unsigned char)host[cursor];
          if (!((byte >= 'a' && byte <= 'z') ||
                (byte >= 'A' && byte <= 'Z') ||
                (byte >= '0' && byte <= '9') || byte == '-')) {
            return FTUN_E_INVALID;
          }
        }
        start = index + 1u;
      }
    }
  }
  memcpy(domain, host, length + 1u);
  out->kind = FTUN_ADDRESS_DOMAIN;
  out->domain.data = domain;
  out->domain.length = length;
  return FTUN_OK;
}

static ftun_status_t ftun_control_system(const ftun_control_execution_t *execution,
  ftun_string_t domain, uint16_t port,
  ftun_endpoint_t *out, uint16_t query_type)
{
  char host[254];
  if (domain.data == NULL || domain.length == 0u || domain.length > 253u) {
    return FTUN_E_INVALID;
  }
  memcpy(host, domain.data, domain.length);
  host[domain.length] = '\0';
  {
    ftun_ip_t numeric;
    if (ftun_ip_parse(host, domain.length, &numeric)) {
      ftun_endpoint_set_ip(out, &numeric, port);
      return FTUN_OK;
    }
  }
  if (!execution->allow_system_resolver) return FTUN_E_REJECTED;
  return ftun_sysresolve_first(host, query_type == 28u ? FTUN_IP_V6 : FTUN_IP_V4, port, out);
}

#if defined(FTUN_HAVE_MODULE_DNS)
static ftun_status_t ftun_control_encode_query(
  ftun_string_t domain, uint16_t id, uint8_t *wire, size_t capacity,
  size_t *out_length, size_t *out_name_length)
{
  size_t input = 0u;
  size_t output = FTUN_DNS_HEADER_BYTES;
  size_t effective = domain.length;
  if (out_length != NULL) *out_length = 0u;
  if (out_name_length != NULL) *out_name_length = 0u;
  if (domain.data == NULL || effective == 0u || effective > 253u ||
      wire == NULL || capacity < FTUN_DNS_HEADER_BYTES + 5u ||
      out_length == NULL || out_name_length == NULL) return FTUN_E_INVALID;
  if (domain.data[effective - 1u] == '.') effective--;
  if (effective == 0u) return FTUN_E_INVALID;
  memset(wire, 0, capacity);
  wire[0] = (uint8_t)(id >> 8u);
  wire[1] = (uint8_t)id;
  wire[2] = 0x01u;
  wire[5] = 0x01u;
  while (input < effective) {
    size_t end = input;
    size_t length;
    while (end < effective && domain.data[end] != '.') end++;
    length = end - input;
    if (length == 0u || length > 63u ||
        output + length + 1u > capacity) return FTUN_E_INVALID;
    wire[output++] = (uint8_t)length;
    while (input < end) {
      uint8_t byte = (uint8_t)domain.data[input++];
      if (byte >= 'A' && byte <= 'Z') byte = (uint8_t)(byte + 32u);
      if (!((byte >= 'a' && byte <= 'z') ||
            (byte >= '0' && byte <= '9') || byte == '-')) {
        return FTUN_E_INVALID;
      }
      wire[output++] = byte;
    }
    input++;
  }
  if (output + 5u > capacity) return FTUN_E_LIMIT;
  wire[output++] = 0u;
  *out_name_length = output - FTUN_DNS_HEADER_BYTES;
  wire[output++] = 0u; wire[output++] = 1u;
  wire[output++] = 0u; wire[output++] = 1u;
  *out_length = output;
  return FTUN_OK;
}

static ftun_status_t ftun_control_dns_query(
  const ftun_control_execution_t *execution,
  const ftun_control_resolver_plan_t *plan,
  const ftun_dns_blocking_query_t *transport,
  ftun_string_t domain, uint16_t port, ftun_endpoint_t *out)
{
  uint8_t query_wire[FTUN_DNS_HEADER_BYTES + FTUN_DNS_MAX_NAME_BYTES + 4u];
  uint8_t response[FTUN_CONTROL_DNS_RESPONSE_BYTES];
  ftun_dns_message_t *message = NULL;
  ftun_dns_query_t query;
  bool matches = false;
  size_t query_length = 0u;
  size_t name_length = 0u;
  size_t response_length = 0u;
  size_t index;
  uint16_t id = UINT16_C(0x4654);
  size_t bytes = plan->query_type == 28u ? 16u : 4u;
  ftun_status_t status;
  status = ftun_control_encode_query(domain, id, query_wire,
    sizeof(query_wire), &query_length, &name_length);
  if (status == FTUN_OK) {
    query_wire[query_length - 3u] = plan->query_type == 28u ? 28u : 1u;
    status = ftun_dns_query_blocking(execution, transport,
      (ftun_bytes_t){query_wire, query_length}, response, sizeof(response), &response_length);
  }
  if (status == FTUN_OK) {
    status = ftun_dns_message_parse_with_budget(execution->budget,
      (ftun_bytes_t){response, response_length}, &message);
  }
  memset(&query, 0, sizeof(query));
  if (status == FTUN_OK) {
    query.id = id;
    query.transport = transport->tcp ? FTUN_DNS_TRANSPORT_TCP :
                                              FTUN_DNS_TRANSPORT_UDP;
    query.upstream = transport->upstream;
    query.question.name.data = query_wire + FTUN_DNS_HEADER_BYTES;
    query.question.name.length = name_length;
    query.question.type = plan->query_type == 28u ? 28u : 1u;
    query.question.class_code = 1u;
    status = ftun_dns_message_matches(message, &query, query.transport,
                                      &query.upstream, &matches);
    if (status == FTUN_OK && !matches) status = FTUN_E_PROTOCOL;
  }
  if (status == FTUN_OK && message->rcode != 0u) status = FTUN_E_RESOLVE;
  if (status == FTUN_OK) status = FTUN_E_RESOLVE;
  for (index = 0u; status == FTUN_E_RESOLVE && message != NULL &&
       message->rcode == 0u &&
       index < message->record_count; index++) {
    const ftun_dns_record_t *record = &message->records[index];
    if (record->section != FTUN_DNS_SECTION_ANSWER || record->type != (plan->query_type == 28u ? 28u : 1u) ||
        record->class_code != 1u || record->rdata.length != bytes) continue;
    memset(out, 0, sizeof(*out));
    out->kind = plan->query_type == 28u ? FTUN_ADDRESS_IPV6 : FTUN_ADDRESS_IPV4;
    out->port = port;
    memcpy(out->address, record->rdata.data, bytes);
    status = FTUN_OK;
  }
  ftun_dns_message_release(&message);
  return status;
}
#else
static ftun_status_t ftun_control_dns_query(
  const ftun_control_execution_t *execution,
  const ftun_control_resolver_plan_t *plan,
  const ftun_dns_blocking_query_t *transport,
  ftun_string_t domain, uint16_t port, ftun_endpoint_t *out)
{
  (void)plan;
  (void)execution;
  (void)transport;
  (void)domain;
  (void)port;
  (void)out;
  return FTUN_E_UNSUPPORTED;
}
#endif

static ftun_status_t ftun_control_bootstrap(
  const ftun_control_execution_t *execution,
  const ftun_control_resolver_plan_t *plan, ftun_string_t domain,
  uint16_t port, ftun_endpoint_t *out)
{
  size_t index;
  ftun_status_t status = FTUN_E_RESOLVE;
  ftun_control_execution_t checked;
  status = ftun_control_execution_limit(execution, UINT64_MAX, &checked);
  if (status != FTUN_OK) return status;
  if (plan->bootstrap_count == 0u) {
    ftun_status_t deadline_status;
    status = ftun_control_system(execution, domain, port, out, plan->query_type);
    /* libc 解析仍在阻塞工作线程；返回时检查期限，不交付已过期的结果。 */
    deadline_status = ftun_control_execution_limit(execution, UINT64_MAX, &checked);
    if (deadline_status != FTUN_OK) status = deadline_status;
    if (status != FTUN_OK) memset(out, 0, sizeof(*out));
    return status;
  }
  for (index = 0u; index < plan->bootstrap_count; index++) {
    ftun_dns_blocking_query_t query;
    memset(&query, 0, sizeof(query));
    query.upstream = plan->bootstrap[index];
    query.socket_mark = plan->socket_mark;
    status = ftun_control_dns_query(execution, plan, &query, domain, port, out);
    if (status == FTUN_OK || status == FTUN_E_PROTOCOL) return status;
  }
  return status;
}

static ftun_status_t ftun_control_resolve_text(
  const ftun_control_execution_t *execution,
  const ftun_control_resolver_plan_t *plan, const char *text,
  uint16_t default_port, ftun_endpoint_t *out)
{
  ftun_endpoint_t parsed;
  char domain[FTUN_CONTROL_ENDPOINT_TEXT_BYTES];
  ftun_status_t status = ftun_control_parse_endpoint(text, default_port,
                                                      &parsed, domain);
  if (status != FTUN_OK) return status;
  if (ftun_endpoint_is_ip(&parsed)) {
    *out = parsed;
    return FTUN_OK;
  }
  ftun_control_resolver_plan_t dependency = *plan;
  dependency.query_type = 1u;
  status = ftun_control_bootstrap(execution, &dependency, parsed.domain, parsed.port, out);
  if (status == FTUN_E_RESOLVE && plan->ipv6) {
    dependency.query_type = 28u;
    status = ftun_control_bootstrap(execution, &dependency, parsed.domain, parsed.port, out);
  }
  return status;
}

static ftun_status_t ftun_control_resolve_raw(
  const ftun_control_execution_t *execution,
  const ftun_control_resolver_plan_t *plan, ftun_string_t domain,
  uint16_t port, ftun_endpoint_t *out)
{
  ftun_dns_blocking_query_t query;
  ftun_endpoint_t upstream;
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (execution == NULL || plan == NULL ||
      plan->bootstrap_count > FTUN_BOOTSTRAP_MAX_SERVERS || domain.data == NULL || domain.length == 0u ||
      domain.length > 253u || port == 0u || out == NULL) return FTUN_E_INVALID;
  if (!plan->named) return ftun_control_bootstrap(execution, plan, domain, port, out);
  status = ftun_control_resolve_text(execution, plan, plan->upstream, 53u, &upstream);
  if (status != FTUN_OK) return status;
  memset(&query, 0, sizeof(query));
  query.upstream = upstream;
  query.socket_mark = plan->socket_mark;
  query.tcp = plan->tcp;
  query.egress_id = plan->egress_id;
  return ftun_control_dns_query(execution, plan, &query, domain, port, out);
}

/* 工厂只在现有控制工作线程的私有 owner 上使用；不向数据面 loop 投递
 * 阻塞工作，不为每个请求创建线程。计划和请求均在接纳前复制。 */
typedef struct {
  ftun_control_execution_t execution;
  ftun_control_resolver_plan_t plan;
} ftun_control_resolver_binding_t;

typedef struct {
  ftun_control_resolver_binding_t binding;
  ftun_reservation_t reservation;
  ftun_event_source_t *task;
  ftun_operation_token_t token;
  ftun_system_resolve_completion_fn completion;
  void *user;
  ftun_endpoint_t endpoint;
  char domain[FTUN_SYSTEM_RESOLVER_MAX_DOMAIN_BYTES + 1u];
  size_t domain_length;
  ftun_status_t status;
  bool computed;
} ftun_control_resolution_t;

static ftun_status_t ftun_control_resolution_cancel(void *user)
{
  ftun_control_resolution_t *state = user;
  return ftun_event_source_cancel(&state->task);
}

static void ftun_control_resolution_completed(ftun_operation_t *operation,
  ftun_error_t error, void *user)
{
  ftun_control_resolution_t *state = user;
  ftun_system_resolve_result_t result = {{state->domain, state->domain_length}, &state->endpoint, 1u, 0u};
  ftun_reservation_t reservation = state->reservation;
  (void)ftun_event_source_cancel(&state->task);
  state->completion(operation, error, error.status == FTUN_OK ? &result : NULL, state->user);
  free(state);
  ftun_reservation_release(&reservation);
}

static void ftun_control_resolution_run(ftun_event_source_t *source,
  uint32_t events, void *user)
{
  ftun_control_resolution_t *state = user;
  ftun_status_t status;
  (void)source;
  (void)events;
  if (!state->computed) {
    state->status = ftun_control_resolve_raw(&state->binding.execution,
      &state->binding.plan, (ftun_string_t){state->domain, state->domain_length},
      1u, &state->endpoint);
    state->endpoint.port = 0u;
    state->computed = true;
  }
  status = ftun_operation_complete(state->token, (ftun_error_t){state->status, 0u, 0});
  /* 终结权未交出时保留全部输入/结果，由同一有界 task 重试，不重做查询。 */
  if (status != FTUN_OK) (void)ftun_event_task_ready(state->task);
}

static ftun_status_t ftun_control_resolver_start(void *context, ftun_core_t *core,
  const ftun_resolver_provider_request_t *request, ftun_operation_t **out)
{
  const ftun_control_resolver_binding_t *binding = context;
  ftun_control_resolution_t *state;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (binding == NULL || core == NULL || request == NULL || out == NULL ||
      request->loop == NULL || request->operations == NULL ||
      request->system.domain.length == 0u || request->system.domain.length > 253u ||
      request->system.domain.data == NULL || request->system.completion == NULL ||
      request->generation != binding->execution.generation ||
      request->purpose != binding->execution.purpose ||
      request->requested_domain != FTUN_DIAL_DOMAIN_UNDERLAY ||
      request->network_view != NULL) return FTUN_E_INVALID;
  if (request->source == FTUN_RESOLVER_NAMED &&
      (request->resolver_name.length != strlen(binding->plan.name) ||
       memcmp(request->resolver_name.data, binding->plan.name, request->resolver_name.length) != 0)) return FTUN_E_REJECTED;
  status = ftun_budget_reserve(request->system.budget, sizeof(*state), &reservation);
  if (status != FTUN_OK) return status;
  state = calloc(1u, sizeof(*state));
  if (state == NULL) { ftun_reservation_release(&reservation); return FTUN_E_LIMIT; }
  state->reservation = reservation;
  state->binding = *binding;
  state->binding.execution.budget = request->system.budget;
  state->binding.execution.deadline_ms = request->system.deadline_ms;
  state->binding.plan.query_type = request->system.query_type;
  state->binding.plan.named = request->source == FTUN_RESOLVER_NAMED;
  if (request->source != FTUN_RESOLVER_NAMED) {
    state->binding.plan.bootstrap_count = request->server_count;
    if (request->server_count != 0u) memcpy(state->binding.plan.bootstrap,
      request->servers, request->server_count * sizeof(*request->servers));
  }
  memcpy(state->domain, request->system.domain.data, request->system.domain.length);
  state->domain_length = request->system.domain.length;
  state->completion = request->system.completion;
  state->user = request->system.user;
  status = ftun_event_task_start(request->loop, ftun_control_resolution_run, state, &state->task);
  if (status == FTUN_OK) status = ftun_operation_accept(request->operations,
    ftun_control_resolution_completed, state, out, &state->token);
  if (status != FTUN_OK) {
    (void)ftun_event_source_cancel(&state->task);
    free(state);
    ftun_reservation_release(&reservation);
    return status;
  }
  status = ftun_operation_set_cancel_hook(*out, ftun_control_resolution_cancel, state);
  if (status == FTUN_OK) status = ftun_event_task_ready(state->task);
  if (status != FTUN_OK) (void)ftun_operation_complete(state->token, (ftun_error_t){status, 0u, 0});
  return FTUN_OK;
}

static ftun_status_t ftun_control_resolve_provider(
  const ftun_control_execution_t *execution,
  const ftun_control_resolver_plan_t *plan, ftun_string_t domain,
  uint16_t port, bool bootstrap, ftun_endpoint_t *out)
{
  ftun_control_resolver_binding_t binding;
  ftun_control_channel_t *channel = NULL;
  ftun_resolver_provider_request_t request = {0};
  ftun_resolver_provider_ops_t ops = {0};
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (execution == NULL || plan == NULL || out == NULL || domain.data == NULL ||
      domain.length == 0u || domain.length > 253u || port == 0u ||
      plan->bootstrap_count > FTUN_BOOTSTRAP_MAX_SERVERS) return FTUN_E_INVALID;
  binding.execution = *execution;
  binding.plan = *plan;
  request.generation = execution->generation;
  request.purpose = execution->purpose;
  request.requested_domain = FTUN_DIAL_DOMAIN_UNDERLAY;
  request.system.domain = domain;
  request.system.ipv6 = plan->ipv6;
  request.system.query_type = plan->query_type;
  request.system.protection.mark = plan->socket_mark;
  if (plan->named && !bootstrap) {
    request.source = FTUN_RESOLVER_NAMED;
    request.resolver_name = (ftun_string_t){plan->name, strlen(plan->name)};
  } else if (plan->bootstrap_count != 0u) {
    request.source = FTUN_RESOLVER_BOOTSTRAP;
    request.servers = plan->bootstrap;
    request.server_count = plan->bootstrap_count;
  } else request.source = FTUN_RESOLVER_SYSTEM;
  ops.start = ftun_control_resolver_start;
  status = ftun_control_channel_create_execution(execution, &channel);
  if (status == FTUN_OK) status = ftun_control_channel_resolve(channel, &ops,
    &binding, &request, out);
  ftun_control_channel_drain(&channel);
  if (status == FTUN_OK) out->port = port;
  return status;
}

ftun_status_t ftun_control_resolve(const ftun_control_execution_t *execution,
  const ftun_control_resolver_plan_t *plan, ftun_string_t domain,
  uint16_t port, ftun_endpoint_t *out)
{
  return ftun_control_resolve_provider(execution, plan, domain, port, false, out);
}

ftun_status_t ftun_control_resolve_bootstrap(const ftun_control_execution_t *execution,
  const ftun_control_resolver_plan_t *plan, ftun_string_t domain,
  uint16_t port, ftun_endpoint_t *out)
{
  return ftun_control_resolve_provider(execution, plan, domain, port, true, out);
}
