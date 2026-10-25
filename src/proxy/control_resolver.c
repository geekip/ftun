#define _GNU_SOURCE 1

#include "proxy/control_resolver.h"

#include "proxy/dns/control_path_adapter.h"
#if defined(FTUN_HAVE_MODULE_DNS)
#include "dns/wire.h"
#endif
#include "proxy/outbound_id.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FTUN_CONTROL_DNS_RESPONSE_BYTES 4096u

static ftun_status_t ftun_control_copy(char *out, size_t capacity,
                                       const char *value)
{
  size_t length;
  if (out == NULL || capacity == 0u || value == NULL) return FTUN_E_INVALID;
  length = strlen(value);
  if (length >= capacity) return FTUN_E_LIMIT;
  memcpy(out, value, length + 1u);
  return FTUN_OK;
}

ftun_status_t ftun_control_parse_endpoint(
  const char *text, uint16_t default_port, ftun_endpoint_t *out,
  char domain[FTUN_CONTROL_ENDPOINT_TEXT_BYTES])
{
  const char *colon;
  char host[FTUN_CONTROL_ENDPOINT_TEXT_BYTES];
  char *tail = NULL;
  unsigned long port = default_port;
  size_t length;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (domain != NULL) domain[0] = '\0';
  if (text == NULL || text[0] == '\0' || default_port == 0u || out == NULL) {
    return FTUN_E_INVALID;
  }
  colon = strrchr(text, ':');
  length = colon == NULL ? strlen(text) : (size_t)(colon - text);
  if (length == 0u || length > 253u || length >= sizeof(host)) {
    return FTUN_E_INVALID;
  }
  memcpy(host, text, length);
  host[length] = '\0';
  if (colon != NULL) {
    errno = 0;
    port = strtoul(colon + 1u, &tail, 10);
    if (errno != 0 || tail == colon + 1u || *tail != '\0' ||
        port == 0u || port > UINT16_MAX) return FTUN_E_INVALID;
  }
  out->port = (uint16_t)port;
  if (inet_pton(AF_INET, host, out->address) == 1) {
    out->kind = FTUN_ADDRESS_IPV4;
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

static ftun_status_t ftun_control_outbound_id(const ftun_config_t *config,
                                               const char *name,
                                               uint32_t *out)
{
  size_t index;
  if (strcmp(name, "DIRECT") == 0) {
    *out = FTUN_OUTBOUND_ID_DIRECT;
    return FTUN_OK;
  }
  if (strcmp(name, "REJECT") == 0) {
    *out = FTUN_OUTBOUND_ID_REJECT;
    return FTUN_OK;
  }
  for (index = 0u; index < config->outbound_count; index++) {
    if (strcmp(config->outbounds[index].name, name) == 0) {
      if (index > UINT32_MAX - FTUN_OUTBOUND_ID_NAMED_BASE) {
        return FTUN_E_LIMIT;
      }
      *out = (uint32_t)index + FTUN_OUTBOUND_ID_NAMED_BASE;
      return FTUN_OK;
    }
  }
  return FTUN_E_REJECTED;
}

static ftun_status_t ftun_control_proxy_plan(
  const ftun_config_t *config, const ftun_runtime_t *runtime,
  const char *outbound, ftun_control_resolver_plan_t *plan)
{
  uint32_t current;
  size_t depth;
  ftun_status_t status = ftun_control_outbound_id(config, outbound, &current);
  for (depth = 0u; status == FTUN_OK && depth <= config->outbound_count;
       depth++) {
    const ftun_config_outbound_t *item;
    size_t index;
    if (current == FTUN_OUTBOUND_ID_DIRECT) return FTUN_OK;
    if (current == FTUN_OUTBOUND_ID_REJECT ||
        current < FTUN_OUTBOUND_ID_NAMED_BASE) return FTUN_E_REJECTED;
    index = current - FTUN_OUTBOUND_ID_NAMED_BASE;
    if (index >= config->outbound_count) return FTUN_E_STATE_CORRUPT;
    item = &config->outbounds[index];
    if (item->kind == FTUN_CONFIG_OUTBOUND_SOCKS5) {
      status = ftun_control_copy(plan->proxy, sizeof(plan->proxy),
                                 item->server);
      if (status == FTUN_OK && item->username != NULL) {
        status = ftun_control_copy(plan->proxy_username,
          sizeof(plan->proxy_username), item->username);
        if (status == FTUN_OK) status = ftun_control_copy(
          plan->proxy_password, sizeof(plan->proxy_password), item->password);
      }
      if (status == FTUN_OK) plan->use_proxy = true;
      return status;
    }
    if (runtime != NULL) {
      uint32_t selected = 0u;
      bool is_group = false;
      bool degraded = false;
      ftun_string_t dns_server;
      status = ftun_runtime_group_selected(runtime, current, &selected,
        &is_group, &degraded, &dns_server);
      (void)degraded;
      (void)dns_server;
      if (status == FTUN_OK && !is_group) status = FTUN_E_STATE_CORRUPT;
      if (status == FTUN_OK) current = selected;
    } else {
      status = ftun_control_outbound_id(config, item->default_member,
                                        &current);
    }
  }
  return status == FTUN_OK ? FTUN_E_STATE_CORRUPT : status;
}

ftun_status_t ftun_control_resolver_plan(
  const ftun_config_t *config, const ftun_runtime_t *runtime,
  ftun_string_t server, uint32_t socket_mark,
  ftun_control_resolver_plan_t *out)
{
  size_t index;
  ftun_status_t status = FTUN_OK;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (config == NULL || out == NULL ||
      (server.length != 0u && server.data == NULL)) return FTUN_E_INVALID;
  out->socket_mark = socket_mark;
  if (!config->dns.enable) return FTUN_OK;
  if (config->dns.bootstrap.count > FTUN_BOOTSTRAP_MAX_SERVERS) {
    return FTUN_E_LIMIT;
  }
  for (index = 0u; index < config->dns.bootstrap.count; index++) {
    char domain[FTUN_CONTROL_ENDPOINT_TEXT_BYTES];
    status = ftun_control_parse_endpoint(config->dns.bootstrap.items[index],
      53u, &out->bootstrap[index], domain);
    if (status != FTUN_OK || out->bootstrap[index].kind != FTUN_ADDRESS_IPV4) {
      return status == FTUN_OK ? FTUN_E_INVALID : status;
    }
    out->bootstrap_count++;
  }
  if (server.length == 0u) return FTUN_OK;
  for (index = 0u; index < config->dns.server_count; index++) {
    const ftun_config_dns_server_t *item = &config->dns.servers[index];
    if (strlen(item->name) != server.length ||
        memcmp(item->name, server.data, server.length) != 0) continue;
    if (item->addresses.count == 0u) return FTUN_E_STATE_CORRUPT;
    status = ftun_control_copy(out->upstream, sizeof(out->upstream),
                               item->addresses.items[0]);
    if (status == FTUN_OK) status = ftun_control_copy(out->name, sizeof(out->name), item->name);
    if (status == FTUN_OK) {
      out->named = true;
      out->tcp = strcmp(item->type, "tcp") == 0;
      status = ftun_control_proxy_plan(config, runtime, item->outbound, out);
    }
    return status;
  }
  return FTUN_E_REJECTED;
}

static ftun_status_t ftun_control_system(const ftun_control_execution_t *execution,
  ftun_string_t domain, uint16_t port,
                                         ftun_endpoint_t *out)
{
  char host[254];
  char service[6];
  struct addrinfo hints;
  struct addrinfo *results = NULL;
  struct addrinfo *cursor;
  if (domain.data == NULL || domain.length == 0u || domain.length > 253u) {
    return FTUN_E_INVALID;
  }
  memcpy(host, domain.data, domain.length);
  host[domain.length] = '\0';
  {
    struct in_addr numeric;
    if (inet_pton(AF_INET, host, &numeric) == 1) {
      memset(out, 0, sizeof(*out));
      out->kind = FTUN_ADDRESS_IPV4;
      out->port = port;
      memcpy(out->address, &numeric.s_addr, 4u);
      return FTUN_OK;
    }
  }
  if (!execution->allow_system_resolver) return FTUN_E_REJECTED;
  (void)snprintf(service, sizeof(service), "%u", (unsigned int)port);
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(host, service, &hints, &results) != 0) {
    return FTUN_E_RESOLVE;
  }
  for (cursor = results; cursor != NULL; cursor = cursor->ai_next) {
    if (cursor->ai_family == AF_INET && cursor->ai_addr != NULL &&
        cursor->ai_addrlen >= (socklen_t)sizeof(struct sockaddr_in)) {
      const struct sockaddr_in *address =
        (const struct sockaddr_in *)cursor->ai_addr;
      memset(out, 0, sizeof(*out));
      out->kind = FTUN_ADDRESS_IPV4;
      out->port = port;
      memcpy(out->address, &address->sin_addr.s_addr, 4u);
      freeaddrinfo(results);
      return FTUN_OK;
    }
  }
  freeaddrinfo(results);
  return FTUN_E_RESOLVE;
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
  const ftun_proxy_dns_blocking_query_t *transport,
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
  ftun_status_t status;
  (void)plan;
  status = ftun_control_encode_query(domain, id, query_wire,
    sizeof(query_wire), &query_length, &name_length);
  if (status == FTUN_OK) {
    status = ftun_proxy_dns_query_blocking(execution, transport,
      (ftun_bytes_t){query_wire, query_length}, response, sizeof(response),
      &response_length);
  }
  if (status == FTUN_OK) {
    status = ftun_dns_message_parse_with_budget(execution->budget,
      (ftun_bytes_t){response, response_length}, &message);
  }
  memset(&query, 0, sizeof(query));
  if (status == FTUN_OK) {
    query.id = id;
    query.transport = transport->direct.tcp ? FTUN_DNS_TRANSPORT_TCP :
                                              FTUN_DNS_TRANSPORT_UDP;
    query.upstream = transport->direct.upstream;
    query.question.name.data = query_wire + FTUN_DNS_HEADER_BYTES;
    query.question.name.length = name_length;
    query.question.type = 1u;
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
    if (record->section != FTUN_DNS_SECTION_ANSWER || record->type != 1u ||
        record->class_code != 1u || record->rdata.length != 4u) continue;
    memset(out, 0, sizeof(*out));
    out->kind = FTUN_ADDRESS_IPV4;
    out->port = port;
    memcpy(out->address, record->rdata.data, 4u);
    status = FTUN_OK;
  }
  (void)ftun_dns_message_release(&message);
  return status;
}
#else
static ftun_status_t ftun_control_dns_query(
  const ftun_control_execution_t *execution,
  const ftun_control_resolver_plan_t *plan,
  const ftun_proxy_dns_blocking_query_t *transport,
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
    status = ftun_control_system(execution, domain, port, out);
    /* libc 解析仍在阻塞工作线程；返回时检查期限，不交付已过期的结果。 */
    deadline_status = ftun_control_execution_limit(execution, UINT64_MAX, &checked);
    if (deadline_status != FTUN_OK) status = deadline_status;
    if (status != FTUN_OK) memset(out, 0, sizeof(*out));
    return status;
  }
  for (index = 0u; index < plan->bootstrap_count; index++) {
    ftun_proxy_dns_blocking_query_t query;
    memset(&query, 0, sizeof(query));
    query.direct.upstream = plan->bootstrap[index];
    query.direct.socket_mark = plan->socket_mark;
    status = ftun_control_dns_query(execution, plan, &query, domain, port, out);
    if (status == FTUN_OK) return FTUN_OK;
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
  if (parsed.kind == FTUN_ADDRESS_IPV4) {
    *out = parsed;
    return FTUN_OK;
  }
  return ftun_control_bootstrap(execution, plan, parsed.domain, parsed.port, out);
}

static ftun_status_t ftun_control_resolve_raw(
  const ftun_control_execution_t *execution,
  const ftun_control_resolver_plan_t *plan, ftun_string_t domain,
  uint16_t port, ftun_endpoint_t *out)
{
  ftun_proxy_dns_blocking_query_t query;
  ftun_endpoint_t upstream;
  ftun_endpoint_t proxy;
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (execution == NULL || plan == NULL ||
      plan->bootstrap_count > FTUN_BOOTSTRAP_MAX_SERVERS || domain.data == NULL || domain.length == 0u ||
      domain.length > 253u || port == 0u || out == NULL) return FTUN_E_INVALID;
  if (!plan->named) return ftun_control_bootstrap(execution, plan, domain, port, out);
  status = ftun_control_resolve_text(execution, plan, plan->upstream, 53u, &upstream);
  if (status != FTUN_OK) return status;
  memset(&query, 0, sizeof(query));
  query.direct.upstream = upstream;
  query.direct.socket_mark = plan->socket_mark;
  query.direct.tcp = plan->tcp;
  if (plan->use_proxy) {
    status = ftun_control_resolve_text(execution, plan, plan->proxy, 1u, &proxy);
    if (status != FTUN_OK) return status;
    query.use_proxy = true;
    query.proxy = proxy;
    if (plan->proxy_username[0] != '\0') {
      query.proxy_username.data = plan->proxy_username;
      query.proxy_username.length = strlen(plan->proxy_username);
      query.proxy_password.data = plan->proxy_password;
      query.proxy_password.length = strlen(plan->proxy_password);
    }
  }
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
  ftun_reservation_t *reservation;
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
  ftun_system_resolve_result_t result = {{state->domain, state->domain_length}, &state->endpoint, 1u};
  ftun_reservation_t *reservation = state->reservation;
  (void)ftun_event_source_cancel(&state->task);
  state->completion(operation, error, error.status == FTUN_OK ? &result : NULL, state->user);
  free(state);
  (void)ftun_reservation_release(&reservation);
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
  ftun_reservation_t *reservation = NULL;
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
  if (state == NULL) { (void)ftun_reservation_release(&reservation); return FTUN_E_LIMIT; }
  state->reservation = reservation;
  state->binding = *binding;
  state->binding.execution.budget = request->system.budget;
  state->binding.execution.deadline_ms = request->system.deadline_ms;
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
    (void)ftun_reservation_release(&reservation);
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
