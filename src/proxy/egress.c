#include "proxy/egress_internal.h"
#include "util/endpoint.h"
#include "proxy/outbound_id.h"
#include "libs/resolver/config.h"
#include "platform/sysresolve.h"
#include "platform/clock.h"
#include "libs/transport/socket_path.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

static ftun_status_t named(const ftun_proxy_egress_t *plan,
  ftun_string_t name, uint32_t *out)
{
  size_t i;
  if (name.length == 6u && memcmp(name.data, "DIRECT", 6u) == 0) { *out = 0u; return FTUN_OK; }
  if (name.length == 6u && memcmp(name.data, "REJECT", 6u) == 0) { *out = 1u; return FTUN_OK; }
  for (i = 0u; i < plan->count; i++) {
    if (name.length == plan->nodes[i].name.length &&
        memcmp(name.data, plan->nodes[i].name.data, name.length) == 0) {
      *out = (uint32_t)i + FTUN_OUTBOUND_ID_NAMED_BASE;
      return FTUN_OK;
    }
  }
  return FTUN_E_REJECTED;
}

static ftun_status_t info(const ftun_proxy_egress_t *plan, uint32_t id,
  size_t depth, ftun_egress_info_t *out)
{
  const ftun_proxy_egress_node_t *node;
  size_t i;
  if (depth > 64u) return FTUN_E_INVALID;
  memset(out, 0, sizeof(*out));
  out->id = id;
  out->configuration_generation = plan->generation;
  out->provider_kind = "proxy";
  out->state = FTUN_EGRESS_STATE_AVAILABLE;
  if (id == 1u) { out->state = FTUN_EGRESS_STATE_UNAVAILABLE; return FTUN_OK; }
  if (id == 0u) {
    out->capabilities = FTUN_EGRESS_CAP_STREAM | FTUN_EGRESS_CAP_DATAGRAM;
    return FTUN_OK;
  }
  if (id - FTUN_OUTBOUND_ID_NAMED_BASE >= plan->count) return FTUN_E_REJECTED;
  node = &plan->nodes[id - FTUN_OUTBOUND_ID_NAMED_BASE];
  out->resolver = node->resolver;
  if (node->kind == FTUN_CONFIG_OUTBOUND_SOCKS5) {
    out->capabilities = FTUN_EGRESS_CAP_STREAM | FTUN_EGRESS_CAP_DOMAIN_TARGET |
      (node->proxy.udp_enabled ? FTUN_EGRESS_CAP_DATAGRAM : 0u);
    return FTUN_OK;
  }
  out->capabilities = FTUN_EGRESS_CAP_STREAM | FTUN_EGRESS_CAP_DATAGRAM | FTUN_EGRESS_CAP_DOMAIN_TARGET;
  for (i = 0u; i < node->member_count; i++) {
    ftun_egress_info_t member;
    ftun_status_t status = info(plan, node->members[i], depth + 1u, &member);
    if (status != FTUN_OK) return status;
    if (member.state != FTUN_EGRESS_STATE_UNAVAILABLE) out->capabilities &= member.capabilities;
  }
  return FTUN_OK;
}

static ftun_status_t resolve(const void *context, const ftun_config_t *config,
  ftun_string_t name, ftun_egress_info_t *out)
{
  const ftun_proxy_egress_t *plan = context;
  uint32_t id;
  ftun_status_t status;
  (void)config;
  status = named(plan, name, &id);
  return status == FTUN_OK ? info(plan, id, 0u, out) : status;
}

static ftun_status_t query(const void *context, uint32_t id,
  uint64_t generation, ftun_egress_info_t *out)
{
  const ftun_proxy_egress_t *plan = context;
  ftun_string_t resolver = {0};
  size_t depth;
  if (generation != plan->generation) return FTUN_E_STALE;
  for (depth = 0u; depth <= 64u; depth++) {
    const ftun_proxy_egress_node_t *node = NULL;
    ftun_status_t status;
    if (id >= FTUN_OUTBOUND_ID_NAMED_BASE) {
      if (id - FTUN_OUTBOUND_ID_NAMED_BASE >= plan->count) return FTUN_E_REJECTED;
      node = &plan->nodes[id - FTUN_OUTBOUND_ID_NAMED_BASE];
      if (resolver.length == 0u) resolver = node->resolver;
    }
    if (node == NULL || node->kind == FTUN_CONFIG_OUTBOUND_SOCKS5) {
      status = info(plan, id, 0u, out);
      if (status == FTUN_OK && resolver.length != 0u) out->resolver = resolver;
      return status;
    }
    if (plan->select == NULL) id = node->default_id;
    else {
      size_t i;
      uint32_t member;
      status = plan->select(plan->select_context, generation, id, &member);
      if (status != FTUN_OK) return status;
      for (i = 0u; i < node->member_count && node->members[i] != member; i++) {}
      if (i == node->member_count) return FTUN_E_REJECTED;
      id = member;
    }
  }
  return FTUN_E_INVALID;
}

static bool contains(const ftun_proxy_egress_t *plan, uint32_t root, uint32_t leaf)
{
  const ftun_proxy_egress_node_t *node;
  size_t i;
  if (root < FTUN_OUTBOUND_ID_NAMED_BASE) return root == leaf;
  if (root - FTUN_OUTBOUND_ID_NAMED_BASE >= plan->count) return false;
  node = &plan->nodes[root - FTUN_OUTBOUND_ID_NAMED_BASE];
  if (node->kind == FTUN_CONFIG_OUTBOUND_SOCKS5) return root == leaf;
  for (i = 0u; i < node->member_count; i++) {
    if (contains(plan, node->members[i], leaf)) return true;
  }
  return false;
}

static ftun_status_t validate(const void *context, uint32_t root,
  uint32_t leaf, uint64_t generation)
{
  const ftun_proxy_egress_t *plan = context;
  ftun_egress_info_t result;
  if (generation != plan->generation) return FTUN_E_STALE;
  if (!contains(plan, root, leaf) || info(plan, leaf, 0u, &result) != FTUN_OK ||
      (leaf >= FTUN_OUTBOUND_ID_NAMED_BASE &&
       plan->nodes[leaf - FTUN_OUTBOUND_ID_NAMED_BASE].kind != FTUN_CONFIG_OUTBOUND_SOCKS5)) return FTUN_E_REJECTED;
  return result.state == FTUN_EGRESS_STATE_UNAVAILABLE ? FTUN_E_REJECTED : FTUN_OK;
}

static ftun_status_t worker_query(const void *context, uint32_t id,
  uint64_t generation, ftun_egress_info_t *out)
{
  const ftun_proxy_egress_t *plan = context;
  if (generation != plan->generation) return FTUN_E_STALE;
  if (id >= FTUN_OUTBOUND_ID_NAMED_BASE &&
      (id - FTUN_OUTBOUND_ID_NAMED_BASE >= plan->count ||
       plan->nodes[id - FTUN_OUTBOUND_ID_NAMED_BASE].kind != FTUN_CONFIG_OUTBOUND_SOCKS5)) {
    return FTUN_E_REJECTED;
  }
  return info(plan, id, 0u, out);
}

static void retain(void *context)
{
  ftun_proxy_egress_t *plan = context;
  size_t previous = ftun_atomic_fetch_add_explicit(&plan->references, 1u, FTUN_MEMORY_RELAXED);
  assert(previous != 0u && previous != SIZE_MAX);
  (void)previous;
}

static void release(void *context)
{
  ftun_proxy_egress_t *plan = context;
  size_t previous = ftun_atomic_fetch_sub_explicit(&plan->references, 1u, FTUN_MEMORY_ACQ_REL);
  assert(previous != 0u);
  if (previous == 1u) {
    ftun_reservation_t reservation = plan->reservation;
    free(plan);
    ftun_reservation_release(&reservation);
  }
}

static ftun_string_t copy_text(char **cursor, const char *text)
{
  ftun_string_t result = {0};
  if (text != NULL) {
    result.length = strlen(text);
    memcpy(*cursor, text, result.length + 1u);
    result.data = *cursor;
    *cursor += result.length + 1u;
  }
  return result;
}

static ftun_status_t resolve_needed(ftun_proxy_egress_t *plan, uint32_t id, size_t depth)
{
  ftun_proxy_egress_node_t *node;
  ftun_status_t status = FTUN_OK;
  size_t i;
  if (id < FTUN_OUTBOUND_ID_NAMED_BASE) return FTUN_OK;
  if (depth > 64u || id - FTUN_OUTBOUND_ID_NAMED_BASE >= plan->count) return FTUN_E_INVALID;
  node = &plan->nodes[id - FTUN_OUTBOUND_ID_NAMED_BASE];
  if (node->kind == FTUN_CONFIG_OUTBOUND_SOCKS5) {
    ftun_control_execution_t execution = {0};
    ftun_control_resolver_plan_t bootstrap = plan->bootstrap;
    uint64_t now;
    if (node->resolved) return FTUN_OK;
    status = ftun_monotonic_now(&now);
    if (status != FTUN_OK) return status;
    execution.budget = plan->reservation.budget;
    execution.generation = 1u;
    execution.deadline_ms = now + 5000u;
    execution.purpose = FTUN_DIAL_PURPOSE_BOOTSTRAP;
    /* 配置准备沿用DNS首个Bootstrap；命名解析失败不能改走其他来源。 */
    if (bootstrap.bootstrap_count == 0u) {
      ftun_reservation_t descriptor = {0};
      status = ftun_budget_reserve_resources(execution.budget,
        (ftun_budget_resources_t){0u, 1u, 0u}, &descriptor);
      if (status == FTUN_OK) status = ftun_system_nameserver(&bootstrap.bootstrap[0]);
      ftun_reservation_release(&descriptor);
      if (status != FTUN_OK) return status;
    }
    bootstrap.bootstrap_count = 1u;
    status = ftun_control_resolve_bootstrap(&execution, &bootstrap,
      node->proxy.server.domain, node->proxy.server.port, &node->endpoint);
    if (status == FTUN_OK) node->resolved = true;
    return status;
  }
  for (i = 0u; status == FTUN_OK && i < node->member_count; i++) {
    status = resolve_needed(plan, node->members[i], depth + 1u);
  }
  return status;
}

ftun_status_t ftun_proxy_egress_prepare(ftun_budget_t *budget,
  const ftun_config_t *config, uint32_t mark, const ftun_egress_provider_t **out)
{
  ftun_proxy_egress_t *plan;
  ftun_reservation_t reservation = {0};
  ftun_config_resolver_t dns = ftun_config_resolver(config);
  size_t count = ftun_config_outbound_count(config), i, bytes = sizeof(*plan);
  size_t member_count = 0u, text_bytes = 0u;
  uint32_t *members;
  char *text;
  ftun_status_t status = FTUN_OK;
  *out = NULL;
  if (count > (SIZE_MAX - bytes) / sizeof(*plan->nodes) ||
      count > UINT32_MAX - FTUN_OUTBOUND_ID_NAMED_BASE) return FTUN_E_LIMIT;
  bytes += count * sizeof(*plan->nodes);
  for (i = 0u; i < count; i++) {
    const ftun_config_outbound_t *item = &ftun_config_outbounds(config)[i];
    member_count += item->members.count;
    text_bytes += strlen(item->name) + 1u;
    if (item->dns_server != NULL) text_bytes += strlen(item->dns_server) + 1u;
  }
  bytes += member_count * sizeof(*members) + text_bytes;
  status = ftun_budget_reserve(budget, bytes, &reservation);
  if (status != FTUN_OK) return status;
  plan = calloc(1u, bytes);
  if (plan == NULL) { ftun_reservation_release(&reservation); return FTUN_E_LIMIT; }
  plan->reservation = reservation;
  plan->physical.open = ftun_socket_path_open;
  plan->count = count;
  plan->nodes = (ftun_proxy_egress_node_t *)(plan + 1);
  members = (uint32_t *)(plan->nodes + count);
  text = (char *)(members + member_count);
  ftun_atomic_init(&plan->references, 1u);
  plan->provider = (ftun_egress_provider_t){resolve, query, ftun_proxy_egress_open, plan, retain, release, validate};
  plan->worker = (ftun_egress_provider_t){resolve, worker_query, ftun_proxy_egress_worker_open, plan, retain, release, validate};
  plan->bootstrap.socket_mark = mark;
  plan->bootstrap.ipv6 = dns.ipv6;
  for (i = 0u; i < count; i++) {
    const ftun_config_outbound_t *item = &ftun_config_outbounds(config)[i];
    ftun_proxy_egress_node_t *node = &plan->nodes[i];
    node->kind = item->kind;
    node->name = copy_text(&text, item->name);
    node->resolver = copy_text(&text, item->dns_server);
    node->members = members;
    node->member_count = item->members.count;
    members += node->member_count;
  }
  for (i = 0u; status == FTUN_OK && i < count; i++) {
    const ftun_config_outbound_t *item = &ftun_config_outbounds(config)[i];
    ftun_proxy_egress_node_t *node = &plan->nodes[i];
    size_t j;
    if (node->kind != FTUN_CONFIG_OUTBOUND_SOCKS5) {
      for (j = 0u; status == FTUN_OK && j < node->member_count; j++) {
        const char *name = item->members.items[j];
        status = named(plan, (ftun_string_t){name, strlen(name)}, &node->members[j]);
      }
      if (status == FTUN_OK && item->default_member != NULL) status = named(plan,
        (ftun_string_t){item->default_member, strlen(item->default_member)}, &node->default_id);
      continue;
    }
    status = ftun_control_parse_endpoint(item->server, 1u, &node->proxy.server, node->domain);
    node->proxy.udp_enabled = item->udp;
    node->proxy.username = (ftun_bytes_t){node->username, item->username == NULL ? 0u : strlen(item->username)};
    node->proxy.password = (ftun_bytes_t){node->password, item->password == NULL ? 0u : strlen(item->password)};
    if (node->proxy.username.length > 255u || node->proxy.password.length > 255u) { status = FTUN_E_LIMIT; break; }
    if (node->proxy.username.length != 0u) memcpy(node->username, item->username, node->proxy.username.length);
    if (node->proxy.password.length != 0u) memcpy(node->password, item->password, node->proxy.password.length);
    if (ftun_endpoint_is_ip(&node->proxy.server)) {
      node->endpoint = node->proxy.server;
      node->resolved = true;
    }
  }
  if (dns.bootstrap.count > FTUN_BOOTSTRAP_MAX_SERVERS) status = FTUN_E_LIMIT;
  for (i = 0u; status == FTUN_OK && i < dns.bootstrap.count; i++) {
    char domain[FTUN_CONTROL_ENDPOINT_TEXT_BYTES];
    status = ftun_control_parse_endpoint(dns.bootstrap.items[i], 53u,
      &plan->bootstrap.bootstrap[i], domain);
    if (status == FTUN_OK && !ftun_endpoint_is_ip(&plan->bootstrap.bootstrap[i])) status = FTUN_E_INVALID;
    if (status == FTUN_OK) plan->bootstrap.bootstrap_count++;
  }
  for (i = 0u; status == FTUN_OK && dns.enable && i < dns.server_count; i++) {
    const char *name = dns.servers[i].outbound;
    uint32_t id;
    status = named(plan, (ftun_string_t){name, strlen(name)}, &id);
    if (status == FTUN_OK) status = resolve_needed(plan, id, 0u);
  }
  if (status != FTUN_OK) { release(plan); return status; }
  plan->provider.validate = validate;
  plan->worker.validate = validate;
  *out = &plan->provider;
  return FTUN_OK;
}

void ftun_proxy_egress_bind(const ftun_egress_provider_t *provider,
  uint64_t generation, ftun_proxy_egress_select_fn select, void *context)
{
  ftun_proxy_egress_t *plan = provider->context;
  assert(plan->generation == 0u && generation != 0u);
  plan->generation = generation;
  plan->select = select;
  plan->select_context = context;
}

const ftun_egress_provider_t *ftun_proxy_egress_worker(const ftun_egress_provider_t *provider)
{
  const ftun_proxy_egress_t *plan = provider->context;
  return &plan->worker;
}

void ftun_proxy_egress_set_path(const ftun_egress_provider_t *provider,
  ftun_path_provider_ops_t ops, void *context)
{
  ftun_proxy_egress_t *plan = provider->context;
  plan->physical = ops;
  plan->physical_context = context;
}
