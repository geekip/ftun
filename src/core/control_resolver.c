#define _GNU_SOURCE 1

#include "core/control_resolver.h"

#include "core/engine_dns.h"
#include "dns/wire.h"
#include "route/rule.h"

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
    if (status == FTUN_OK) {
      out->named = true;
      out->tcp = strcmp(item->type, "tcp") == 0;
      status = ftun_control_proxy_plan(config, runtime, item->outbound, out);
    }
    return status;
  }
  return FTUN_E_REJECTED;
}

static ftun_status_t ftun_control_system(ftun_string_t domain, uint16_t port,
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
  const ftun_control_resolver_plan_t *plan,
  const ftun_engine_dns_blocking_query_t *transport,
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
    status = ftun_engine_dns_query_blocking(transport,
      (ftun_bytes_t){query_wire, query_length}, response, sizeof(response),
      &response_length);
  }
  if (status == FTUN_OK) {
    status = ftun_dns_message_parse(
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
    query.question.type = 1u;
    query.question.class_code = 1u;
    status = ftun_dns_message_matches(message, &query, query.transport,
                                      &query.upstream, &matches);
    if (status == FTUN_OK && !matches) status = FTUN_E_PROTOCOL;
  }
  if (status == FTUN_OK && message->rcode != 0u) status = FTUN_E_RESOLVE;
  if (status == FTUN_OK) status = FTUN_E_RESOLVE;
  for (index = 0u; status == FTUN_E_RESOLVE && message != NULL &&
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

static ftun_status_t ftun_control_bootstrap(
  const ftun_control_resolver_plan_t *plan, ftun_string_t domain,
  uint16_t port, ftun_endpoint_t *out)
{
  size_t index;
  ftun_status_t status = FTUN_E_RESOLVE;
  if (plan->bootstrap_count == 0u) return ftun_control_system(domain, port, out);
  for (index = 0u; index < plan->bootstrap_count; index++) {
    ftun_engine_dns_blocking_query_t query;
    memset(&query, 0, sizeof(query));
    query.upstream = plan->bootstrap[index];
    query.socket_mark = plan->socket_mark;
    status = ftun_control_dns_query(plan, &query, domain, port, out);
    if (status == FTUN_OK) return FTUN_OK;
  }
  return status;
}

ftun_status_t ftun_control_resolve_bootstrap(
  const ftun_control_resolver_plan_t *plan, ftun_string_t domain,
  uint16_t port, ftun_endpoint_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (plan == NULL || domain.data == NULL ||
      domain.length == 0u || domain.length > 253u || port == 0u ||
      out == NULL) return FTUN_E_INVALID;
  return ftun_control_bootstrap(plan, domain, port, out);
}

static ftun_status_t ftun_control_resolve_text(
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
  return ftun_control_bootstrap(plan, parsed.domain, parsed.port, out);
}

ftun_status_t ftun_control_resolve(
  const ftun_control_resolver_plan_t *plan, ftun_string_t domain,
  uint16_t port, ftun_endpoint_t *out)
{
  ftun_engine_dns_blocking_query_t query;
  ftun_endpoint_t upstream;
  ftun_endpoint_t proxy;
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (plan == NULL || domain.data == NULL || domain.length == 0u ||
      domain.length > 253u || port == 0u || out == NULL) return FTUN_E_INVALID;
  if (!plan->named) return ftun_control_bootstrap(plan, domain, port, out);
  status = ftun_control_resolve_text(plan, plan->upstream, 53u, &upstream);
  if (status != FTUN_OK) return status;
  memset(&query, 0, sizeof(query));
  query.upstream = upstream;
  query.socket_mark = plan->socket_mark;
  query.tcp = plan->tcp;
  if (plan->use_proxy) {
    status = ftun_control_resolve_text(plan, plan->proxy, 1u, &proxy);
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
  return ftun_control_dns_query(plan, &query, domain, port, out);
}
