#define _GNU_SOURCE 1

#include "dns/service_internal.h"
#include "util/ip.h"
#include "platform/sysresolve.h"

#if defined(FTUN_HAVE_MODULE_DNS)

ftun_status_t ftun_dns_runtime_parse_endpoint(const char *text,
                                                     ftun_endpoint_t *out)
{
  ftun_host_port_t value;
  memset(out, 0, sizeof(*out));
  if (text == NULL || !ftun_host_port_split(text, strlen(text), &value) ||
      value.bracketed) return FTUN_E_INVALID;
  /* 不是 IPv4 字面量时由调用方按域名处理。 */
  if (!ftun_ipv4_parse(value.host, value.host_length, out->address)) {
    return FTUN_E_UNSUPPORTED;
  }
  out->port = value.has_port ? value.port : 53u;
  out->kind = FTUN_ADDRESS_IPV4;
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_bootstrap_endpoint(
  ftun_budget_t *budget, const ftun_config_t *config, ftun_endpoint_t *out)
{
  ftun_reservation_t reservation = {0};
  ftun_status_t status;
  if (config == NULL || out == NULL) return FTUN_E_INVALID;
  if (ftun_config_dns(config)->bootstrap.count != 0u) {
    return ftun_dns_runtime_parse_endpoint(ftun_config_dns(config)->bootstrap.items[0], out);
  }
  status = ftun_budget_reserve_resources(budget,
    (ftun_budget_resources_t){0u, 1u, 0u}, &reservation);
  if (status != FTUN_OK) return status;
  status = ftun_system_nameserver(out);
  (void)ftun_reservation_release(&reservation);
  return status;
}

ftun_status_t ftun_dns_runtime_encode_bootstrap_query(
  const char *domain, uint16_t query_id, uint8_t *wire, size_t capacity,
  size_t *out_length)
{
  size_t input = 0u;
  size_t output = FTUN_DNS_HEADER_BYTES;
  size_t length;
  if (out_length != NULL) *out_length = 0u;
  if (domain == NULL || wire == NULL || out_length == NULL ||
      (length = strlen(domain)) == 0u || length > 253u ||
      capacity < FTUN_DNS_HEADER_BYTES + 5u) return FTUN_E_INVALID;
  if (domain[length - 1u] == '.') length--;
  if (length == 0u) return FTUN_E_INVALID;
  memset(wire, 0, capacity);
  wire[0] = (uint8_t)(query_id >> 8u);
  wire[1] = (uint8_t)query_id;
  wire[2] = 0x01u;
  wire[5] = 0x01u;
  while (input < length) {
    size_t end = input;
    size_t label_length;
    while (end < length && domain[end] != '.') end++;
    label_length = end - input;
    if (label_length == 0u || label_length > 63u ||
        output + label_length + 1u > capacity) return FTUN_E_INVALID;
    wire[output++] = (uint8_t)label_length;
    while (input < end) {
      uint8_t byte = (uint8_t)domain[input++];
      if (byte >= (uint8_t)'A' && byte <= (uint8_t)'Z') byte += 32u;
      if (!((byte >= (uint8_t)'a' && byte <= (uint8_t)'z') ||
            (byte >= (uint8_t)'0' && byte <= (uint8_t)'9') ||
            byte == (uint8_t)'-')) return FTUN_E_INVALID;
      wire[output++] = byte;
    }
    input++;
  }
  if (output + 5u > capacity) return FTUN_E_LIMIT;
  wire[output++] = 0u;
  wire[output++] = 0u;
  wire[output++] = 1u;
  wire[output++] = 0u;
  wire[output++] = 1u;
  *out_length = output;
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_resolve_upstream(
  ftun_budget_t *budget, const ftun_config_t *config, const char *text, uint32_t socket_mark,
  ftun_endpoint_t *out)
{
  uint8_t query[FTUN_DNS_HEADER_BYTES + FTUN_DNS_MAX_NAME_BYTES + 4u];
  uint8_t response[FTUN_BOOTSTRAP_MAX_RESPONSE_BYTES];
  ftun_endpoint_t bootstrap;
  ftun_dns_message_t *message = NULL;
  ftun_host_port_t host_port;
  char domain[254];
  size_t domain_length;
  size_t query_length = 0u;
  size_t index;
  ptrdiff_t received;
  uint64_t deadline;
  int descriptor = -1;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_status_t status;
  if (config == NULL || text == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_dns_runtime_parse_endpoint(text, out);
  if (status == FTUN_OK) return FTUN_OK;
  if (status != FTUN_E_UNSUPPORTED) return status;
  /* UNSUPPORTED 只会出现在语法已通过之后，这里的拆分必然成功。 */
  if (!ftun_host_port_split(text, strlen(text), &host_port) ||
      host_port.host_length >= sizeof(domain)) return FTUN_E_INVALID;
  domain_length = host_port.host_length;
  memcpy(domain, host_port.host, domain_length);
  domain[domain_length] = '\0';
  status = ftun_dns_runtime_encode_bootstrap_query(domain, UINT16_C(0x4654),
    query, sizeof(query), &query_length);
  if (status != FTUN_OK) return status;
  status = ftun_dns_runtime_bootstrap_endpoint(budget, config, &bootstrap);
  if (status != FTUN_OK) return status;
  status = ftun_budget_reserve_resources(budget,
    (ftun_budget_resources_t){0u, 1u, 0u}, &reservation);
  if (status != FTUN_OK) return status;
  status = ftun_socket_connect_udp(&bootstrap, socket_mark, &descriptor);
  if (status != FTUN_OK) goto done;
  if (ftun_monotonic_now(&deadline) != FTUN_OK ||
      deadline > UINT64_MAX - FTUN_DNS_RUNTIME_TIMEOUT_MS) {
    status = FTUN_E_IO;
    goto done;
  }
  deadline += FTUN_DNS_RUNTIME_TIMEOUT_MS;
  if (!ftun_blocking_socket_wait(descriptor, FTUN_POLLER_WRITE, deadline) ||
      !ftun_blocking_socket_send_all(descriptor, query, query_length, deadline) ||
      !ftun_blocking_socket_wait(descriptor, FTUN_POLLER_READ, deadline)) {
    status = FTUN_E_TIMEOUT;
    goto done;
  }
  received = ftun_socket_receive_nowait(descriptor, response, sizeof(response), &status);
  if (received < 0) goto done;
  status = ftun_dns_message_parse_with_budget(budget,
    (ftun_bytes_t){response, (size_t)received}, &message);
  if (status != FTUN_OK) goto done;
  if (message->id != UINT16_C(0x4654) || (message->flags & 0x8000u) == 0u ||
      message->rcode != 0u || message->question.type != 1u ||
      message->question.class_code != 1u ||
      message->question.name.length + FTUN_DNS_HEADER_BYTES + 4u !=
        query_length ||
      memcmp(message->question.name.data, query + FTUN_DNS_HEADER_BYTES,
             message->question.name.length) != 0) {
    status = FTUN_E_PROTOCOL;
    goto done;
  }
  status = FTUN_E_RESOLVE;
  for (index = 0u; index < message->record_count; index++) {
    const ftun_dns_record_t *record = &message->records[index];
    if (record->section != FTUN_DNS_SECTION_ANSWER || record->type != 1u ||
        record->class_code != 1u || record->rdata.length != 4u) continue;
    memset(out, 0, sizeof(*out));
    out->kind = FTUN_ADDRESS_IPV4;
    out->port = host_port.has_port ? host_port.port : 53u;
    memcpy(out->address, record->rdata.data, 4u);
    status = FTUN_OK;
    break;
  }

done:
  (void)ftun_dns_message_release(&message);
  if (descriptor >= 0) (void)ftun_socket_close((ftun_native_socket_t)(unsigned int)descriptor);
  (void)ftun_reservation_release(&reservation);
  return status;
}

ftun_status_t ftun_dns_runtime_outbound_id(
  const ftun_config_t *config, const char *name, uint32_t *out);

ftun_status_t ftun_dns_runtime_proxy_visit(
  const ftun_config_t *config, uint32_t id, uint8_t *states, size_t depth)
{
  ftun_channel_config_t outbound_view;
  const ftun_channel_config_t *outbound;
  size_t index;
  size_t member;
  if (depth > 64u) return FTUN_E_LIMIT;
  if (id == FTUN_DNS_OUTBOUND_DIRECT || id == FTUN_DNS_OUTBOUND_REJECT) {
    return FTUN_OK;
  }
  index = (size_t)(id - FTUN_DNS_OUTBOUND_NAMED_BASE);
  if (index >= ftun_config_channel_count(config) || states == NULL) return FTUN_E_INVALID;
  if (states[index] == 1u) return FTUN_E_INVALID;
  if (states[index] >= 2u) return FTUN_OK;
  outbound_view = ftun_config_channel(config, index);
  outbound = &outbound_view;
  if (outbound->kind == FTUN_CHANNEL_CONFIG_SOCKS5) {
    states[index] = 2u;
    return FTUN_OK;
  }
  if ((outbound->kind != FTUN_CHANNEL_CONFIG_GROUP) ||
      outbound->members.count == 0u || outbound->members.items == NULL) {
    return FTUN_E_INVALID;
  }
  states[index] = 1u;
  for (member = 0u; member < outbound->members.count; member++) {
    uint32_t child;
    ftun_status_t status = ftun_dns_runtime_outbound_id(config,
      outbound->members.items[member], &child);
    if (status == FTUN_OK) {
      status = ftun_dns_runtime_proxy_visit(config, child, states, depth + 1u);
    }
    if (status != FTUN_OK) return status;
  }
  states[index] = 3u;
  return FTUN_OK;
}

ftun_status_t ftun_dns_runtime_proxy_dependencies(
  const ftun_config_t *config, uint8_t *needed)
{
  size_t index;
  if (ftun_config_channel_count(config) > UINT32_MAX - FTUN_DNS_OUTBOUND_NAMED_BASE ||
      (ftun_config_channel_count(config) != 0u && needed == NULL)) return FTUN_E_LIMIT;
  if (ftun_config_channel_count(config) != 0u) {
    memset(needed, 0, ftun_config_channel_count(config));
  }
  /* 只复用尚未发布的 valid 数组作为有界遍历状态，不另分配临时队列。
   * 全部实际 DNS server 均为根，所有组成员均展开，与当前选择无关。 */
  for (index = 0u; index < ftun_config_dns(config)->server_count; index++) {
    uint32_t root;
    ftun_status_t status = ftun_dns_runtime_outbound_id(config,
      ftun_config_dns(config)->servers[index].outbound, &root);
    if (status == FTUN_OK) {
      status = ftun_dns_runtime_proxy_visit(config, root, needed, 0u);
    }
    if (status != FTUN_OK) return status;
  }
  for (index = 0u; index < ftun_config_channel_count(config); index++) {
    needed[index] = needed[index] == 2u ? 1u : 0u;
  }
  return FTUN_OK;
}


#endif
