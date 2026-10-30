#include "proxy/fakeip/pool.h"
#include "app/composition/dns_dispatch.h"

#include "dns/dispatcher.h"
#include "proxy/dns/runtime_adapter.h"

/*
 * Proxy adapter 保持既有策略入口，DNS 原语不反向依赖 Proxy。 */

#if defined(FTUN_HAVE_MODULE_DNS)
#include "proxy/runtime_state.h"
#include "proxy/route/router.h"

#include <stdlib.h>
#include <string.h>

ftun_status_t ftun_proxy_dns_dispatch(
  void *user, ftun_core_t *core, ftun_dns_dispatcher_t *dispatcher,
  const ftun_dns_query_t *query, ftun_operation_t **out)
{
  const ftun_proxy_dns_runtime_adapter_t *adapter =
    (const ftun_proxy_dns_runtime_adapter_t *)user;
  ftun_fakeip_service_t *fakeip = NULL;
  ftun_dns_server_info_t server_info;
  ftun_dns_server_t *server = NULL;
  ftun_dns_query_t selected;
  size_t server_index;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (adapter == NULL || adapter->core == NULL ||
      core == NULL || core != adapter->core || query == NULL || out == NULL) return FTUN_E_INVALID;
  if (dispatcher == NULL) return FTUN_E_AGAIN;
  status = ftun_dns_dispatcher_validate(dispatcher, query);
  if (status != FTUN_OK) return status;
  if (adapter->fakeip_slot != NULL) fakeip = *adapter->fakeip_slot;
  if (query->entry == FTUN_DNS_ENTRY_FIXED) {
    server_index = query->fixed_server;
  } else if (query->entry == FTUN_DNS_ENTRY_POLICY) {
    ftun_runtime_t *runtime = NULL;
    const ftun_config_t *config = NULL;
    const ftun_route_table_t *table = NULL;
    ftun_route_result_t route;
    ftun_metadata_t metadata;
    if (query->real_only || query->metadata == NULL) return FTUN_E_INVALID;
    metadata = *query->metadata;
    metadata.known_fields &= ~(FTUN_META_PORT | FTUN_META_NETWORK);
    metadata.network = 0u;
    status = ftun_runtime_active_acquire(core, &runtime);
    if (status != FTUN_OK) return status;
    status = ftun_runtime_config(runtime, &config);
    if (status == FTUN_OK &&
        config != ftun_dns_dispatcher_config_scope(dispatcher)) {
      status = FTUN_E_STALE;
    }
    if (status == FTUN_OK) status = ftun_runtime_route_table(runtime, &table);
    if (status == FTUN_OK) {
      status = ftun_route_table_evaluate_known(table, &metadata, &route);
    }
    if (status == FTUN_OK && route.kind == FTUN_ROUTE_READY) {
      status = ftun_dns_dispatcher_select(dispatcher, route.outbound_id,
                                          &server_index);
    }
    if (ftun_runtime_release(&runtime) != FTUN_OK && status == FTUN_OK) {
      status = FTUN_E_STATE_CORRUPT;
    }
    if (status != FTUN_OK) return status;
    if (route.kind == FTUN_ROUTE_DENY) {
      return ftun_dns_local_answer(dispatcher, query, 5u, 0, 0u, out);
    }
    if (route.kind != FTUN_ROUTE_READY) return FTUN_E_STATE_CORRUPT;
  } else {
    return FTUN_E_INVALID;
  }
  status = ftun_dns_dispatcher_server(dispatcher, server_index, &server);
  if (status != FTUN_OK) return status;
  status = ftun_dns_server_get_info(server, &server_info);
  if (status != FTUN_OK) return status;
  selected = *query;
  selected.server_fingerprint = server_info.fingerprint;
  selected.outbound_id = server_info.outbound_id;
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  if (!query->real_only && server_info.fakeip && fakeip != NULL) {
    if (query->question.type == 1u) {
      char domain[254];
      size_t domain_length;
      ftun_fakeip_handle_t *handle = NULL;
      ftun_string_t ignored;
      uint32_t address;
      status = ftun_dns_name_domain(query->question.name, domain,
                                    &domain_length);
      if (status == FTUN_OK) {
        status = ftun_fakeip_service_acquire(fakeip,
          (ftun_string_t){domain, domain_length}, &handle);
      }
      if (status != FTUN_OK) {
        return ftun_dns_local_answer(dispatcher, query, 2u, 0, 0u, out);
      }
      status = ftun_fakeip_handle_get(handle, &address, &ignored);
      if (ftun_fakeip_handle_release(&handle) != FTUN_OK && status == FTUN_OK) {
        status = FTUN_E_STATE_CORRUPT;
      }
      if (status != FTUN_OK) return status;
      return ftun_dns_local_answer(dispatcher, query, 0u, 1, address, out);
    }
    if (query->question.type == 28u || query->question.type == 64u ||
        query->question.type == 65u) {
      return ftun_dns_local_answer(dispatcher, query, 0u, 0, 0u, out);
    }
  }
#endif
  selected.resolution_mode = 1u;
  return ftun_dns_exchange(core, server, &selected, out);
}

typedef struct {
  ftun_reservation_t reservation;
  ftun_budget_t *budget;
  ftun_system_resolve_completion_fn completion;
  void *completion_user;
  char domain[FTUN_SYSTEM_RESOLVER_MAX_DOMAIN_BYTES + 1u];
  size_t domain_length;
  uint16_t query_type;
  ftun_endpoint_t addresses[FTUN_SYSTEM_RESOLVER_MAX_RESULTS];
} ftun_dns_named_context_t;

static ftun_status_t ftun_dns_named_status(uint16_t rcode)
{
  if (rcode == 0u) return FTUN_OK;
  if (rcode == 3u) return FTUN_E_RESOLVE;
  if (rcode == 4u || rcode == 16u) return FTUN_E_UNSUPPORTED;
  if (rcode == 5u) return FTUN_E_REJECTED;
  if (rcode == 1u) return FTUN_E_PROTOCOL;
  return FTUN_E_IO;
}

static void ftun_dns_named_completed(ftun_operation_t *operation,
                                     ftun_error_t error,
                                     ftun_bytes_t response, void *user)
{
  ftun_dns_named_context_t *context = (ftun_dns_named_context_t *)user;
  ftun_dns_message_t *message = NULL;
  ftun_system_resolve_result_t result;
  ftun_reservation_t reservation = context->reservation;
  size_t bytes = context->query_type == 28u ? 16u : 4u;
  size_t count = 0u;
  size_t index;
  memset(&result, 0, sizeof(result));
  result.domain.data = context->domain;
  result.domain.length = context->domain_length;
  if (error.status == FTUN_OK) {
    error.status = ftun_dns_message_parse_with_budget(context->budget, response, &message);
    error.stage = 3u;
  }
  if (error.status == FTUN_OK) {
    error.status = ftun_dns_named_status(message->rcode);
  }
  if (error.status == FTUN_OK) {
    for (index = 0u; index < message->record_count; index++) {
      const ftun_dns_record_t *record = &message->records[index];
      size_t previous;
      int duplicate = 0;
      if (record->section != FTUN_DNS_SECTION_ANSWER ||
          record->kind != FTUN_DNS_RECORD_ORDINARY || record->type != context->query_type ||
          record->class_code != 1u || record->rdata.length != bytes) continue;
      for (previous = 0u; previous < count; previous++) {
        if (memcmp(context->addresses[previous].address,
                   record->rdata.data, bytes) == 0) duplicate = 1;
      }
      if (duplicate) continue;
      if (count >= FTUN_SYSTEM_RESOLVER_MAX_RESULTS) {
        error.status = FTUN_E_LIMIT;
        break;
      }
      context->addresses[count].kind = context->query_type == 28u ? FTUN_ADDRESS_IPV6 : FTUN_ADDRESS_IPV4;
      memcpy(context->addresses[count].address, record->rdata.data, bytes);
      count++;
    }
    if (error.status == FTUN_OK && count == 0u) error.status = FTUN_E_RESOLVE;
  }
  if (error.status == FTUN_OK) {
    result.addresses = context->addresses;
    result.address_count = count;
  }
  ftun_dns_message_release(&message);
  context->completion(operation, error, &result, context->completion_user);
  free(context);
  ftun_reservation_release(&reservation);
}

static ftun_status_t ftun_dns_named_wire(ftun_string_t domain, uint16_t id,
                                         uint8_t *wire,
                                         size_t *out_length,
                                         size_t *out_name_length)
{
  size_t effective = domain.length;
  size_t input = 0u;
  size_t output = FTUN_DNS_HEADER_BYTES;
  if (out_length != NULL) *out_length = 0u;
  if (out_name_length != NULL) *out_name_length = 0u;
  if (domain.data == NULL || domain.length == 0u || domain.length > 254u ||
      out_length == NULL || out_name_length == NULL ||
      memchr(domain.data, '\0', domain.length) != NULL) return FTUN_E_INVALID;
  if (domain.data[effective - 1u] == '.') effective--;
  if (effective == 0u || effective > 253u) return FTUN_E_INVALID;
  memset(wire, 0, FTUN_DNS_HEADER_BYTES + FTUN_DNS_MAX_NAME_BYTES + 4u);
  wire[0] = (uint8_t)(id >> 8u);
  wire[1] = (uint8_t)id;
  wire[2] = 0x01u;
  wire[5] = 1u;
  while (input < effective) {
    size_t end = input;
    size_t length;
    while (end < effective && domain.data[end] != '.') end++;
    length = end - input;
    if (length == 0u || length > 63u ||
        output + length + 1u > FTUN_DNS_HEADER_BYTES +
                               FTUN_DNS_MAX_NAME_BYTES) return FTUN_E_INVALID;
    wire[output++] = (uint8_t)length;
    memcpy(wire + output, domain.data + input, length);
    output += length;
    input = end + 1u;
  }
  wire[output++] = 0u;
  *out_name_length = output - FTUN_DNS_HEADER_BYTES;
  wire[output++] = 0u; wire[output++] = 1u;
  wire[output++] = 0u; wire[output++] = 1u;
  *out_length = output;
  return FTUN_OK;
}

ftun_status_t ftun_proxy_dns_resolve_named_dispatcher(
  ftun_core_t *core, ftun_dns_dispatcher_t *dispatcher,
  ftun_string_t server, const ftun_bootstrap_request_t *request,
  ftun_operation_t **out)
{
  ftun_dns_named_context_t *context;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_dns_query_t query;
  uint8_t wire[FTUN_DNS_HEADER_BYTES + FTUN_DNS_MAX_NAME_BYTES + 4u];
  size_t wire_length;
  size_t name_length;
  size_t server_index;
  ftun_dns_server_t *upstream = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (core == NULL || request == NULL || request->budget == NULL ||
      request->completion == NULL || out == NULL || server.data == NULL ||
      server.length == 0u) return FTUN_E_INVALID;
  if (dispatcher == NULL) return FTUN_E_AGAIN;
  status = ftun_dns_dispatcher_select_named(dispatcher, server, &server_index);
  if (status != FTUN_OK) return status;
  status = ftun_dns_dispatcher_server(dispatcher, server_index, &upstream);
  if (status != FTUN_OK) return status;
  status = ftun_dns_named_wire(request->domain, request->query_id, wire,
                               &wire_length, &name_length);
  if (status != FTUN_OK) return status;
  status = ftun_budget_reserve(request->budget, sizeof(*context), &reservation);
  if (status != FTUN_OK) return status;
  context = (ftun_dns_named_context_t *)calloc(1u, sizeof(*context));
  if (context == NULL) {
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  context->reservation = reservation;
  context->budget = request->budget;
  context->completion = request->completion;
  context->completion_user = request->user;
  context->domain_length = request->domain.length;
  context->query_type = request->query_type == 28u ? 28u : 1u;
  memcpy(context->domain, request->domain.data, request->domain.length);
  context->domain[request->domain.length] = '\0';
  memset(&query, 0, sizeof(query));
  query.id = request->query_id;
  query.flags = 0x0100u;
  query.question.name.data = wire + FTUN_DNS_HEADER_BYTES;
  query.question.name.length = name_length;
  query.question.type = context->query_type;
  wire[wire_length - 3u] = (uint8_t)context->query_type;
  query.question.class_code = 1u;
  query.wire = (ftun_bytes_t){wire, wire_length};
  query.deadline_ms = request->deadline_ms;
  query.resolution_mode = 1u;
  query.completion = ftun_dns_named_completed;
  query.completion_user = context;
  query.entry = FTUN_DNS_ENTRY_FIXED;
  query.fixed_server = server_index;
  query.real_only = true;
  status = ftun_dns_exchange(core, upstream,
                             &query, out);
  if (status != FTUN_OK) {
    free(context);
    ftun_reservation_release(&reservation);
  }
  return status;
}

#endif
