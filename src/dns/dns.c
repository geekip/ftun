#include "dns.h"

#include "core/runtime.h"

#include <stdlib.h>
#include <string.h>

/* 需求 REQ-DNS-001；任务 TASK-DNS-001；目标 0.3.0；验收 TEST-DNS-001。 */

struct ftun_dns_dispatcher {
  ftun_budget_t *budget;
  ftun_operation_queue_t *operations;
  ftun_dns_server_t **servers;
  ftun_fakeip_service_t *fakeip;
  ftun_dns_server_select_fn select_server;
  ftun_dns_named_server_select_fn select_named_server;
  void *select_user;
  ftun_reservation_t *reservation;
  size_t server_count;
  size_t inflight_local;
};

typedef struct {
  ftun_dns_dispatcher_t *dispatcher;
  ftun_operation_t *operation;
  ftun_reservation_t *reservation;
  ftun_dns_query_completion_fn completion;
  void *completion_user;
  uint8_t *wire;
  size_t wire_length;
} ftun_dns_local_context_t;

static int ftun_dns_query_request_valid(const ftun_dns_query_t *query)
{
  ftun_dns_message_t *message = NULL;
  ftun_status_t status;
  int valid;
  if (query == NULL || query->completion == NULL || query->wire.data == NULL ||
      query->wire.length < FTUN_DNS_HEADER_BYTES) return 0;
  status = ftun_dns_message_parse(query->wire, &message);
  if (status != FTUN_OK) return 0;
  valid = (message->flags & 0x8000u) == 0u && message->id == query->id &&
          message->question.type == query->question.type &&
          message->question.class_code == query->question.class_code;
  (void)ftun_dns_message_release(&message);
  return valid;
}

static ftun_status_t ftun_dns_name_domain(ftun_dns_name_t name,
                                          char output[254],
                                          size_t *out_length)
{
  size_t input = 0u;
  size_t cursor = 0u;
  if (out_length != NULL) *out_length = 0u;
  if (name.data == NULL || name.length == 0u || out_length == NULL) {
    return FTUN_E_INVALID;
  }
  while (input < name.length) {
    uint8_t length = name.data[input++];
    size_t index;
    if (length == 0u) {
      if (input != name.length || cursor == 0u) return FTUN_E_PROTOCOL;
      output[cursor] = '\0';
      *out_length = cursor;
      return FTUN_OK;
    }
    if (length > 63u || (size_t)length > name.length - input ||
        cursor + (cursor == 0u ? 0u : 1u) + length > 253u) {
      return FTUN_E_PROTOCOL;
    }
    if (cursor != 0u) output[cursor++] = '.';
    for (index = 0u; index < length; index++) {
      uint8_t value = name.data[input++];
      output[cursor++] = (char)value;
    }
  }
  return FTUN_E_PROTOCOL;
}

static void ftun_dns_local_completed(ftun_operation_t *operation,
                                     ftun_error_t error, void *user)
{
  ftun_dns_local_context_t *context = (ftun_dns_local_context_t *)user;
  ftun_dns_dispatcher_t *dispatcher = context->dispatcher;
  ftun_reservation_t *reservation = context->reservation;
  ftun_bytes_t response = {NULL, 0u};
  if (error.status == FTUN_OK) {
    response.data = context->wire;
    response.length = context->wire_length;
  }
  context->completion(operation, error, response, context->completion_user);
  if (dispatcher->inflight_local != 0u) dispatcher->inflight_local--;
  free(context);
  (void)ftun_reservation_release(&reservation);
}

static ftun_status_t ftun_dns_local_answer(ftun_dns_dispatcher_t *dispatcher,
                                           const ftun_dns_query_t *query,
                                           uint16_t rcode,
                                           int with_address,
                                           uint32_t address,
                                           ftun_operation_t **out)
{
  ftun_dns_local_context_t *context;
  ftun_reservation_t *reservation = NULL;
  size_t question_bytes = query->question.name.length + 4u;
  size_t wire_length = FTUN_DNS_HEADER_BYTES + question_bytes +
                       (with_address ? 16u : 0u);
  size_t bytes;
  uint16_t flags;
  uint8_t *cursor;
  ftun_status_t status;
  if (sizeof(*context) > SIZE_MAX - wire_length) return FTUN_E_LIMIT;
  bytes = sizeof(*context) + wire_length;
  status = ftun_budget_reserve(dispatcher->budget, bytes, &reservation);
  if (status != FTUN_OK) return status;
  context = (ftun_dns_local_context_t *)calloc(1u, bytes);
  if (context == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  context->dispatcher = dispatcher;
  context->reservation = reservation;
  context->completion = query->completion;
  context->completion_user = query->completion_user;
  context->wire = (uint8_t *)(context + 1);
  context->wire_length = wire_length;
  context->wire[0] = (uint8_t)(query->id >> 8u);
  context->wire[1] = (uint8_t)query->id;
  flags = (uint16_t)(0x8000u | (query->flags & 0x0110u) | (rcode & 0x0fu));
  context->wire[2] = (uint8_t)(flags >> 8u);
  context->wire[3] = (uint8_t)flags;
  context->wire[5] = 1u;
  context->wire[7] = with_address ? 1u : 0u;
  cursor = context->wire + FTUN_DNS_HEADER_BYTES;
  memcpy(cursor, query->question.name.data, query->question.name.length);
  cursor += query->question.name.length;
  cursor[0] = (uint8_t)(query->question.type >> 8u);
  cursor[1] = (uint8_t)query->question.type;
  cursor[2] = (uint8_t)(query->question.class_code >> 8u);
  cursor[3] = (uint8_t)query->question.class_code;
  cursor += 4u;
  if (with_address) {
    cursor[0] = 0xc0u; cursor[1] = 0x0cu;
    cursor[2] = 0u; cursor[3] = 1u;
    cursor[4] = 0u; cursor[5] = 1u;
    cursor[9] = 60u;
    cursor[10] = 0u; cursor[11] = 4u;
    cursor[12] = (uint8_t)(address >> 24u);
    cursor[13] = (uint8_t)(address >> 16u);
    cursor[14] = (uint8_t)(address >> 8u);
    cursor[15] = (uint8_t)address;
  }
  status = ftun_operation_accept(dispatcher->operations,
    ftun_dns_local_completed, context, &context->operation);
  if (status != FTUN_OK) {
    free(context);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  dispatcher->inflight_local++;
  *out = context->operation;
  return ftun_operation_complete(context->operation,
                                  (ftun_error_t){FTUN_OK, 0u, 0});
}

ftun_status_t ftun_dns_dispatcher_create(
  const ftun_dns_dispatcher_options_t *options, ftun_dns_dispatcher_t **out)
{
  ftun_dns_dispatcher_t *dispatcher;
  ftun_reservation_t *reservation = NULL;
  size_t bytes;
  size_t index;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (options == NULL || options->budget == NULL ||
      options->operations == NULL || options->servers == NULL ||
      options->server_count == 0u || options->server_count > UINT32_MAX ||
      options->server_count > SIZE_MAX / sizeof(ftun_dns_server_t *) ||
      options->select_server == NULL || out == NULL) return FTUN_E_INVALID;
  bytes = sizeof(*dispatcher) +
          options->server_count * sizeof(ftun_dns_server_t *);
  status = ftun_budget_reserve(options->budget, bytes, &reservation);
  if (status != FTUN_OK) return status;
  dispatcher = (ftun_dns_dispatcher_t *)calloc(1u, bytes);
  if (dispatcher == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  dispatcher->servers = (ftun_dns_server_t **)(dispatcher + 1);
  for (index = 0u; index < options->server_count; index++) {
    if (options->servers[index] == NULL) {
      free(dispatcher);
      (void)ftun_reservation_release(&reservation);
      return FTUN_E_INVALID;
    }
    dispatcher->servers[index] = options->servers[index];
  }
  dispatcher->budget = options->budget;
  dispatcher->operations = options->operations;
  dispatcher->fakeip = options->fakeip;
  dispatcher->select_server = options->select_server;
  dispatcher->select_named_server = options->select_named_server;
  dispatcher->select_user = options->select_user;
  dispatcher->server_count = options->server_count;
  dispatcher->reservation = reservation;
  *out = dispatcher;
  return FTUN_OK;
}

ftun_status_t ftun_dns_dispatcher_get_info(
  const ftun_dns_dispatcher_t *dispatcher, ftun_dns_dispatcher_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (dispatcher == NULL || out == NULL) return FTUN_E_INVALID;
  out->server_count = dispatcher->server_count;
  out->inflight_local = dispatcher->inflight_local;
  return FTUN_OK;
}

ftun_status_t ftun_dns_dispatch(ftun_core_t *core,
                                const ftun_dns_query_t *query,
                                ftun_operation_t **out)
{
  ftun_dns_dispatcher_t *dispatcher = NULL;
  ftun_dns_server_info_t server_info;
  ftun_dns_query_t selected;
  size_t server_index;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (core == NULL || query == NULL || out == NULL ||
      !ftun_dns_query_request_valid(query)) return FTUN_E_INVALID;
  status = ftun_runtime_manager_dns(core, &dispatcher);
  if (status != FTUN_OK) return status;
  if (query->entry == FTUN_DNS_ENTRY_FIXED) {
    server_index = query->fixed_server;
  } else if (query->entry == FTUN_DNS_ENTRY_POLICY) {
    ftun_runtime_t *runtime = NULL;
    const ftun_route_table_t *table = NULL;
    ftun_route_result_t route;
    ftun_metadata_t metadata;
    if (query->real_only || query->metadata == NULL) return FTUN_E_INVALID;
    metadata = *query->metadata;
    metadata.known_fields &= ~(FTUN_META_PORT | FTUN_META_NETWORK);
    metadata.network = 0u;
    status = ftun_runtime_active_acquire(core, &runtime);
    if (status != FTUN_OK) return status;
    status = ftun_runtime_route_table(runtime, &table);
    if (status == FTUN_OK) {
      status = ftun_route_table_evaluate_known(table, &metadata, &route);
    }
    if (ftun_runtime_release(&runtime) != FTUN_OK && status == FTUN_OK) {
      status = FTUN_E_STATE_CORRUPT;
    }
    if (status != FTUN_OK) return status;
    if (route.kind == FTUN_ROUTE_DENY) {
      return ftun_dns_local_answer(dispatcher, query, 5u, 0, 0u, out);
    }
    if (route.kind != FTUN_ROUTE_READY) return FTUN_E_STATE_CORRUPT;
    status = dispatcher->select_server(route.outbound_id, &server_index,
                                       dispatcher->select_user);
    if (status != FTUN_OK) return status;
  } else {
    return FTUN_E_INVALID;
  }
  if (server_index >= dispatcher->server_count) return FTUN_E_INVALID;
  status = ftun_dns_server_get_info(dispatcher->servers[server_index],
                                    &server_info);
  if (status != FTUN_OK) return status;
  selected = *query;
  selected.server_fingerprint = server_info.fingerprint;
  selected.outbound_id = server_info.outbound_id;
  if (!query->real_only && server_info.fakeip && dispatcher->fakeip != NULL) {
    if (query->question.type == 1u) {
      char domain[254];
      size_t domain_length;
      ftun_fakeip_handle_t *handle = NULL;
      ftun_string_t ignored;
      uint32_t address;
      status = ftun_dns_name_domain(query->question.name, domain,
                                    &domain_length);
      if (status == FTUN_OK) {
        status = ftun_fakeip_service_acquire(dispatcher->fakeip,
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
  selected.resolution_mode = 1u;
  return ftun_dns_exchange(core, dispatcher->servers[server_index],
                           &selected, out);
}

typedef struct {
  ftun_reservation_t *reservation;
  ftun_system_resolve_completion_fn completion;
  void *completion_user;
  char domain[FTUN_SYSTEM_RESOLVER_MAX_DOMAIN_BYTES + 1u];
  size_t domain_length;
  ftun_endpoint_t addresses[FTUN_SYSTEM_RESOLVER_MAX_IPV4_RESULTS];
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
  ftun_reservation_t *reservation = context->reservation;
  size_t count = 0u;
  size_t index;
  memset(&result, 0, sizeof(result));
  result.domain.data = context->domain;
  result.domain.length = context->domain_length;
  if (error.status == FTUN_OK) {
    error.status = ftun_dns_message_parse(response, &message);
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
          record->kind != FTUN_DNS_RECORD_ORDINARY || record->type != 1u ||
          record->class_code != 1u || record->rdata.length != 4u) continue;
      for (previous = 0u; previous < count; previous++) {
        if (memcmp(context->addresses[previous].address,
                   record->rdata.data, 4u) == 0) duplicate = 1;
      }
      if (duplicate) continue;
      if (count >= FTUN_SYSTEM_RESOLVER_MAX_IPV4_RESULTS) {
        error.status = FTUN_E_LIMIT;
        break;
      }
      context->addresses[count].kind = FTUN_ADDRESS_IPV4;
      memcpy(context->addresses[count].address, record->rdata.data, 4u);
      count++;
    }
    if (error.status == FTUN_OK && count == 0u) error.status = FTUN_E_RESOLVE;
  }
  if (error.status == FTUN_OK) {
    result.addresses = context->addresses;
    result.address_count = count;
  }
  (void)ftun_dns_message_release(&message);
  context->completion(operation, error, &result, context->completion_user);
  free(context);
  (void)ftun_reservation_release(&reservation);
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

ftun_status_t ftun_dns_resolve_named(ftun_core_t *core, ftun_string_t server,
                                     const ftun_bootstrap_request_t *request,
                                     ftun_operation_t **out)
{
  ftun_dns_dispatcher_t *dispatcher = NULL;
  ftun_dns_named_context_t *context;
  ftun_reservation_t *reservation = NULL;
  ftun_dns_query_t query;
  uint8_t wire[FTUN_DNS_HEADER_BYTES + FTUN_DNS_MAX_NAME_BYTES + 4u];
  size_t wire_length;
  size_t name_length;
  size_t server_index;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (core == NULL || request == NULL || request->budget == NULL ||
      request->completion == NULL || out == NULL || server.data == NULL ||
      server.length == 0u) return FTUN_E_INVALID;
  status = ftun_runtime_manager_dns(core, &dispatcher);
  if (status != FTUN_OK) return status;
  if (dispatcher->select_named_server == NULL) return FTUN_E_UNSUPPORTED;
  status = dispatcher->select_named_server(server, &server_index,
                                           dispatcher->select_user);
  if (status != FTUN_OK) return status;
  if (server_index >= dispatcher->server_count) return FTUN_E_INVALID;
  status = ftun_dns_named_wire(request->domain, request->query_id, wire,
                               &wire_length, &name_length);
  if (status != FTUN_OK) return status;
  status = ftun_budget_reserve(request->budget, sizeof(*context), &reservation);
  if (status != FTUN_OK) return status;
  context = (ftun_dns_named_context_t *)calloc(1u, sizeof(*context));
  if (context == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  context->reservation = reservation;
  context->completion = request->completion;
  context->completion_user = request->user;
  context->domain_length = request->domain.length;
  memcpy(context->domain, request->domain.data, request->domain.length);
  context->domain[request->domain.length] = '\0';
  memset(&query, 0, sizeof(query));
  query.id = request->query_id;
  query.flags = 0x0100u;
  query.question.name.data = wire + FTUN_DNS_HEADER_BYTES;
  query.question.name.length = name_length;
  query.question.type = 1u;
  query.question.class_code = 1u;
  query.wire = (ftun_bytes_t){wire, wire_length};
  query.deadline_ms = request->deadline_ms;
  query.resolution_mode = 1u;
  query.completion = ftun_dns_named_completed;
  query.completion_user = context;
  query.entry = FTUN_DNS_ENTRY_FIXED;
  query.fixed_server = server_index;
  query.real_only = true;
  status = ftun_dns_exchange(core, dispatcher->servers[server_index],
                             &query, out);
  if (status != FTUN_OK) {
    free(context);
    (void)ftun_reservation_release(&reservation);
  }
  return status;
}

ftun_status_t ftun_dns_dispatcher_destroy(ftun_dns_dispatcher_t **dispatcher)
{
  ftun_dns_dispatcher_t *owned;
  ftun_reservation_t *reservation;
  if (dispatcher == NULL) return FTUN_E_INVALID;
  owned = *dispatcher;
  if (owned == NULL) return FTUN_OK;
  if (owned->inflight_local != 0u) return FTUN_E_AGAIN;
  reservation = owned->reservation;
  free(owned);
  *dispatcher = NULL;
  return ftun_reservation_release(&reservation);
}
