#include "dns/internal.h"

#include <stdlib.h>
#include <string.h>

/* 需求 REQ-DNS-001；任务 TASK-DNS-001；目标 0.3.0；验收 TEST-DNS-001。 */

typedef struct {
  ftun_dns_dispatcher_t *dispatcher;
  ftun_operation_t *operation;
  ftun_operation_token_t completion_token;
  ftun_reservation_t *reservation;
  ftun_dns_query_completion_fn completion;
  void *completion_user;
  uint8_t *wire;
  size_t wire_length;
} ftun_dns_local_context_t;

ftun_status_t ftun_dns_query_request_validate(ftun_budget_t *budget, const ftun_dns_query_t *query)
{
  ftun_dns_message_t *message = NULL;
  ftun_status_t status;
  int valid;
  if (query == NULL || query->completion == NULL || query->wire.data == NULL ||
      query->wire.length < FTUN_DNS_HEADER_BYTES) return FTUN_E_INVALID;
  status = ftun_dns_message_parse_with_budget(budget, query->wire, &message);
  if (status != FTUN_OK) return status == FTUN_E_LIMIT ? status : FTUN_E_INVALID;
  valid = (message->flags & 0x8000u) == 0u && message->id == query->id &&
          message->question.type == query->question.type &&
          message->question.class_code == query->question.class_code;
  (void)ftun_dns_message_release(&message);
  return valid ? FTUN_OK : FTUN_E_INVALID;
}

ftun_status_t ftun_dns_name_domain(ftun_dns_name_t name,
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

ftun_status_t ftun_dns_local_answer(ftun_dns_dispatcher_t *dispatcher,
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
    ftun_dns_local_completed, context, &context->operation,
    &context->completion_token);
  if (status != FTUN_OK) {
    free(context);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  dispatcher->inflight_local++;
  *out = context->operation;
  return ftun_operation_complete(context->completion_token,
                                  (ftun_error_t){FTUN_OK, 0u, 0});
}

ftun_status_t ftun_dns_dispatch_fixed(void *user, ftun_core_t *core,
                                      ftun_dns_dispatcher_t *dispatcher,
                                      const ftun_dns_query_t *query,
                                      ftun_operation_t **out)
{
  ftun_dns_server_info_t server_info;
  ftun_dns_query_t selected;
  size_t server_index;
  ftun_status_t status;
  (void)user;
  if (out != NULL) *out = NULL;
  if (core == NULL || dispatcher == NULL || query == NULL || out == NULL ||
      query->entry != FTUN_DNS_ENTRY_FIXED) return FTUN_E_INVALID;
  status = ftun_dns_query_request_validate(dispatcher->budget, query);
  if (status != FTUN_OK) return status;
  server_index = query->fixed_server;
  if (server_index >= dispatcher->server_count) return FTUN_E_INVALID;
  status = ftun_dns_server_get_info(dispatcher->servers[server_index],
                                    &server_info);
  if (status != FTUN_OK) return status;
  selected = *query;
  selected.server_fingerprint = server_info.fingerprint;
  selected.outbound_id = server_info.outbound_id;
  if (!query->real_only && server_info.fakeip) return FTUN_E_UNSUPPORTED;
  selected.resolution_mode = 1u;
  return ftun_dns_exchange(core, dispatcher->servers[server_index],
                           &selected, out);
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
  dispatcher->config_scope = options->config_scope;
  dispatcher->operations = options->operations;
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
