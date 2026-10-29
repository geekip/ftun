#include "proxy/outbound/direct.h"

#include "platform/socket.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  ftun_core_t *core;
  ftun_operation_t *operation;
  ftun_operation_token_t completion_token;
  ftun_operation_t *child;
  ftun_reservation_t reservation;
  ftun_event_loop_t *loop;
  ftun_operation_queue_t *operations;
  ftun_budget_t *budget;
  ftun_endpoint_t *allowed;
  size_t allowed_count;
  size_t next_candidate;
  ftun_network_view_t *network_view;
  uint64_t network_generation;
  ftun_dial_domain_t requested_domain;
  ftun_socket_policy_t protection;
  char interface_name[FTUN_SOCKET_INTERFACE_BYTES];
  uint64_t deadline_ms;
  ftun_dial_transport_t transport;
  ftun_dial_completion_fn completion;
  void *completion_user;
  ftun_dial_result_t result;
  ftun_dial_io_t io;
  ftun_path_scope_t *scope;
  ftun_path_t *path;
  ftun_stream_options_t stream;
  ftun_datagram_options_t datagram;
  ftun_path_completion_fn path_completion;
  ftun_path_notify_fn notify;
  void *notify_user;
  int custom_io;
  int cancelling;
} ftun_direct_context_t;

static ftun_error_t ftun_direct_error(ftun_status_t status, uint32_t stage)
{
  ftun_error_t error;
  memset(&error, 0, sizeof(error));
  error.status = status;
  error.stage = stage;
  return error;
}

static int ftun_direct_domain_valid(ftun_string_t domain)
{
  return domain.data != NULL && domain.length != 0u && domain.length <= 253u &&
         memchr(domain.data, '\0', domain.length) == NULL;
}

static int ftun_direct_endpoint_equal(const ftun_endpoint_t *left,
                                      const ftun_endpoint_t *right)
{
  return left->kind == FTUN_ADDRESS_IPV4 &&
         right->kind == FTUN_ADDRESS_IPV4 && left->port == right->port &&
         memcmp(left->address, right->address, 4u) == 0;
}

static int ftun_direct_contains(const ftun_endpoint_t *items, size_t count,
                                const ftun_endpoint_t *endpoint)
{
  size_t index;
  for (index = 0u; index < count; index++) {
    if (ftun_direct_endpoint_equal(&items[index], endpoint)) return 1;
  }
  return 0;
}

static ftun_status_t ftun_direct_target_validate(const ftun_target_t *target)
{
  size_t index;
  size_t previous;
  if (target == NULL || target->generation == 0u || target->original.port == 0u ||
      (target->candidate_count != 0u && target->candidates == NULL) ||
      (target->allowed_count != 0u && target->allowed == NULL) ||
      target->allowed_count > target->candidate_count) return FTUN_E_INVALID;
  if (target->original.kind != FTUN_ADDRESS_IPV4 &&
      target->original.kind != FTUN_ADDRESS_DOMAIN) return FTUN_E_INVALID;
  if (target->original.kind == FTUN_ADDRESS_DOMAIN &&
      !ftun_direct_domain_valid(target->original.domain)) return FTUN_E_INVALID;
  for (index = 0u; index < target->candidate_count; index++) {
    const ftun_endpoint_t *endpoint = &target->candidates[index];
    if (endpoint->kind != FTUN_ADDRESS_IPV4 || endpoint->port == 0u ||
        endpoint->port != target->original.port ||
        endpoint->domain.length != 0u) return FTUN_E_INVALID;
  }
  for (index = 0u; index < target->allowed_count; index++) {
    const ftun_endpoint_t *endpoint = &target->allowed[index];
    if (endpoint->kind != FTUN_ADDRESS_IPV4 || endpoint->port == 0u ||
        endpoint->domain.length != 0u) return FTUN_E_INVALID;
    if (!ftun_direct_contains(target->candidates, target->candidate_count,
                              endpoint)) return FTUN_E_REJECTED;
    for (previous = 0u; previous < index; previous++) {
      if (ftun_direct_endpoint_equal(&target->allowed[previous], endpoint)) {
        return FTUN_E_INVALID;
      }
    }
  }
  if (target->candidate_count == 0u) {
    return ftun_direct_domain_valid(target->identity) ? FTUN_E_RESOLVE :
                                                       FTUN_E_REJECTED;
  }
  if (target->allowed_count == 0u) return FTUN_E_REJECTED;
  return FTUN_OK;
}

static int ftun_direct_request_valid(const ftun_direct_request_t *request)
{
  if (request == NULL || request->loop == NULL ||
      request->operations == NULL || request->budget == NULL ||
      request->target == NULL ||
      (request->scope == NULL ? request->completion == NULL || request->path_completion != NULL
        : request->completion != NULL || request->path_completion == NULL) ||
      (request->transport != FTUN_DIAL_TCP &&
       request->transport != FTUN_DIAL_UDP)) return 0;
  if (request->protection.interface_name.length >=
      FTUN_SOCKET_INTERFACE_BYTES) return 0;
  if (request->protection.interface_name.length != 0u &&
      request->protection.interface_name.data == NULL) return 0;
  if (request->protection.mark == 0u &&
      request->protection.interface_name.length != 0u) return 0;
  return 1;
}

static int ftun_direct_io_valid(const ftun_dial_io_t *io)
{
  return io != NULL && io->open_socket != NULL && io->protect_socket != NULL &&
         io->connect_socket != NULL && io->get_socket_error != NULL &&
         io->close_socket != NULL;
}

static ftun_status_t ftun_direct_system_close(ftun_native_socket_t socket)
{
  return ftun_socket_close(socket);
}

static ftun_status_t ftun_direct_close_result(ftun_direct_context_t *context)
{
  ftun_status_t status;
  if (context->path != NULL) {
    status = ftun_path_revoke(context->path);
    if (status == FTUN_OK) status = ftun_path_destroy(&context->path);
    return status;
  }
  if (context->result.socket == FTUN_INVALID_SOCKET) return FTUN_OK;
  if (context->custom_io) {
    status = context->io.close_socket(context->io.context,
                                      context->result.socket);
  } else {
    status = ftun_direct_system_close(context->result.socket);
  }
  context->result.socket = FTUN_INVALID_SOCKET;
  return status;
}

static ftun_status_t ftun_direct_cancel(void *user)
{
  ftun_direct_context_t *context = (ftun_direct_context_t *)user;
  ftun_status_t status;
  if (context == NULL) return FTUN_E_INVALID;
  if (context->child != NULL) {
    if (context->cancelling) return FTUN_E_AGAIN;
    status = ftun_operation_cancel(context->child);
    if (status != FTUN_OK) return status;
    context->cancelling = 1;
    return FTUN_E_AGAIN;
  }
  return ftun_direct_close_result(context);
}

static void ftun_direct_release_context(ftun_direct_context_t *context)
{
  ftun_reservation_t reservation;
  ftun_network_view_t *network_view;
  if (context == NULL) return;
  reservation = context->reservation;
  network_view = context->network_view;
  context->reservation = (ftun_reservation_t){0};
  context->network_view = NULL;
  (void)ftun_path_scope_release(&context->scope);
  memset(context, 0, sizeof(*context));
  free(context);
  (void)ftun_network_view_release(&network_view);
  (void)ftun_reservation_release(&reservation);
}

static void ftun_direct_completed(ftun_operation_t *operation,
                                  ftun_error_t error, void *user)
{
  ftun_direct_context_t *context = (ftun_direct_context_t *)user;
  ftun_dial_completion_fn completion;
  void *completion_user;
  if (context == NULL) return;
  if (error.status != FTUN_OK) (void)ftun_direct_close_result(context);
  completion = context->completion;
  completion_user = context->completion_user;
  context->operation = NULL;
  if (context->path_completion != NULL) {
    ftun_path_t *path = context->path;
    context->path = NULL;
    context->path_completion(operation, error, path, completion_user);
  } else completion(operation, error, &context->result, completion_user);
  ftun_direct_release_context(context);
}

static int ftun_direct_retryable(ftun_status_t status)
{
  return status == FTUN_E_REJECTED || status == FTUN_E_IO ||
         status == FTUN_E_TIMEOUT;
}

static void ftun_direct_child_completed(ftun_operation_t *operation,
                                        ftun_error_t error,
                                        const ftun_dial_result_t *result,
                                        void *user);

static void ftun_direct_path_completed(ftun_operation_t *operation,
  ftun_error_t error, ftun_path_t *path, void *user);

static ftun_status_t ftun_direct_start_attempt(ftun_direct_context_t *context)
{
  ftun_status_t status = FTUN_E_REJECTED;
  while (context->next_candidate < context->allowed_count) {
    ftun_dial_request_t request;
    size_t index = context->next_candidate++;
    memset(&request, 0, sizeof(request));
    request.loop = context->loop;
    request.operations = context->operations;
    request.budget = context->budget;
    request.endpoint = context->allowed[index];
    request.allowed = context->allowed;
    request.allowed_count = context->allowed_count;
    request.network_view = context->network_view;
    request.network_generation = context->network_generation;
    request.requested_domain = context->requested_domain;
    request.protection = context->protection;
    request.deadline_ms = context->deadline_ms;
    request.transport = context->transport;
    request.purpose = FTUN_DIAL_PURPOSE_BUSINESS;
    request.completion = ftun_direct_child_completed;
    request.user = context;
    if (context->scope != NULL) {
      ftun_path_open_request_t channel = {0};
      channel.dial = request;
      channel.dial.completion = NULL;
      channel.dial.user = NULL;
      channel.stream = context->stream;
      channel.datagram = context->datagram;
      channel.completion = ftun_direct_path_completed;
      channel.user = context;
      channel.notify = context->notify;
      channel.notify_user = context->notify_user;
      status = ftun_path_scope_open(context->scope, context->core, &channel, &context->child);
    } else if (context->custom_io) {
      status = ftun_dial_start_with_io(context->core, &request, &context->io,
                                       &context->child);
    } else {
      status = ftun_dial_start(context->core, &request, &context->child);
    }
    if (status == FTUN_OK) return FTUN_OK;
    context->child = NULL;
    if (context->transport != FTUN_DIAL_TCP ||
        !ftun_direct_retryable(status)) return status;
  }
  return status;
}

static void ftun_direct_child_completed(ftun_operation_t *operation,
                                        ftun_error_t error,
                                        const ftun_dial_result_t *result,
                                        void *user)
{
  ftun_direct_context_t *context = (ftun_direct_context_t *)user;
  ftun_status_t status;
  (void)operation;
  if (context == NULL || result == NULL) return;
  context->child = NULL;
  if (context->cancelling) {
    (void)ftun_operation_cancel(context->operation);
    return;
  }
  if (error.status == FTUN_OK) {
    context->result = *result;
    status = ftun_operation_complete(context->completion_token, error);
    if (status != FTUN_OK) (void)ftun_direct_close_result(context);
    return;
  }
  if (context->transport == FTUN_DIAL_TCP &&
      ftun_direct_retryable(error.status) &&
      context->next_candidate < context->allowed_count) {
    status = ftun_direct_start_attempt(context);
    if (status == FTUN_OK) return;
    error = ftun_direct_error(status, FTUN_DIAL_STAGE_CONNECT);
  }
  (void)ftun_operation_complete(context->completion_token, error);
}

static void ftun_direct_path_completed(ftun_operation_t *operation,
  ftun_error_t error, ftun_path_t *path, void *user)
{
  ftun_direct_context_t *context = (ftun_direct_context_t *)user;
  ftun_status_t status;
  (void)operation;
  context->child = NULL;
  context->path = path;
  if (context->cancelling) {
    (void)ftun_operation_cancel(context->operation);
    return;
  }
  if (error.status == FTUN_OK && path == NULL) error.status = FTUN_E_STATE_CORRUPT;
  if (error.status != FTUN_OK && context->transport == FTUN_DIAL_TCP &&
      ftun_direct_retryable(error.status) && context->next_candidate < context->allowed_count) {
    status = ftun_direct_start_attempt(context);
    if (status == FTUN_OK) return;
    error = ftun_direct_error(status, FTUN_DIAL_STAGE_CONNECT);
  }
  (void)ftun_operation_complete(context->completion_token, error);
}

static ftun_status_t ftun_direct_reject(ftun_direct_context_t *context,
                                        ftun_status_t original)
{
  ftun_status_t status;
  ftun_status_t cleanup = FTUN_OK;
  status = ftun_operation_set_cancel_hook(context->operation, NULL, NULL);
  if (status != FTUN_OK) cleanup = status;
  status = ftun_operation_reject(&context->operation);
  if (status != FTUN_OK && cleanup == FTUN_OK) cleanup = status;
  if (context->operation == NULL) ftun_direct_release_context(context);
  return cleanup == FTUN_OK ? original : cleanup;
}

static ftun_status_t ftun_direct_open_internal(
  ftun_core_t *core, const ftun_direct_request_t *request,
  const ftun_dial_io_t *io, ftun_operation_t **out)
{
  ftun_direct_context_t *context;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_status_t status;
  size_t allocation_size;
  if (out != NULL) *out = NULL;
  if (out == NULL || !ftun_direct_request_valid(request) ||
      (io != NULL && (!ftun_direct_io_valid(io) || request->scope != NULL))) return FTUN_E_INVALID;
  if (request->scope != NULL) {
    uint64_t generation;
    status = ftun_path_scope_generation(request->scope, &generation);
    if (status != FTUN_OK) return status;
    if (generation != request->target->generation) return FTUN_E_STALE;
  }
  status = ftun_direct_target_validate(request->target);
  if (status != FTUN_OK) return status;
  if (request->target->allowed_count >
      (SIZE_MAX - sizeof(*context)) / sizeof(*context->allowed)) {
    return FTUN_E_LIMIT;
  }
  allocation_size = sizeof(*context) + request->target->allowed_count *
                    sizeof(*context->allowed);
  status = ftun_budget_reserve(request->budget, allocation_size, &reservation);
  if (status != FTUN_OK) return status;
  context = (ftun_direct_context_t *)calloc(1u, allocation_size);
  if (context == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  context->core = core;
  context->reservation = reservation;
  if (request->scope != NULL) {
    status = ftun_path_scope_retain(request->scope);
    if (status != FTUN_OK) { ftun_direct_release_context(context); return status; }
    context->scope = request->scope;
    context->stream = request->stream;
    context->datagram = request->datagram;
    context->path_completion = request->path_completion;
    context->notify = request->notify;
    context->notify_user = request->notify_user;
  }
  context->loop = request->loop;
  context->operations = request->operations;
  context->budget = request->budget;
  context->allowed = (ftun_endpoint_t *)(context + 1);
  context->allowed_count = request->target->allowed_count;
  memcpy(context->allowed, request->target->allowed,
         context->allowed_count * sizeof(*context->allowed));
  if (request->network_view != NULL) {
    status = ftun_network_view_retain((ftun_network_view_t *)
                                      request->network_view);
    if (status != FTUN_OK) {
      ftun_direct_release_context(context);
      return status;
    }
    context->network_view = (ftun_network_view_t *)request->network_view;
  }
  context->network_generation = request->network_generation;
  context->requested_domain = request->requested_domain;
  context->protection.mark = request->protection.mark;
  context->protection.liveness = request->protection.liveness;
  if (request->protection.interface_name.length != 0u) {
    memcpy(context->interface_name,
           request->protection.interface_name.data,
           request->protection.interface_name.length);
    context->protection.interface_name.data = context->interface_name;
    context->protection.interface_name.length =
      request->protection.interface_name.length;
  }
  context->deadline_ms = request->deadline_ms;
  context->transport = request->transport;
  context->completion = request->completion;
  context->completion_user = request->user;
  context->result.socket = FTUN_INVALID_SOCKET;
  context->result.transport = request->transport;
  context->result.purpose = FTUN_DIAL_PURPOSE_BUSINESS;
  if (io != NULL) {
    context->io = *io;
    context->custom_io = 1;
  }

  status = ftun_operation_accept(request->operations, ftun_direct_completed,
                                 context, &context->operation,
                                 &context->completion_token);
  if (status != FTUN_OK) {
    ftun_direct_release_context(context);
    return status;
  }
  status = ftun_operation_set_cancel_hook(context->operation,
                                          ftun_direct_cancel, context);
  if (status != FTUN_OK) return ftun_direct_reject(context, status);
  status = ftun_direct_start_attempt(context);
  if (status != FTUN_OK) return ftun_direct_reject(context, status);
  *out = context->operation;
  return FTUN_OK;
}

/* 固定候选的受保护直连。 */
ftun_status_t ftun_direct_open_with_io(ftun_core_t *core,
                                       const ftun_direct_request_t *request,
                                       const ftun_dial_io_t *io,
                                       ftun_operation_t **out)
{
  if (io == NULL) {
    if (out != NULL) *out = NULL;
    return FTUN_E_INVALID;
  }
  return ftun_direct_open_internal(core, request, io, out);
}

ftun_status_t ftun_direct_open(ftun_core_t *core,
                               const ftun_direct_request_t *request,
                               ftun_operation_t **out)
{
  return ftun_direct_open_internal(core, request, NULL, out);
}
