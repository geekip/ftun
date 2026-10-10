#define _GNU_SOURCE 1

#include "bootstrap.h"

#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define FTUN_BOOTSTRAP_MAX_QUERY_BYTES \
  (FTUN_DNS_HEADER_BYTES + FTUN_DNS_MAX_NAME_BYTES + 4u)

typedef enum {
  FTUN_BOOTSTRAP_STATE_DIAL = 1,
  FTUN_BOOTSTRAP_STATE_SEND,
  FTUN_BOOTSTRAP_STATE_RECEIVE
} ftun_bootstrap_state_t;

typedef struct {
  ftun_core_t *core;
  ftun_operation_t *operation;
  ftun_operation_t *child;
  ftun_reservation_t *reservation;
  ftun_event_loop_t *loop;
  ftun_operation_queue_t *operations;
  ftun_budget_t *budget;
  ftun_event_source_t *io_source;
  ftun_event_source_t *timer_source;
  ftun_endpoint_t *servers;
  size_t server_count;
  size_t next_server;
  size_t current_server;
  ftun_socket_policy_t protection;
  char interface_name[FTUN_LINUX_SOCKET_DEVICE_BYTES];
  char domain[FTUN_SYSTEM_RESOLVER_MAX_DOMAIN_BYTES + 1u];
  size_t domain_length;
  uint8_t question_name[FTUN_DNS_MAX_NAME_BYTES];
  size_t question_name_length;
  uint8_t query_wire[FTUN_BOOTSTRAP_MAX_QUERY_BYTES];
  size_t query_wire_length;
  uint8_t response_wire[FTUN_BOOTSTRAP_MAX_RESPONSE_BYTES];
  ftun_endpoint_t addresses[FTUN_SYSTEM_RESOLVER_MAX_IPV4_RESULTS];
  size_t address_count;
  uint64_t deadline_ms;
  uint16_t query_id;
  ftun_native_socket_t socket;
  ftun_system_resolve_completion_fn completion;
  void *completion_user;
  ftun_dial_io_t dial_io;
  ftun_bootstrap_io_t io;
  ftun_error_t pending_error;
  ftun_bootstrap_state_t state;
  int custom_io;
  int cancelling;
  int has_pending_error;
  int cleanup_deferred;
} ftun_bootstrap_context_t;

static ftun_error_t ftun_bootstrap_error(ftun_status_t status, uint32_t stage)
{
  ftun_error_t error;
  memset(&error, 0, sizeof(error));
  error.status = status;
  error.stage = stage;
  return error;
}

static int ftun_bootstrap_domain_valid(ftun_string_t domain)
{
  size_t effective;
  size_t start = 0u;
  size_t index;
  size_t dots = 0u;
  int only_digits_and_dots = 1;
  if (domain.data == NULL || domain.length == 0u ||
      domain.length > FTUN_SYSTEM_RESOLVER_MAX_DOMAIN_BYTES ||
      memchr(domain.data, '\0', domain.length) != NULL) return 0;
  effective = domain.length;
  if (domain.data[effective - 1u] == '.') effective--;
  if (effective == 0u || effective > 253u) return 0;
  for (index = 0u; index < effective; index++) {
    unsigned char byte = (unsigned char)domain.data[index];
    if (byte == '.') dots++;
    else if (byte < (unsigned char)'0' || byte > (unsigned char)'9') {
      only_digits_and_dots = 0;
    }
  }
  if (only_digits_and_dots && dots == 3u) return 0;
  for (index = 0u; index <= effective; index++) {
    if (index == effective || domain.data[index] == '.') {
      size_t label_length = index - start;
      size_t label_index;
      if (label_length == 0u || label_length > 63u ||
          domain.data[start] == '-' || domain.data[index - 1u] == '-') return 0;
      for (label_index = start; label_index < index; label_index++) {
        unsigned char byte = (unsigned char)domain.data[label_index];
        if (!((byte >= (unsigned char)'A' && byte <= (unsigned char)'Z') ||
              (byte >= (unsigned char)'a' && byte <= (unsigned char)'z') ||
              (byte >= (unsigned char)'0' && byte <= (unsigned char)'9') ||
              byte == (unsigned char)'-')) return 0;
      }
      start = index + 1u;
    }
  }
  return 1;
}

static int ftun_bootstrap_device_valid(ftun_string_t device)
{
  size_t index;
  if (device.length == 0u) return 1;
  if (device.data == NULL ||
      device.length >= FTUN_LINUX_SOCKET_DEVICE_BYTES) return 0;
  for (index = 0u; index < device.length; index++) {
    unsigned char byte = (unsigned char)device.data[index];
    if (byte <= (unsigned char)' ' || byte == (unsigned char)'/' ||
        byte == (unsigned char)':') return 0;
  }
  return 1;
}

static int ftun_bootstrap_endpoint_equal(const ftun_endpoint_t *left,
                                         const ftun_endpoint_t *right)
{
  return left != NULL && right != NULL &&
         left->kind == FTUN_ADDRESS_IPV4 &&
         right->kind == FTUN_ADDRESS_IPV4 && left->port == right->port &&
         memcmp(left->address, right->address, 4u) == 0;
}

static ftun_status_t ftun_bootstrap_servers_validate(
  const ftun_bootstrap_request_t *request)
{
  size_t index;
  size_t previous;
  if (request->server_count > FTUN_BOOTSTRAP_MAX_SERVERS ||
      (request->server_count != 0u && request->servers == NULL)) {
    return FTUN_E_INVALID;
  }
  for (index = 0u; index < request->server_count; index++) {
    const ftun_endpoint_t *server = &request->servers[index];
    if (server->kind == FTUN_ADDRESS_IPV6_RESERVED) return FTUN_E_UNSUPPORTED;
    if (server->kind != FTUN_ADDRESS_IPV4 || server->port == 0u ||
        server->domain.length != 0u) return FTUN_E_INVALID;
    for (previous = 0u; previous < index; previous++) {
      if (ftun_bootstrap_endpoint_equal(server, &request->servers[previous])) {
        return FTUN_E_INVALID;
      }
    }
  }
  return FTUN_OK;
}

static ftun_status_t ftun_bootstrap_request_validate(
  const ftun_bootstrap_request_t *request)
{
  ftun_status_t status;
  if (request == NULL || request->budget == NULL ||
      request->completion == NULL || request->protection.mark == 0u ||
      !ftun_bootstrap_domain_valid(request->domain) ||
      !ftun_bootstrap_device_valid(request->protection.interface_name)) {
    return FTUN_E_INVALID;
  }
  status = ftun_bootstrap_servers_validate(request);
  if (status != FTUN_OK) return status;
  if (request->server_count == 0u) {
    return request->worker != NULL && request->check_system_path != NULL ?
      FTUN_OK : FTUN_E_INVALID;
  }
  return request->loop != NULL && request->operations != NULL ?
    FTUN_OK : FTUN_E_INVALID;
}

static int ftun_bootstrap_dial_io_valid(const ftun_dial_io_t *io)
{
  return io != NULL && io->open_socket != NULL && io->protect_socket != NULL &&
         io->connect_socket != NULL && io->get_socket_error != NULL &&
         io->close_socket != NULL;
}

static int ftun_bootstrap_io_valid(const ftun_bootstrap_io_t *io)
{
  return io != NULL && io->send_datagram != NULL &&
         io->receive_datagram != NULL;
}

static ftun_status_t ftun_bootstrap_errno_status(int error_code)
{
  if (error_code == EINTR || error_code == EAGAIN ||
      error_code == EWOULDBLOCK) return FTUN_E_AGAIN;
  if (error_code == ETIMEDOUT) return FTUN_E_TIMEOUT;
  if (error_code == ENOMEM || error_code == ENOBUFS) return FTUN_E_LIMIT;
  if (error_code == EBADF || error_code == ENOTSOCK || error_code == EINVAL) {
    return FTUN_E_INVALID;
  }
  if (error_code == EACCES || error_code == EPERM ||
      error_code == ECONNREFUSED || error_code == ENETUNREACH ||
      error_code == EHOSTUNREACH) return FTUN_E_REJECTED;
  return FTUN_E_IO;
}

static ftun_status_t ftun_bootstrap_system_send(
  void *user, ftun_native_socket_t socket, const void *data, size_t length,
  size_t *out_sent)
{
  ssize_t result;
  int descriptor;
  (void)user;
  if (out_sent != NULL) *out_sent = 0u;
  if (out_sent == NULL || data == NULL || length == 0u ||
      socket > (ftun_native_socket_t)INT_MAX) return FTUN_E_INVALID;
  descriptor = (int)socket;
  do {
    result = send(descriptor, data, length, 0);
  } while (result < 0 && errno == EINTR);
  if (result < 0) return ftun_bootstrap_errno_status(errno);
  if (result == 0) return FTUN_E_IO;
  *out_sent = (size_t)result;
  return FTUN_OK;
}

static ftun_status_t ftun_bootstrap_system_receive(
  void *user, ftun_native_socket_t socket, void *data, size_t capacity,
  size_t *out_received, ftun_endpoint_t *out_source)
{
  struct sockaddr_in source;
  struct iovec vector;
  struct msghdr message;
  ssize_t result;
  int descriptor;
  (void)user;
  if (out_received != NULL) *out_received = 0u;
  if (out_source != NULL) memset(out_source, 0, sizeof(*out_source));
  if (data == NULL || capacity == 0u || out_received == NULL ||
      out_source == NULL || socket > (ftun_native_socket_t)INT_MAX) {
    return FTUN_E_INVALID;
  }
  descriptor = (int)socket;
  memset(&source, 0, sizeof(source));
  memset(&message, 0, sizeof(message));
  vector.iov_base = data;
  vector.iov_len = capacity;
  message.msg_name = &source;
  message.msg_namelen = (socklen_t)sizeof(source);
  message.msg_iov = &vector;
  message.msg_iovlen = 1u;
  do {
    result = recvmsg(descriptor, &message, MSG_TRUNC);
  } while (result < 0 && errno == EINTR);
  if (result < 0) return ftun_bootstrap_errno_status(errno);
  if (result == 0) return FTUN_E_IO;
  if ((size_t)result > capacity || (message.msg_flags & MSG_TRUNC) != 0) {
    return FTUN_E_LIMIT;
  }
  if (source.sin_family != AF_INET ||
      message.msg_namelen < (socklen_t)sizeof(source)) return FTUN_E_PROTOCOL;
  out_source->kind = FTUN_ADDRESS_IPV4;
  memcpy(out_source->address, &source.sin_addr.s_addr, 4u);
  out_source->port = ntohs(source.sin_port);
  *out_received = (size_t)result;
  return FTUN_OK;
}

static const ftun_bootstrap_io_t ftun_bootstrap_system_io = {
  ftun_bootstrap_system_send,
  ftun_bootstrap_system_receive,
  NULL
};

static ftun_status_t ftun_bootstrap_system_close(ftun_native_socket_t socket)
{
  int descriptor;
  if (socket > (ftun_native_socket_t)INT_MAX) return FTUN_E_INVALID;
  descriptor = (int)socket;
  if (close(descriptor) == 0) return FTUN_OK;
  if (errno == EBADF) return FTUN_E_INVALID;
  return FTUN_E_IO;
}

static ftun_status_t ftun_bootstrap_close(ftun_bootstrap_context_t *context)
{
  ftun_status_t status;
  if (context->socket == FTUN_INVALID_SOCKET) return FTUN_OK;
  if (context->custom_io) {
    status = context->dial_io.close_socket(context->dial_io.context,
                                           context->socket);
  } else {
    status = ftun_bootstrap_system_close(context->socket);
  }
  context->socket = FTUN_INVALID_SOCKET;
  return status;
}

static ftun_status_t ftun_bootstrap_cancel_sources(
  ftun_bootstrap_context_t *context)
{
  ftun_status_t status = ftun_event_source_cancel(&context->io_source);
  if (status != FTUN_OK) return status;
  return ftun_event_source_cancel(&context->timer_source);
}

static ftun_status_t ftun_bootstrap_cancel(void *user)
{
  ftun_bootstrap_context_t *context = (ftun_bootstrap_context_t *)user;
  ftun_status_t status;
  if (context == NULL) return FTUN_E_INVALID;
  if (context->cleanup_deferred) return FTUN_E_AGAIN;
  if (context->child != NULL) {
    if (context->cancelling) return FTUN_E_AGAIN;
    status = ftun_operation_cancel(context->child);
    if (status != FTUN_OK) return status;
    context->cancelling = 1;
    return FTUN_E_AGAIN;
  }
  status = ftun_bootstrap_cancel_sources(context);
  if (status != FTUN_OK) return status;
  return ftun_bootstrap_close(context);
}

static void ftun_bootstrap_release_context(ftun_bootstrap_context_t *context)
{
  ftun_reservation_t *reservation;
  if (context == NULL) return;
  reservation = context->reservation;
  context->reservation = NULL;
  memset(context, 0, sizeof(*context));
  free(context);
  (void)ftun_reservation_release(&reservation);
}

static void ftun_bootstrap_completed(ftun_operation_t *operation,
                                     ftun_error_t error, void *user)
{
  ftun_bootstrap_context_t *context = (ftun_bootstrap_context_t *)user;
  ftun_system_resolve_result_t result;
  memset(&result, 0, sizeof(result));
  result.domain.data = context->domain;
  result.domain.length = context->domain_length;
  if (error.status == FTUN_OK) {
    result.addresses = context->addresses;
    result.address_count = context->address_count;
  }
  context->operation = NULL;
  context->completion(operation, error, &result, context->completion_user);
  ftun_bootstrap_release_context(context);
}

static void ftun_bootstrap_cleanup_deferred(void *user);

static ftun_status_t ftun_bootstrap_defer_cleanup(
  ftun_bootstrap_context_t *context)
{
  ftun_status_t status;
  if (context->cleanup_deferred) return FTUN_E_AGAIN;
  status = ftun_event_defer(context->loop, ftun_bootstrap_cleanup_deferred,
                            context);
  if (status == FTUN_OK) context->cleanup_deferred = 1;
  return status;
}

static ftun_status_t ftun_bootstrap_finish(ftun_bootstrap_context_t *context,
                                           ftun_error_t error)
{
  ftun_status_t status = ftun_bootstrap_cancel_sources(context);
  ftun_status_t close_status;
  if (status != FTUN_OK) {
    context->pending_error = error;
    context->has_pending_error = 1;
    (void)ftun_bootstrap_defer_cleanup(context);
    return status;
  }
  close_status = ftun_bootstrap_close(context);
  if (close_status != FTUN_OK && error.status == FTUN_OK) {
    error = ftun_bootstrap_error(close_status, FTUN_BOOTSTRAP_STAGE_RECEIVE);
  }
  context->pending_error = error;
  context->has_pending_error = 0;
  return ftun_operation_complete(context->operation, error);
}

static void ftun_bootstrap_cleanup_deferred(void *user)
{
  ftun_bootstrap_context_t *context = (ftun_bootstrap_context_t *)user;
  ftun_error_t error;
  if (context == NULL) return;
  context->cleanup_deferred = 0;
  if (!context->has_pending_error) return;
  error = context->pending_error;
  (void)ftun_bootstrap_finish(context, error);
}

static ftun_status_t ftun_bootstrap_encode_query(
  ftun_bootstrap_context_t *context)
{
  size_t input = 0u;
  size_t output = FTUN_DNS_HEADER_BYTES;
  size_t effective = context->domain_length;
  uint8_t *wire = context->query_wire;
  if (context->domain[effective - 1u] == '.') effective--;
  memset(wire, 0, sizeof(context->query_wire));
  wire[0] = (uint8_t)(context->query_id >> 8u);
  wire[1] = (uint8_t)context->query_id;
  wire[2] = 0x01u;
  wire[5] = 0x01u;
  while (input < effective) {
    size_t end = input;
    size_t length;
    while (end < effective && context->domain[end] != '.') end++;
    length = end - input;
    if (length == 0u || length > 63u ||
        output + 1u + length > sizeof(context->query_wire)) {
      return FTUN_E_INVALID;
    }
    wire[output++] = (uint8_t)length;
    memcpy(wire + output, context->domain + input, length);
    output += length;
    input = end + 1u;
  }
  if (output + 5u > sizeof(context->query_wire)) return FTUN_E_LIMIT;
  wire[output++] = 0u;
  context->question_name_length = output - FTUN_DNS_HEADER_BYTES;
  memcpy(context->question_name, wire + FTUN_DNS_HEADER_BYTES,
         context->question_name_length);
  wire[output++] = 0u;
  wire[output++] = 1u;
  wire[output++] = 0u;
  wire[output++] = 1u;
  context->query_wire_length = output;
  return FTUN_OK;
}

static int ftun_bootstrap_address_contains(
  const ftun_bootstrap_context_t *context, const uint8_t address[4])
{
  size_t index;
  for (index = 0u; index < context->address_count; index++) {
    if (memcmp(context->addresses[index].address, address, 4u) == 0) return 1;
  }
  return 0;
}

static ftun_status_t ftun_bootstrap_response_status(uint16_t rcode)
{
  if (rcode == 0u) return FTUN_OK;
  if (rcode == 3u) return FTUN_E_RESOLVE;
  if (rcode == 4u || rcode == 16u) return FTUN_E_UNSUPPORTED;
  if (rcode == 5u) return FTUN_E_REJECTED;
  if (rcode == 1u) return FTUN_E_PROTOCOL;
  return FTUN_E_IO;
}

static ftun_status_t ftun_bootstrap_collect_answers(
  ftun_bootstrap_context_t *context, const ftun_dns_message_t *message)
{
  size_t index;
  context->address_count = 0u;
  for (index = 0u; index < message->record_count; index++) {
    const ftun_dns_record_t *record = &message->records[index];
    ftun_endpoint_t *endpoint;
    if (record->section != FTUN_DNS_SECTION_ANSWER ||
        record->kind != FTUN_DNS_RECORD_ORDINARY || record->type != 1u ||
        record->class_code != 1u || record->rdata.length != 4u) continue;
    if (ftun_bootstrap_address_contains(context, record->rdata.data)) continue;
    if (context->address_count >= FTUN_SYSTEM_RESOLVER_MAX_IPV4_RESULTS) {
      return FTUN_E_LIMIT;
    }
    endpoint = &context->addresses[context->address_count++];
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->kind = FTUN_ADDRESS_IPV4;
    memcpy(endpoint->address, record->rdata.data, 4u);
  }
  return context->address_count == 0u ? FTUN_E_RESOLVE : FTUN_OK;
}

static ftun_status_t ftun_bootstrap_process_response(
  ftun_bootstrap_context_t *context, size_t received,
  const ftun_endpoint_t *source, int *out_matched)
{
  ftun_dns_message_t *message = NULL;
  ftun_dns_query_t query;
  bool matches = false;
  ftun_status_t status;
  *out_matched = 0;
  if (!ftun_bootstrap_endpoint_equal(
        source, &context->servers[context->current_server])) return FTUN_OK;
  status = ftun_dns_message_parse(
    (ftun_bytes_t){context->response_wire, received}, &message);
  if (status != FTUN_OK) return status;
  memset(&query, 0, sizeof(query));
  query.id = context->query_id;
  query.transport = FTUN_DNS_TRANSPORT_UDP;
  query.upstream = context->servers[context->current_server];
  query.question.name.data = context->question_name;
  query.question.name.length = context->question_name_length;
  query.question.type = 1u;
  query.question.class_code = 1u;
  status = ftun_dns_message_matches(message, &query, FTUN_DNS_TRANSPORT_UDP,
                                    source, &matches);
  if (status == FTUN_OK && !matches) {
    (void)ftun_dns_message_release(&message);
    return FTUN_OK;
  }
  if (status == FTUN_OK) {
    *out_matched = 1;
    if ((message->flags & 0x0200u) != 0u) status = FTUN_E_UNSUPPORTED;
  }
  if (status == FTUN_OK) status = ftun_bootstrap_response_status(message->rcode);
  if (status == FTUN_OK) status = ftun_bootstrap_collect_answers(context, message);
  (void)ftun_dns_message_release(&message);
  return status;
}

static void ftun_bootstrap_io_ready(ftun_event_source_t *source,
                                    uint32_t events, void *user);

static ftun_status_t ftun_bootstrap_watch(ftun_bootstrap_context_t *context,
                                          uint32_t interests)
{
  ftun_status_t status = ftun_event_source_cancel(&context->io_source);
  if (status != FTUN_OK) return status;
  return ftun_event_io_start(context->loop, context->socket,
                             interests | FTUN_EVENT_ERROR,
                             ftun_bootstrap_io_ready, context,
                             &context->io_source);
}

static ftun_status_t ftun_bootstrap_send_query(
  ftun_bootstrap_context_t *context)
{
  size_t sent = 0u;
  ftun_status_t status = context->io.send_datagram(
    context->io.context, context->socket, context->query_wire,
    context->query_wire_length, &sent);
  if (status == FTUN_E_AGAIN) {
    context->state = FTUN_BOOTSTRAP_STATE_SEND;
    return ftun_bootstrap_watch(context, FTUN_EVENT_WRITE);
  }
  if (status != FTUN_OK) return status;
  if (sent != context->query_wire_length) return FTUN_E_IO;
  context->state = FTUN_BOOTSTRAP_STATE_RECEIVE;
  return ftun_bootstrap_watch(context, FTUN_EVENT_READ);
}

static int ftun_bootstrap_retryable(ftun_status_t status)
{
  return status == FTUN_E_REJECTED || status == FTUN_E_IO ||
         status == FTUN_E_RESOLVE || status == FTUN_E_PROTOCOL ||
         status == FTUN_E_UNSUPPORTED;
}

static void ftun_bootstrap_child_completed(
  ftun_operation_t *operation, ftun_error_t error,
  const ftun_dial_result_t *result, void *user);

static ftun_status_t ftun_bootstrap_start_attempt(
  ftun_bootstrap_context_t *context)
{
  ftun_status_t status = FTUN_E_RESOLVE;
  while (context->next_server < context->server_count) {
    ftun_dial_request_t request;
    context->current_server = context->next_server++;
    memset(&request, 0, sizeof(request));
    request.loop = context->loop;
    request.operations = context->operations;
    request.budget = context->budget;
    request.endpoint = context->servers[context->current_server];
    request.protection = context->protection;
    request.deadline_ms = context->deadline_ms;
    request.transport = FTUN_DIAL_UDP;
    request.purpose = FTUN_DIAL_PURPOSE_BOOTSTRAP;
    request.completion = ftun_bootstrap_child_completed;
    request.user = context;
    context->state = FTUN_BOOTSTRAP_STATE_DIAL;
    if (context->custom_io) {
      status = ftun_dial_start_with_io(context->core, &request,
                                       &context->dial_io, &context->child);
    } else {
      status = ftun_dial_start(context->core, &request, &context->child);
    }
    if (status == FTUN_OK) return FTUN_OK;
    context->child = NULL;
    if (!ftun_bootstrap_retryable(status)) return status;
  }
  return status;
}

static ftun_status_t ftun_bootstrap_retry(ftun_bootstrap_context_t *context,
                                          ftun_error_t error)
{
  ftun_status_t status = ftun_bootstrap_cancel_sources(context);
  if (status != FTUN_OK) return ftun_bootstrap_finish(context, error);
  status = ftun_bootstrap_close(context);
  if (status != FTUN_OK) return ftun_bootstrap_finish(
    context, ftun_bootstrap_error(status, FTUN_BOOTSTRAP_STAGE_RECEIVE));
  if (ftun_bootstrap_retryable(error.status) &&
      context->next_server < context->server_count) {
    status = ftun_bootstrap_start_attempt(context);
    if (status == FTUN_OK) return FTUN_OK;
    error = ftun_bootstrap_error(status, FTUN_BOOTSTRAP_STAGE_DIAL);
  }
  return ftun_bootstrap_finish(context, error);
}

static void ftun_bootstrap_child_completed(
  ftun_operation_t *operation, ftun_error_t error,
  const ftun_dial_result_t *result, void *user)
{
  ftun_bootstrap_context_t *context = (ftun_bootstrap_context_t *)user;
  ftun_status_t status;
  (void)operation;
  context->child = NULL;
  if (context->cancelling) {
    (void)ftun_operation_cancel(context->operation);
    return;
  }
  if (error.status != FTUN_OK) {
    (void)ftun_bootstrap_retry(
      context, ftun_bootstrap_error(error.status, FTUN_BOOTSTRAP_STAGE_DIAL));
    return;
  }
  if (result == NULL || result->socket == FTUN_INVALID_SOCKET ||
      result->transport != FTUN_DIAL_UDP ||
      result->purpose != FTUN_DIAL_PURPOSE_BOOTSTRAP ||
      !ftun_bootstrap_endpoint_equal(
        &result->endpoint, &context->servers[context->current_server])) {
    if (result != NULL) context->socket = result->socket;
    (void)ftun_bootstrap_finish(
      context, ftun_bootstrap_error(FTUN_E_STATE_CORRUPT,
                                    FTUN_BOOTSTRAP_STAGE_DIAL));
    return;
  }
  context->socket = result->socket;
  status = ftun_event_timer_start(context->loop, context->deadline_ms,
                                  ftun_bootstrap_io_ready, context,
                                  &context->timer_source);
  if (status == FTUN_OK) status = ftun_bootstrap_send_query(context);
  if (status != FTUN_OK) {
    (void)ftun_bootstrap_retry(
      context, ftun_bootstrap_error(status, FTUN_BOOTSTRAP_STAGE_SEND));
  }
}

static void ftun_bootstrap_io_ready(ftun_event_source_t *source,
                                    uint32_t events, void *user)
{
  ftun_bootstrap_context_t *context = (ftun_bootstrap_context_t *)user;
  ftun_status_t status;
  (void)source;
  if (context->has_pending_error) {
    (void)ftun_bootstrap_finish(context, context->pending_error);
    return;
  }
  if ((events & FTUN_EVENT_TIMER) != 0u) {
    (void)ftun_bootstrap_finish(
      context, ftun_bootstrap_error(FTUN_E_TIMEOUT,
                                    FTUN_BOOTSTRAP_STAGE_TIMEOUT));
    return;
  }
  if (context->state == FTUN_BOOTSTRAP_STATE_SEND) {
    status = ftun_bootstrap_send_query(context);
    if (status != FTUN_OK) {
      (void)ftun_bootstrap_retry(
        context, ftun_bootstrap_error(status, FTUN_BOOTSTRAP_STAGE_SEND));
    }
    return;
  }
  if (context->state == FTUN_BOOTSTRAP_STATE_RECEIVE) {
    ftun_endpoint_t source_endpoint;
    size_t received = 0u;
    int matched = 0;
    status = context->io.receive_datagram(
      context->io.context, context->socket, context->response_wire,
      sizeof(context->response_wire), &received, &source_endpoint);
    if (status == FTUN_E_AGAIN) return;
    if (status == FTUN_OK && received == 0u) status = FTUN_E_IO;
    if (status == FTUN_OK) {
      status = ftun_bootstrap_process_response(context, received,
                                                &source_endpoint, &matched);
      if (status == FTUN_OK && !matched) return;
    }
    if (status == FTUN_OK) {
      (void)ftun_bootstrap_finish(
        context, ftun_bootstrap_error(FTUN_OK,
                                      FTUN_BOOTSTRAP_STAGE_RESPONSE));
    } else if (!matched) {
      (void)ftun_bootstrap_retry(
        context, ftun_bootstrap_error(status,
                                      FTUN_BOOTSTRAP_STAGE_RECEIVE));
    } else {
      (void)ftun_bootstrap_retry(
        context, ftun_bootstrap_error(status,
                                      FTUN_BOOTSTRAP_STAGE_RESPONSE));
    }
  }
}

static ftun_status_t ftun_bootstrap_reject(ftun_bootstrap_context_t *context,
                                           ftun_status_t original)
{
  ftun_status_t cleanup = FTUN_OK;
  ftun_status_t status = ftun_operation_set_cancel_hook(
    context->operation, NULL, NULL);
  if (status != FTUN_OK) cleanup = status;
  status = ftun_operation_reject(&context->operation);
  if (status != FTUN_OK && cleanup == FTUN_OK) cleanup = status;
  if (context->operation == NULL) ftun_bootstrap_release_context(context);
  return cleanup == FTUN_OK ? original : cleanup;
}

static ftun_status_t ftun_bootstrap_explicit(
  ftun_core_t *core, const ftun_bootstrap_request_t *request,
  const ftun_dial_io_t *dial_io, const ftun_bootstrap_io_t *io,
  ftun_operation_t **out)
{
  ftun_bootstrap_context_t *context;
  ftun_reservation_t *reservation = NULL;
  size_t allocation_size;
  ftun_status_t status;
  if (request->server_count >
      (SIZE_MAX - sizeof(*context)) / sizeof(*context->servers)) {
    return FTUN_E_LIMIT;
  }
  allocation_size = sizeof(*context) + request->server_count *
                    sizeof(*context->servers);
  status = ftun_budget_reserve(request->budget, allocation_size, &reservation);
  if (status != FTUN_OK) return status;
  context = (ftun_bootstrap_context_t *)calloc(1u, allocation_size);
  if (context == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  context->core = core;
  context->reservation = reservation;
  context->loop = request->loop;
  context->operations = request->operations;
  context->budget = request->budget;
  context->servers = (ftun_endpoint_t *)(context + 1);
  context->server_count = request->server_count;
  memcpy(context->servers, request->servers,
         request->server_count * sizeof(*context->servers));
  context->protection.mark = request->protection.mark;
  if (request->protection.interface_name.length != 0u) {
    memcpy(context->interface_name, request->protection.interface_name.data,
           request->protection.interface_name.length);
    context->protection.interface_name.data = context->interface_name;
    context->protection.interface_name.length =
      request->protection.interface_name.length;
  }
  memcpy(context->domain, request->domain.data, request->domain.length);
  context->domain[request->domain.length] = '\0';
  context->domain_length = request->domain.length;
  context->deadline_ms = request->deadline_ms;
  context->query_id = request->query_id;
  context->completion = request->completion;
  context->completion_user = request->user;
  context->socket = FTUN_INVALID_SOCKET;
  context->io = io == NULL ? ftun_bootstrap_system_io : *io;
  if (io != NULL) {
    context->dial_io = *dial_io;
    context->custom_io = 1;
  }
  status = ftun_bootstrap_encode_query(context);
  if (status != FTUN_OK) {
    ftun_bootstrap_release_context(context);
    return status;
  }
  status = ftun_operation_accept(request->operations, ftun_bootstrap_completed,
                                 context, &context->operation);
  if (status != FTUN_OK) {
    ftun_bootstrap_release_context(context);
    return status;
  }
  status = ftun_operation_set_cancel_hook(context->operation,
                                          ftun_bootstrap_cancel, context);
  if (status != FTUN_OK) return ftun_bootstrap_reject(context, status);
  status = ftun_bootstrap_start_attempt(context);
  if (status != FTUN_OK) return ftun_bootstrap_reject(context, status);
  *out = context->operation;
  return FTUN_OK;
}

static ftun_status_t ftun_bootstrap_resolve_internal(
  ftun_core_t *core, const ftun_bootstrap_request_t *request,
  const ftun_dial_io_t *dial_io, const ftun_bootstrap_io_t *io,
  ftun_operation_t **out)
{
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (out == NULL) return FTUN_E_INVALID;
  status = ftun_bootstrap_request_validate(request);
  if (status != FTUN_OK) return status;
  if (request->server_count == 0u) {
    ftun_system_resolve_request_t system_request;
    if (dial_io != NULL || io != NULL) return FTUN_E_INVALID;
    memset(&system_request, 0, sizeof(system_request));
    system_request.worker = request->worker;
    system_request.budget = request->budget;
    system_request.domain = request->domain;
    system_request.protection = request->protection;
    system_request.deadline_ms = request->deadline_ms;
    system_request.check_path = request->check_system_path;
    system_request.path_user = request->system_path_user;
    system_request.completion = request->completion;
    system_request.user = request->user;
    return ftun_system_resolve(core, &system_request, out);
  }
  if ((dial_io == NULL) != (io == NULL) ||
      (dial_io != NULL && (!ftun_bootstrap_dial_io_valid(dial_io) ||
                           !ftun_bootstrap_io_valid(io)))) {
    return FTUN_E_INVALID;
  }
  return ftun_bootstrap_explicit(core, request, dial_io, io, out);
}

/* TASK-DNS-004 / TEST-DNS-004，目标 0.2.0：基础真实解析。 */
ftun_status_t ftun_bootstrap_resolve(
  ftun_core_t *core, const ftun_bootstrap_request_t *request,
  ftun_operation_t **out)
{
  return ftun_bootstrap_resolve_internal(core, request, NULL, NULL, out);
}

ftun_status_t ftun_bootstrap_resolve_with_io(
  ftun_core_t *core, const ftun_bootstrap_request_t *request,
  const ftun_dial_io_t *dial_io, const ftun_bootstrap_io_t *io,
  ftun_operation_t **out)
{
  return ftun_bootstrap_resolve_internal(core, request, dial_io, io, out);
}
