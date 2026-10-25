#define _GNU_SOURCE 1
#include "socks5.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define FTUN_SOCKS5_FRAME_BYTES 520u
#define FTUN_SOCKS5_STAGE_PROXY_DIAL 1u
#define FTUN_SOCKS5_STAGE_METHOD 2u
#define FTUN_SOCKS5_STAGE_AUTH 3u
#define FTUN_SOCKS5_STAGE_REQUEST 4u
#define FTUN_SOCKS5_STAGE_UDP_DIAL 5u
#define FTUN_SOCKS5_STAGE_TIMEOUT 6u

typedef enum {
  FTUN_SOCKS5_STATE_DIAL_PROXY = 1,
  FTUN_SOCKS5_STATE_WRITE_METHOD,
  FTUN_SOCKS5_STATE_READ_METHOD,
  FTUN_SOCKS5_STATE_WRITE_AUTH,
  FTUN_SOCKS5_STATE_READ_AUTH,
  FTUN_SOCKS5_STATE_WRITE_REQUEST,
  FTUN_SOCKS5_STATE_READ_REPLY,
  FTUN_SOCKS5_STATE_DIAL_UDP,
  FTUN_SOCKS5_STATE_READY
} ftun_socks5_state_t;

struct ftun_socks5_connection {
  ftun_core_t *core;
  ftun_operation_t *operation;
  ftun_operation_token_t completion_token;
  ftun_operation_t *child;
  ftun_reservation_t *reservation;
  ftun_event_loop_t *loop;
  ftun_operation_queue_t *operations;
  ftun_budget_t *budget;
  ftun_event_source_t *io_source;
  ftun_event_source_t *timer_source;
  ftun_event_source_t *pump_source;
  ftun_endpoint_t *proxy_candidates;
  size_t proxy_candidate_count;
  size_t next_proxy_candidate;
  ftun_network_view_t *network_view;
  uint64_t network_generation;
  ftun_dial_domain_t requested_domain;
  ftun_endpoint_t proxy_endpoint;
  ftun_endpoint_t target;
  ftun_endpoint_t relay;
  ftun_dial_domain_t proxy_domain;
  uint64_t selected_network_generation;
  ftun_socket_policy_t protection;
  char interface_name[FTUN_SOCKET_INTERFACE_BYTES];
  uint8_t target_domain[FTUN_SOCKS5_MAX_DOMAIN_BYTES];
  uint8_t username[FTUN_SOCKS5_MAX_CREDENTIAL_BYTES];
  uint8_t password[FTUN_SOCKS5_MAX_CREDENTIAL_BYTES];
  size_t username_length;
  size_t password_length;
  uint8_t output[FTUN_SOCKS5_FRAME_BYTES];
  size_t output_offset;
  size_t output_length;
  uint8_t input[FTUN_SOCKS5_FRAME_BYTES];
  size_t input_length;
  uint64_t deadline_ms;
  ftun_dial_transport_t transport;
  ftun_native_socket_t control_socket;
  ftun_native_socket_t data_socket;
  ftun_socks5_completion_fn completion;
  void *completion_user;
  ftun_dial_io_t dial_io;
  ftun_socks5_io_t protocol_io;
  ftun_error_t pending_error;
  ftun_socks5_state_t state;
  ftun_path_scope_t *scope;
  ftun_path_t *control_path;
  ftun_stream_t *control_stream;
  ftun_path_t *data_path;
  ftun_datagram_t *wire_datagram;
  ftun_datagram_t *datagram;
  ftun_datagram_options_t datagram_options;
  ftun_datagram_send_token_t datagram_send;
  ftun_status_t channel_failure;
  bool cancelling_send;
  ftun_stream_options_t stream_options;
  ftun_path_notify_fn notify;
  void *notify_user;
  ftun_buffer_slice_t output_slice;
  ftun_operation_t *write_operation;
  ftun_status_t write_error;
  bool scheduled;
  bool busy;
  bool terminal_queued;
  int custom_dial_io;
  int cancelling;
  int has_pending_error;
  int ready;
};

static ftun_status_t ftun_socks5_schedule(ftun_socks5_connection_t *connection);
static ftun_status_t ftun_socks5_owned_finish(ftun_socks5_connection_t *connection,
  ftun_error_t error);
static void ftun_socks5_path_completed(ftun_operation_t *operation,
  ftun_error_t error, ftun_path_t *path, void *user);
static void ftun_socks5_path_notify(ftun_path_t *path, uint32_t events,
  ftun_error_t error, void *user);
static void ftun_socks5_write_completed(ftun_operation_t *operation,
  ftun_error_t error, void *user);

static ftun_status_t ftun_socks5_datagram_create(ftun_socks5_connection_t *connection);
static void ftun_socks5_wire_result(ftun_datagram_t *channel, ftun_error_t error,
  const ftun_endpoint_t *target, const ftun_packet_t *packet, void *user);
static ftun_status_t ftun_socks5_wire_receive(ftun_datagram_t *channel,
  const ftun_endpoint_t *source, const ftun_packet_t *packet, void *user);
static void ftun_socks5_data_completed(ftun_operation_t *operation,
  ftun_error_t error, ftun_path_t *path, void *user);

static ftun_error_t ftun_socks5_error(ftun_status_t status, uint32_t stage)
{
  ftun_error_t error;
  memset(&error, 0, sizeof(error));
  error.status = status;
  error.stage = stage;
  return error;
}

static int ftun_socks5_domain_valid(ftun_string_t domain, size_t maximum)
{
  return domain.data != NULL && domain.length != 0u &&
         domain.length <= maximum &&
         memchr(domain.data, '\0', domain.length) == NULL;
}

static int ftun_socks5_endpoint_equal(const ftun_endpoint_t *left,
                                      const ftun_endpoint_t *right)
{
  return left != NULL && right != NULL &&
         left->kind == FTUN_ADDRESS_IPV4 &&
         right->kind == FTUN_ADDRESS_IPV4 && left->port == right->port &&
         memcmp(left->address, right->address, 4u) == 0;
}

static int ftun_socks5_contains(const ftun_endpoint_t *items, size_t count,
                                const ftun_endpoint_t *endpoint)
{
  size_t index;
  for (index = 0u; index < count; index++) {
    if (ftun_socks5_endpoint_equal(&items[index], endpoint)) return 1;
  }
  return 0;
}

static ftun_status_t ftun_socks5_proxy_validate(
  const ftun_socks5_proxy_t *proxy, size_t *candidate_count)
{
  size_t index;
  if (candidate_count != NULL) *candidate_count = 0u;
  if (proxy == NULL || candidate_count == NULL || proxy->server.port == 0u ||
      (proxy->username.length == 0u) != (proxy->password.length == 0u) ||
      proxy->username.length > FTUN_SOCKS5_MAX_CREDENTIAL_BYTES ||
      proxy->password.length > FTUN_SOCKS5_MAX_CREDENTIAL_BYTES ||
      (proxy->username.length != 0u && proxy->username.data == NULL) ||
      (proxy->password.length != 0u && proxy->password.data == NULL) ||
      (proxy->resolved_count != 0u && proxy->resolved == NULL)) {
    return FTUN_E_INVALID;
  }
  if (proxy->server.kind == FTUN_ADDRESS_IPV4) {
    if (proxy->server.domain.length != 0u || proxy->resolved_count != 0u) {
      return FTUN_E_INVALID;
    }
    *candidate_count = 1u;
    return FTUN_OK;
  }
  if (proxy->server.kind == FTUN_ADDRESS_IPV6_RESERVED) {
    return FTUN_E_UNSUPPORTED;
  }
  if (proxy->server.kind != FTUN_ADDRESS_DOMAIN ||
      !ftun_socks5_domain_valid(proxy->server.domain, 253u)) {
    return FTUN_E_INVALID;
  }
  if (proxy->resolved_count == 0u) return FTUN_E_RESOLVE;
  for (index = 0u; index < proxy->resolved_count; index++) {
    const ftun_endpoint_t *endpoint = &proxy->resolved[index];
    if (endpoint->kind != FTUN_ADDRESS_IPV4 || endpoint->port == 0u ||
        endpoint->port != proxy->server.port ||
        endpoint->domain.length != 0u) return FTUN_E_INVALID;
  }
  *candidate_count = proxy->resolved_count;
  return FTUN_OK;
}

static ftun_status_t ftun_socks5_target_select(const ftun_target_t *target,
                                                ftun_endpoint_t *out)
{
  size_t index;
  size_t previous;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (target == NULL || out == NULL || target->generation == 0u ||
      target->original.port == 0u ||
      (target->candidate_count != 0u && target->candidates == NULL) ||
      (target->allowed_count != 0u && target->allowed == NULL) ||
      target->allowed_count > target->candidate_count) return FTUN_E_INVALID;
  if (target->original.kind != FTUN_ADDRESS_IPV4 &&
      target->original.kind != FTUN_ADDRESS_DOMAIN) return FTUN_E_INVALID;
  if (target->original.kind == FTUN_ADDRESS_DOMAIN &&
      !ftun_socks5_domain_valid(target->original.domain, 253u)) {
    return FTUN_E_INVALID;
  }
  for (index = 0u; index < target->candidate_count; index++) {
    if (target->candidates[index].kind != FTUN_ADDRESS_IPV4 ||
        target->candidates[index].port != target->original.port ||
        target->candidates[index].domain.length != 0u) return FTUN_E_INVALID;
  }
  for (index = 0u; index < target->allowed_count; index++) {
    if (target->allowed[index].kind != FTUN_ADDRESS_IPV4 ||
        target->allowed[index].port == 0u ||
        target->allowed[index].domain.length != 0u) return FTUN_E_INVALID;
    if (!ftun_socks5_contains(target->candidates, target->candidate_count,
                              &target->allowed[index])) return FTUN_E_REJECTED;
    for (previous = 0u; previous < index; previous++) {
      if (ftun_socks5_endpoint_equal(&target->allowed[previous],
                                     &target->allowed[index])) {
        return FTUN_E_INVALID;
      }
    }
  }
  if (target->candidate_count != 0u) {
    if (target->allowed_count == 0u) return FTUN_E_REJECTED;
    *out = target->allowed[0];
    return FTUN_OK;
  }
  if (!ftun_socks5_domain_valid(target->identity, 253u)) {
    return FTUN_E_REJECTED;
  }
  out->kind = FTUN_ADDRESS_DOMAIN;
  out->domain = target->identity;
  out->port = target->original.port;
  return FTUN_OK;
}

static int ftun_socks5_request_valid(
  const ftun_socks5_connect_request_t *request)
{
  if (request == NULL || request->loop == NULL ||
      request->operations == NULL || request->budget == NULL ||
      request->proxy == NULL || request->target == NULL ||
      request->completion == NULL ||
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

static int ftun_socks5_dial_io_valid(const ftun_dial_io_t *io)
{
  return io != NULL && io->open_socket != NULL && io->protect_socket != NULL &&
         io->connect_socket != NULL && io->get_socket_error != NULL &&
         io->close_socket != NULL;
}

static int ftun_socks5_protocol_io_valid(const ftun_socks5_io_t *io)
{
  return io != NULL && io->send_socket != NULL &&
         io->receive_socket != NULL;
}

static ftun_status_t ftun_socks5_errno_status(int error_code)
{
  if (error_code == EINTR || error_code == EAGAIN ||
      error_code == EWOULDBLOCK) return FTUN_E_AGAIN;
  if (error_code == ETIMEDOUT) return FTUN_E_TIMEOUT;
  if (error_code == ENOMEM || error_code == ENOBUFS) return FTUN_E_LIMIT;
  if (error_code == EBADF || error_code == ENOTSOCK || error_code == EINVAL) {
    return FTUN_E_INVALID;
  }
  if (error_code == EACCES || error_code == EPERM ||
      error_code == ECONNRESET || error_code == EPIPE) return FTUN_E_REJECTED;
  return FTUN_E_IO;
}

static ftun_status_t ftun_socks5_system_send(
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
#ifdef MSG_NOSIGNAL
    result = send(descriptor, data, length, MSG_NOSIGNAL);
#else
    result = send(descriptor, data, length, 0);
#endif
  } while (result < 0 && errno == EINTR);
  if (result < 0) return ftun_socks5_errno_status(errno);
  if (result == 0) return FTUN_E_IO;
  *out_sent = (size_t)result;
  return FTUN_OK;
}

static ftun_status_t ftun_socks5_system_receive(
  void *user, ftun_native_socket_t socket, void *data, size_t capacity,
  size_t *out_received)
{
  ssize_t result;
  int descriptor;
  (void)user;
  if (out_received != NULL) *out_received = 0u;
  if (out_received == NULL || data == NULL || capacity == 0u ||
      socket > (ftun_native_socket_t)INT_MAX) return FTUN_E_INVALID;
  descriptor = (int)socket;
  do {
    result = recv(descriptor, data, capacity, 0);
  } while (result < 0 && errno == EINTR);
  if (result < 0) return ftun_socks5_errno_status(errno);
  if (result == 0) return FTUN_E_EOF;
  *out_received = (size_t)result;
  return FTUN_OK;
}

static ftun_status_t ftun_socks5_system_close(ftun_native_socket_t socket)
{
  int descriptor;
  if (socket > (ftun_native_socket_t)INT_MAX) return FTUN_E_INVALID;
  descriptor = (int)socket;
  if (close(descriptor) == 0) return FTUN_OK;
  return errno == EBADF ? FTUN_E_INVALID : FTUN_E_IO;
}

static const ftun_socks5_io_t ftun_socks5_system_io = {
  ftun_socks5_system_send,
  ftun_socks5_system_receive,
  NULL
};

static ftun_status_t ftun_socks5_close_one(
  ftun_socks5_connection_t *connection, ftun_native_socket_t *socket)
{
  ftun_status_t status;
  if (*socket == FTUN_INVALID_SOCKET) return FTUN_OK;
  if (connection->custom_dial_io) {
    status = connection->dial_io.close_socket(connection->dial_io.context,
                                               *socket);
  } else {
    status = ftun_socks5_system_close(*socket);
  }
  *socket = FTUN_INVALID_SOCKET;
  return status;
}

static ftun_status_t ftun_socks5_close_sockets(
  ftun_socks5_connection_t *connection)
{
  ftun_status_t result;
  ftun_status_t status;
  if (connection->scope != NULL) {
    if (connection->scheduled) return FTUN_E_AGAIN;
    if (connection->write_operation != NULL) {
      status = ftun_operation_cancel(connection->write_operation);
      return status == FTUN_OK || status == FTUN_E_STALE ? FTUN_E_AGAIN : status;
    }
    status = ftun_buffer_slice_release(&connection->output_slice);
    if (status != FTUN_OK) return status;
    if (connection->datagram != NULL) {
      status = ftun_datagram_stop(connection->datagram);
      if (status == FTUN_OK) status = ftun_datagram_destroy(&connection->datagram);
      if (status != FTUN_OK) return status;
    }
    if (connection->data_path != NULL) {
      status = ftun_path_revoke(connection->data_path);
      if (status == FTUN_OK) status = ftun_path_destroy(&connection->data_path);
      if (status != FTUN_OK) return status;
      connection->wire_datagram = NULL;
    }
    if (connection->control_path != NULL) {
      status = ftun_path_revoke(connection->control_path);
      if (status == FTUN_OK) status = ftun_path_destroy(&connection->control_path);
      if (status != FTUN_OK) return status;
      connection->control_stream = NULL;
    }
    return FTUN_OK;
  }
  if (connection->data_socket != FTUN_INVALID_SOCKET &&
      connection->data_socket == connection->control_socket) {
    connection->data_socket = FTUN_INVALID_SOCKET;
  }
  result = ftun_socks5_close_one(connection, &connection->data_socket);
  status = ftun_socks5_close_one(connection, &connection->control_socket);
  return result == FTUN_OK ? status : result;
}

static ftun_status_t ftun_socks5_cancel_sources(
  ftun_socks5_connection_t *connection)
{
  ftun_status_t status;
  status = ftun_event_source_cancel(&connection->io_source);
  if (status != FTUN_OK) return status;
  return ftun_event_source_cancel(&connection->timer_source);
}

static ftun_status_t ftun_socks5_cancel(void *user)
{
  ftun_socks5_connection_t *connection =
    (ftun_socks5_connection_t *)user;
  ftun_status_t status;
  if (connection == NULL) return FTUN_E_INVALID;
  if (connection->scope != NULL) {
    connection->cancelling = 1;
    if (connection->busy || connection->scheduled) return FTUN_E_AGAIN;
    if (connection->child != NULL) {
      status = ftun_operation_cancel(connection->child);
      return status == FTUN_OK || status == FTUN_E_STALE ? FTUN_E_AGAIN : status;
    }
    status = ftun_socks5_cancel_sources(connection);
    if (status == FTUN_OK) status = ftun_socks5_close_sockets(connection);
    if (status == FTUN_OK) status = ftun_event_source_cancel(&connection->pump_source);
    return status;
  }
  if (connection->child != NULL) {
    if (connection->cancelling) return FTUN_E_AGAIN;
    status = ftun_operation_cancel(connection->child);
    if (status != FTUN_OK) return status;
    connection->cancelling = 1;
    return FTUN_E_AGAIN;
  }
  status = ftun_socks5_cancel_sources(connection);
  if (status != FTUN_OK) return status;
  return ftun_socks5_close_sockets(connection);
}

static void ftun_socks5_release_context(
  ftun_socks5_connection_t *connection)
{
  ftun_reservation_t *reservation;
  ftun_network_view_t *network_view;
  if (connection == NULL) return;
  reservation = connection->reservation;
  network_view = connection->network_view;
  connection->reservation = NULL;
  connection->network_view = NULL;
  (void)ftun_path_scope_release(&connection->scope);
  memset(connection, 0, sizeof(*connection));
  free(connection);
  (void)ftun_network_view_release(&network_view);
  (void)ftun_reservation_release(&reservation);
}

static void ftun_socks5_completed(ftun_operation_t *operation,
                                  ftun_error_t error, void *user)
{
  ftun_socks5_connection_t *connection =
    (ftun_socks5_connection_t *)user;
  ftun_socks5_completion_fn completion;
  void *completion_user;
  if (connection == NULL) return;
  completion = connection->completion;
  completion_user = connection->completion_user;
  connection->operation = NULL;
  if (error.status == FTUN_OK) {
    connection->ready = 1;
    /* UDP 控制端在父完成排队期间也可能关闭，重新读一次以免丢失旧通知。 */
    if (connection->scope != NULL && connection->transport == FTUN_DIAL_UDP) {
      ftun_socks5_path_notify(connection->control_path, FTUN_PATH_READABLE,
        ftun_socks5_error(FTUN_OK, FTUN_SOCKS5_STAGE_UDP_DIAL), connection);
    }
    completion(operation, error, connection, completion_user);
    return;
  }
  (void)ftun_socks5_close_sockets(connection);
  completion(operation, error, NULL, completion_user);
  ftun_socks5_release_context(connection);
}

static ftun_status_t ftun_socks5_finish(
  ftun_socks5_connection_t *connection, ftun_error_t error)
{
  ftun_status_t status;
  if (connection->scope != NULL) return ftun_socks5_owned_finish(connection, error);
  status = ftun_socks5_cancel_sources(connection);
  if (status != FTUN_OK) {
    connection->pending_error = error;
    connection->has_pending_error = 1;
    return status;
  }
  if (error.status != FTUN_OK) (void)ftun_socks5_close_sockets(connection);
  connection->pending_error = error;
  connection->has_pending_error = 0;
  status = ftun_operation_complete(connection->completion_token, error);
  if (status != FTUN_OK && error.status == FTUN_OK) {
    (void)ftun_socks5_close_sockets(connection);
  }
  return status;
}

static int ftun_socks5_retryable(ftun_status_t status)
{
  return status == FTUN_E_REJECTED || status == FTUN_E_IO ||
         status == FTUN_E_TIMEOUT;
}

static void ftun_socks5_child_completed(ftun_operation_t *operation,
                                        ftun_error_t error,
                                        const ftun_dial_result_t *result,
                                        void *user);

static ftun_status_t ftun_socks5_start_proxy_attempt(
  ftun_socks5_connection_t *connection)
{
  ftun_status_t status = FTUN_E_REJECTED;
  while (connection->next_proxy_candidate <
         connection->proxy_candidate_count) {
    ftun_dial_request_t request;
    size_t index = connection->next_proxy_candidate++;
    memset(&request, 0, sizeof(request));
    request.loop = connection->loop;
    request.operations = connection->operations;
    request.budget = connection->budget;
    request.endpoint = connection->proxy_candidates[index];
    request.allowed = connection->proxy_candidates;
    request.allowed_count = connection->proxy_candidate_count;
    request.network_view = connection->network_view;
    request.network_generation = connection->network_generation;
    request.requested_domain = connection->requested_domain;
    request.protection = connection->protection;
    request.deadline_ms = connection->deadline_ms;
    request.transport = FTUN_DIAL_TCP;
    request.purpose = FTUN_DIAL_PURPOSE_PROXY;
    request.completion = ftun_socks5_child_completed;
    request.user = connection;
    if (connection->scope != NULL) {
      ftun_path_open_request_t channel = {0};
      channel.dial = request;
      channel.dial.completion = NULL;
      channel.dial.user = NULL;
      channel.stream = connection->stream_options;
      channel.completion = ftun_socks5_path_completed;
      channel.user = connection;
      channel.notify = ftun_socks5_path_notify;
      channel.notify_user = connection;
      status = ftun_path_scope_open(connection->scope, connection->core, &channel, &connection->child);
    } else if (connection->custom_dial_io) {
      status = ftun_dial_start_with_io(connection->core, &request,
                                       &connection->dial_io,
                                       &connection->child);
    } else {
      status = ftun_dial_start(connection->core, &request,
                               &connection->child);
    }
    if (status == FTUN_OK) return FTUN_OK;
    connection->child = NULL;
    if (!ftun_socks5_retryable(status)) return status;
  }
  return status;
}

static ftun_status_t ftun_socks5_watch(
  ftun_socks5_connection_t *connection, uint32_t interests);
static void ftun_socks5_io_ready(ftun_event_source_t *source,
                                 uint32_t events, void *user);
static void ftun_socks5_timer_ready(ftun_event_source_t *source,
                                    uint32_t events, void *user);

static ftun_status_t ftun_socks5_watch(
  ftun_socks5_connection_t *connection, uint32_t interests)
{
  ftun_status_t status;
  if (connection->scope != NULL) return ftun_socks5_schedule(connection);
  status = ftun_event_source_cancel(&connection->io_source);
  if (status != FTUN_OK) return status;
  return ftun_event_io_start(connection->loop, connection->control_socket,
                             interests | FTUN_EVENT_ERROR,
                             ftun_socks5_io_ready, connection,
                             &connection->io_source);
}

static ftun_status_t ftun_socks5_prepare_method(
  ftun_socks5_connection_t *connection)
{
  uint8_t method;
  ftun_bytes_t methods;
  method = connection->username_length == 0u ?
           FTUN_SOCKS5_METHOD_NO_AUTH :
           FTUN_SOCKS5_METHOD_USERNAME_PASSWORD;
  methods.data = &method;
  methods.length = 1u;
  connection->output_offset = 0u;
  return ftun_socks5_encode_method_offer(methods, connection->output,
                                         sizeof(connection->output),
                                         &connection->output_length);
}

static ftun_status_t ftun_socks5_prepare_auth(
  ftun_socks5_connection_t *connection)
{
  ftun_bytes_t username;
  ftun_bytes_t password;
  username.data = connection->username;
  username.length = connection->username_length;
  password.data = connection->password;
  password.length = connection->password_length;
  connection->output_offset = 0u;
  return ftun_socks5_encode_credentials(username, password,
                                        connection->output,
                                        sizeof(connection->output),
                                        &connection->output_length);
}

static ftun_status_t ftun_socks5_prepare_request(
  ftun_socks5_connection_t *connection)
{
  ftun_endpoint_t endpoint;
  ftun_socks5_command_t command;
  if (connection->transport == FTUN_DIAL_TCP) {
    endpoint = connection->target;
    command = FTUN_SOCKS5_COMMAND_CONNECT;
  } else {
    memset(&endpoint, 0, sizeof(endpoint));
    endpoint.kind = FTUN_ADDRESS_IPV4;
    command = FTUN_SOCKS5_COMMAND_UDP_ASSOCIATE;
  }
  connection->output_offset = 0u;
  return ftun_socks5_encode_request(command, &endpoint,
                                    connection->output,
                                    sizeof(connection->output),
                                    &connection->output_length);
}

static ftun_status_t ftun_socks5_begin_handshake(
  ftun_socks5_connection_t *connection)
{
  ftun_status_t status;
  status = ftun_event_timer_start(connection->loop, connection->deadline_ms,
                                  ftun_socks5_timer_ready, connection,
                                  &connection->timer_source);
  if (status != FTUN_OK) return status;
  status = ftun_socks5_prepare_method(connection);
  if (status != FTUN_OK) return status;
  connection->state = FTUN_SOCKS5_STATE_WRITE_METHOD;
  return ftun_socks5_watch(connection, FTUN_EVENT_WRITE);
}

static size_t ftun_socks5_input_needed(
  const ftun_socks5_connection_t *connection)
{
  if (connection->state == FTUN_SOCKS5_STATE_READ_METHOD ||
      connection->state == FTUN_SOCKS5_STATE_READ_AUTH) return 2u;
  if (connection->state != FTUN_SOCKS5_STATE_READ_REPLY) return 0u;
  if (connection->input_length < 4u) return 4u;
  if (connection->input[3] == 0x01u) return 10u;
  if (connection->input[3] == 0x03u) {
    if (connection->input_length < 5u) return 5u;
    return 7u + connection->input[4];
  }
  return 4u;
}

static ftun_status_t ftun_socks5_reply_status(uint8_t reply)
{
  switch (reply) {
    case FTUN_SOCKS5_REPLY_SUCCEEDED:
      return FTUN_OK;
    case FTUN_SOCKS5_REPLY_TTL_EXPIRED:
      return FTUN_E_TIMEOUT;
    case FTUN_SOCKS5_REPLY_COMMAND_UNSUPPORTED:
    case FTUN_SOCKS5_REPLY_ADDRESS_UNSUPPORTED:
      return FTUN_E_UNSUPPORTED;
    case FTUN_SOCKS5_REPLY_NOT_ALLOWED:
    case FTUN_SOCKS5_REPLY_NETWORK_UNREACHABLE:
    case FTUN_SOCKS5_REPLY_HOST_UNREACHABLE:
    case FTUN_SOCKS5_REPLY_CONNECTION_REFUSED:
      return FTUN_E_REJECTED;
    case FTUN_SOCKS5_REPLY_GENERAL_FAILURE:
      return FTUN_E_IO;
    default:
      return FTUN_E_PROTOCOL;
  }
}

static int ftun_socks5_ipv4_unspecified(const ftun_endpoint_t *endpoint)
{
  static const uint8_t zero[4] = {0u, 0u, 0u, 0u};
  return endpoint->kind == FTUN_ADDRESS_IPV4 &&
         memcmp(endpoint->address, zero, sizeof(zero)) == 0;
}

static ftun_status_t ftun_socks5_start_udp(
  ftun_socks5_connection_t *connection, const ftun_endpoint_t *relay)
{
  ftun_dial_request_t request;
  ftun_status_t status;
  if (relay->kind == FTUN_ADDRESS_IPV6_RESERVED ||
      relay->kind == FTUN_ADDRESS_DOMAIN) return FTUN_E_UNSUPPORTED;
  if (relay->kind != FTUN_ADDRESS_IPV4 || relay->port == 0u) {
    return FTUN_E_PROTOCOL;
  }
  connection->relay = *relay;
  if (ftun_socks5_ipv4_unspecified(&connection->relay)) {
    memcpy(connection->relay.address, connection->proxy_endpoint.address, 4u);
  }
  status = connection->scope == NULL ? ftun_socks5_cancel_sources(connection) : FTUN_OK;
  if (status != FTUN_OK) return status;
  memset(&request, 0, sizeof(request));
  request.loop = connection->loop;
  request.operations = connection->operations;
  request.budget = connection->budget;
  request.endpoint = connection->relay;
  request.allowed = &connection->relay;
  request.allowed_count = 1u;
  request.network_view = connection->network_view;
  request.network_generation = connection->network_generation;
  /* UDP relay 与已建立的控制 TCP 保持同一网络域，避免代理控制面走
   * Overlay 后由服务端回复的公网 relay 静默切回 Underlay。 */
  request.requested_domain = connection->proxy_domain;
  request.protection = connection->protection;
  request.deadline_ms = connection->deadline_ms;
  request.transport = FTUN_DIAL_UDP;
  request.purpose = FTUN_DIAL_PURPOSE_PROXY;
  request.completion = ftun_socks5_child_completed;
  request.user = connection;
  connection->state = FTUN_SOCKS5_STATE_DIAL_UDP;
  if (connection->scope != NULL) {
    ftun_path_open_request_t channel = {0};
    status = ftun_socks5_datagram_create(connection);
    if (status != FTUN_OK) return status;
    channel.dial = request;
    channel.dial.completion = NULL;
    channel.dial.user = NULL;
    channel.datagram.budget = connection->budget;
    channel.datagram.max_pending_packets = 1u;
    channel.datagram.max_pending_bytes = UINT16_MAX + 263u;
    channel.datagram.result = ftun_socks5_wire_result;
    channel.datagram.receive = ftun_socks5_wire_receive;
    channel.datagram.user = connection;
    channel.completion = ftun_socks5_data_completed;
    channel.user = connection;
    channel.notify = ftun_socks5_path_notify;
    channel.notify_user = connection;
    return ftun_path_scope_open(connection->scope, connection->core, &channel, &connection->child);
  }
  if (connection->custom_dial_io) {
    return ftun_dial_start_with_io(connection->core, &request,
                                   &connection->dial_io,
                                   &connection->child);
  }
  return ftun_dial_start(connection->core, &request, &connection->child);
}

static ftun_status_t ftun_socks5_handle_frame(
  ftun_socks5_connection_t *connection)
{
  ftun_bytes_t input;
  size_t consumed = 0u;
  ftun_status_t status;
  input.data = connection->input;
  input.length = connection->input_length;
  if (connection->state == FTUN_SOCKS5_STATE_READ_METHOD) {
    uint8_t method = 0u;
    uint8_t expected = connection->username_length == 0u ?
                       FTUN_SOCKS5_METHOD_NO_AUTH :
                       FTUN_SOCKS5_METHOD_USERNAME_PASSWORD;
    status = ftun_socks5_decode_method_selection(input, &method, &consumed);
    if (status != FTUN_OK) return status;
    if (method == FTUN_SOCKS5_METHOD_NONE_ACCEPTABLE) return FTUN_E_REJECTED;
    if (method != expected) return FTUN_E_PROTOCOL;
    connection->input_length = 0u;
    if (method == FTUN_SOCKS5_METHOD_USERNAME_PASSWORD) {
      status = ftun_socks5_prepare_auth(connection);
      if (status != FTUN_OK) return status;
      connection->state = FTUN_SOCKS5_STATE_WRITE_AUTH;
    } else {
      status = ftun_socks5_prepare_request(connection);
      if (status != FTUN_OK) return status;
      connection->state = FTUN_SOCKS5_STATE_WRITE_REQUEST;
    }
    return ftun_socks5_watch(connection, FTUN_EVENT_WRITE);
  }
  if (connection->state == FTUN_SOCKS5_STATE_READ_AUTH) {
    uint8_t auth_status = 0u;
    status = ftun_socks5_decode_auth_result(input, &auth_status, &consumed);
    if (status != FTUN_OK) return status;
    if (auth_status != 0u) return FTUN_E_REJECTED;
    connection->input_length = 0u;
    status = ftun_socks5_prepare_request(connection);
    if (status != FTUN_OK) return status;
    connection->state = FTUN_SOCKS5_STATE_WRITE_REQUEST;
    return ftun_socks5_watch(connection, FTUN_EVENT_WRITE);
  }
  if (connection->state == FTUN_SOCKS5_STATE_READ_REPLY) {
    ftun_socks5_reply_t reply;
    status = ftun_socks5_decode_reply(input, &reply, &consumed);
    if (status != FTUN_OK) return status;
    status = ftun_socks5_reply_status(reply.reply);
    if (status != FTUN_OK) return status;
    connection->input_length = 0u;
    if (connection->transport == FTUN_DIAL_TCP) {
      connection->state = FTUN_SOCKS5_STATE_READY;
      connection->data_socket = connection->control_socket;
      return ftun_socks5_finish(connection,
        ftun_socks5_error(FTUN_OK, FTUN_SOCKS5_STAGE_REQUEST));
    }
    return ftun_socks5_start_udp(connection, &reply.endpoint);
  }
  return FTUN_E_STATE_CORRUPT;
}

static ftun_status_t ftun_socks5_process_write(
  ftun_socks5_connection_t *connection)
{
  ftun_status_t status;
  size_t sent = 0u;
  size_t remaining;
  if (connection->scope != NULL) {
    if (connection->write_operation != NULL) return FTUN_E_AGAIN;
    if (connection->write_error != FTUN_OK) return connection->write_error;
    if (connection->output_offset < connection->output_length) {
      ftun_buffer_slice_t slice;
      if (connection->output_slice.owner == NULL) {
        ftun_buffer_t *buffer = NULL;
        uint8_t *data;
        size_t capacity;
        status = ftun_buffer_acquire(connection->budget, connection->output_length, &buffer);
        if (status != FTUN_OK) return status;
        status = ftun_buffer_data(buffer, &data, &capacity);
        if (status == FTUN_OK) {
          memcpy(data, connection->output, connection->output_length);
          status = ftun_buffer_slice(buffer, 0u, connection->output_length, &connection->output_slice);
        }
        (void)ftun_buffer_release(&buffer);
        if (status != FTUN_OK) return status;
      }
      slice = connection->output_slice;
      slice.offset += connection->output_offset;
      slice.length -= connection->output_offset;
      status = ftun_stream_write_ref_with_completion(connection->control_stream, &slice,
        ftun_socks5_write_completed, connection, &sent, &connection->write_operation);
      if (status == FTUN_OK) connection->output_offset += sent;
      return status == FTUN_OK ? FTUN_E_AGAIN : status;
    }
    status = ftun_buffer_slice_release(&connection->output_slice);
    if (status != FTUN_OK) return status;
  } else {
    if (connection->output_offset >= connection->output_length) return FTUN_E_STATE_CORRUPT;
    remaining = connection->output_length - connection->output_offset;
    status = connection->protocol_io.send_socket(
      connection->protocol_io.context, connection->control_socket,
      connection->output + connection->output_offset, remaining, &sent);
    if (status == FTUN_E_AGAIN) return FTUN_OK;
    if (status != FTUN_OK) return status;
    if (sent == 0u || sent > remaining) return FTUN_E_STATE_CORRUPT;
    connection->output_offset += sent;
    if (connection->output_offset != connection->output_length) return FTUN_OK;
  }
  connection->input_length = 0u;
  if (connection->state == FTUN_SOCKS5_STATE_WRITE_METHOD) {
    connection->state = FTUN_SOCKS5_STATE_READ_METHOD;
  } else if (connection->state == FTUN_SOCKS5_STATE_WRITE_AUTH) {
    connection->state = FTUN_SOCKS5_STATE_READ_AUTH;
  } else if (connection->state == FTUN_SOCKS5_STATE_WRITE_REQUEST) {
    connection->state = FTUN_SOCKS5_STATE_READ_REPLY;
  } else {
    return FTUN_E_STATE_CORRUPT;
  }
  return ftun_socks5_watch(connection, FTUN_EVENT_READ);
}

static ftun_status_t ftun_socks5_process_read(
  ftun_socks5_connection_t *connection)
{
  size_t needed = ftun_socks5_input_needed(connection);
  size_t received = 0u;
  ftun_status_t status;
  if (needed == 0u || needed > sizeof(connection->input) ||
      connection->input_length > needed) return FTUN_E_STATE_CORRUPT;
  if (connection->input_length < needed) {
    if (connection->scope != NULL) {
      status = ftun_stream_read(connection->control_stream,
        connection->input + connection->input_length, needed - connection->input_length, &received);
    } else {
      status = connection->protocol_io.receive_socket(
        connection->protocol_io.context, connection->control_socket,
        connection->input + connection->input_length,
        needed - connection->input_length, &received);
    }
    if (status == FTUN_E_AGAIN) return connection->scope != NULL ? FTUN_E_AGAIN : FTUN_OK;
    if (status == FTUN_E_EOF) return FTUN_E_IO;
    if (status != FTUN_OK) return status;
    if (received == 0u || received > needed - connection->input_length) {
      return FTUN_E_STATE_CORRUPT;
    }
    connection->input_length += received;
    needed = ftun_socks5_input_needed(connection);
    if (needed == 0u || needed > sizeof(connection->input) ||
        connection->input_length > needed) return FTUN_E_STATE_CORRUPT;
    if (connection->input_length < needed) return FTUN_OK;
  }
  return ftun_socks5_handle_frame(connection);
}

static uint32_t ftun_socks5_state_stage(
  const ftun_socks5_connection_t *connection)
{
  if (connection->state == FTUN_SOCKS5_STATE_WRITE_METHOD ||
      connection->state == FTUN_SOCKS5_STATE_READ_METHOD) {
    return FTUN_SOCKS5_STAGE_METHOD;
  }
  if (connection->state == FTUN_SOCKS5_STATE_WRITE_AUTH ||
      connection->state == FTUN_SOCKS5_STATE_READ_AUTH) {
    return FTUN_SOCKS5_STAGE_AUTH;
  }
  return FTUN_SOCKS5_STAGE_REQUEST;
}

static void ftun_socks5_io_ready(ftun_event_source_t *source,
                                 uint32_t events, void *user)
{
  ftun_socks5_connection_t *connection =
    (ftun_socks5_connection_t *)user;
  ftun_status_t status;
  uint32_t stage;
  (void)source;
  (void)events;
  if (connection->has_pending_error) {
    (void)ftun_socks5_finish(connection, connection->pending_error);
    return;
  }
  stage = ftun_socks5_state_stage(connection);
  if (connection->state == FTUN_SOCKS5_STATE_WRITE_METHOD ||
      connection->state == FTUN_SOCKS5_STATE_WRITE_AUTH ||
      connection->state == FTUN_SOCKS5_STATE_WRITE_REQUEST) {
    status = ftun_socks5_process_write(connection);
  } else {
    status = ftun_socks5_process_read(connection);
  }
  if (status != FTUN_OK) {
    (void)ftun_socks5_finish(connection, ftun_socks5_error(status, stage));
  }
}

static void ftun_socks5_timer_ready(ftun_event_source_t *source,
                                    uint32_t events, void *user)
{
  ftun_socks5_connection_t *connection =
    (ftun_socks5_connection_t *)user;
  ftun_error_t error;
  (void)source;
  (void)events;
  error = connection->has_pending_error ? connection->pending_error :
          ftun_socks5_error(FTUN_E_TIMEOUT, FTUN_SOCKS5_STAGE_TIMEOUT);
  (void)ftun_socks5_finish(connection, error);
}

static void ftun_socks5_child_completed(ftun_operation_t *operation,
                                        ftun_error_t error,
                                        const ftun_dial_result_t *result,
                                        void *user)
{
  ftun_socks5_connection_t *connection =
    (ftun_socks5_connection_t *)user;
  ftun_status_t status;
  (void)operation;
  if (connection == NULL || result == NULL) return;
  connection->child = NULL;
  if (connection->cancelling) {
    (void)ftun_operation_cancel(connection->operation);
    return;
  }
  if (connection->state == FTUN_SOCKS5_STATE_DIAL_PROXY) {
    if (error.status != FTUN_OK) {
      if (ftun_socks5_retryable(error.status) &&
          connection->next_proxy_candidate <
          connection->proxy_candidate_count) {
        status = ftun_socks5_start_proxy_attempt(connection);
        if (status == FTUN_OK) return;
        error = ftun_socks5_error(status, FTUN_SOCKS5_STAGE_PROXY_DIAL);
      }
      (void)ftun_socks5_finish(connection, error);
      return;
    }
    connection->control_socket = result->socket;
    connection->proxy_endpoint = result->endpoint;
    connection->proxy_domain = result->domain;
    connection->selected_network_generation = result->network_generation;
    status = ftun_socks5_begin_handshake(connection);
    if (status != FTUN_OK) {
      (void)ftun_socks5_finish(connection,
        ftun_socks5_error(status, FTUN_SOCKS5_STAGE_METHOD));
    }
    return;
  }
  if (connection->state == FTUN_SOCKS5_STATE_DIAL_UDP) {
    if (error.status != FTUN_OK) {
      (void)ftun_socks5_finish(connection,
        ftun_socks5_error(error.status, FTUN_SOCKS5_STAGE_UDP_DIAL));
      return;
    }
    connection->data_socket = result->socket;
    connection->state = FTUN_SOCKS5_STATE_READY;
    (void)ftun_socks5_finish(connection,
      ftun_socks5_error(FTUN_OK, FTUN_SOCKS5_STAGE_UDP_DIAL));
    return;
  }
  (void)ftun_socks5_finish(connection,
    ftun_socks5_error(FTUN_E_STATE_CORRUPT, FTUN_SOCKS5_STAGE_PROXY_DIAL));
}

static ftun_status_t ftun_socks5_owned_finish(ftun_socks5_connection_t *connection,
  ftun_error_t error)
{
  ftun_status_t status;
  if (connection->terminal_queued) return FTUN_E_STALE;
  connection->pending_error = error;
  connection->has_pending_error = 1;
  if (connection->scheduled) return FTUN_E_AGAIN;
  /* 工厂可能在结果交付前通知错误，子操作仍拥有结果及其回调上下文。 */
  if (connection->child != NULL) {
    status = ftun_operation_cancel(connection->child);
    return status == FTUN_OK || status == FTUN_E_STALE ? FTUN_E_AGAIN : status;
  }
  status = ftun_socks5_cancel_sources(connection);
  if (status == FTUN_OK && error.status != FTUN_OK) status = ftun_socks5_close_sockets(connection);
  if (status != FTUN_OK) {
    /* write completion 会独立唤醒；其他可重试清理也不能丢失拥有者。 */
    if (connection->write_operation == NULL) (void)ftun_socks5_schedule(connection);
    return status;
  }
  status = ftun_event_source_cancel(&connection->pump_source);
  if (status == FTUN_OK) status = ftun_operation_complete(connection->completion_token, error);
  if (status == FTUN_OK) {
    connection->terminal_queued = true;
    connection->has_pending_error = 0;
  }
  return status;
}

static void ftun_socks5_owned_pump(void *user)
{
  ftun_socks5_connection_t *connection = (ftun_socks5_connection_t *)user;
  size_t work;
  connection->scheduled = false;
  if (connection->terminal_queued || connection->operation == NULL) return;
  if (connection->cancelling) {
    ftun_status_t status = ftun_operation_cancel(connection->operation);
    if (status != FTUN_OK && status != FTUN_E_STALE &&
        connection->child == NULL && connection->write_operation == NULL) {
      (void)ftun_socks5_schedule(connection);
    }
    return;
  }
  connection->busy = true;
  if (connection->has_pending_error) {
    (void)ftun_socks5_owned_finish(connection, connection->pending_error);
    connection->busy = false;
    return;
  }
  for (work = 0u; work < 16u; work++) {
    ftun_status_t status;
    if (connection->state == FTUN_SOCKS5_STATE_DIAL_PROXY ||
        connection->state == FTUN_SOCKS5_STATE_DIAL_UDP ||
        connection->state == FTUN_SOCKS5_STATE_READY || connection->terminal_queued) break;
    if (connection->state == FTUN_SOCKS5_STATE_WRITE_METHOD ||
        connection->state == FTUN_SOCKS5_STATE_WRITE_AUTH ||
        connection->state == FTUN_SOCKS5_STATE_WRITE_REQUEST) {
      status = ftun_socks5_process_write(connection);
    } else status = ftun_socks5_process_read(connection);
    if (status == FTUN_E_AGAIN) break;
    if (status != FTUN_OK) {
      (void)ftun_socks5_owned_finish(connection,
        ftun_socks5_error(status, ftun_socks5_state_stage(connection)));
      break;
    }
  }
  connection->busy = false;
  if (work == 16u) (void)ftun_socks5_schedule(connection);
}

static void ftun_socks5_pump_ready(ftun_event_source_t *source, uint32_t events, void *user)
{
  (void)source;
  (void)events;
  ftun_socks5_owned_pump(user);
}

static ftun_status_t ftun_socks5_schedule(ftun_socks5_connection_t *connection)
{
  ftun_status_t status;
  if (connection->scheduled || connection->terminal_queued || connection->ready) return FTUN_OK;
  status = ftun_event_task_ready(connection->pump_source);
  if (status == FTUN_OK) connection->scheduled = true;
  return status;
}

static void ftun_socks5_write_completed(ftun_operation_t *operation,
  ftun_error_t error, void *user)
{
  ftun_socks5_connection_t *connection = (ftun_socks5_connection_t *)user;
  (void)operation;
  connection->write_operation = NULL;
  connection->write_error = error.status;
  (void)ftun_socks5_schedule(connection);
}

static void ftun_socks5_path_notify(ftun_path_t *path, uint32_t events,
  ftun_error_t error, void *user)
{
  ftun_socks5_connection_t *connection = (ftun_socks5_connection_t *)user;
  if (connection->ready) {
    bool was_busy = connection->busy;
    connection->busy = true;
    if (connection->transport == FTUN_DIAL_UDP && path == connection->control_path &&
        (events & FTUN_PATH_READABLE) != 0u) {
      uint8_t byte;
      size_t length = 0u;
      ftun_status_t status = ftun_stream_read(connection->control_stream, &byte, 1u, &length);
      if (status != FTUN_E_AGAIN) {
        error = ftun_socks5_error(status == FTUN_OK ? FTUN_E_PROTOCOL : status,
          FTUN_SOCKS5_STAGE_UDP_DIAL);
        events |= FTUN_PATH_ERROR;
      }
    }
    if ((events & FTUN_PATH_ERROR) != 0u && error.status != FTUN_OK &&
        error.status != FTUN_E_AGAIN && error.status != FTUN_E_LIMIT) connection->channel_failure = error.status;
    if (connection->notify != NULL) connection->notify(path, events, error, connection->notify_user);
    connection->busy = was_busy;
    return;
  }
  if (connection->terminal_queued || connection->cancelling || connection->has_pending_error) return;
  if ((events & FTUN_PATH_ERROR) != 0u && error.status != FTUN_OK && !connection->has_pending_error) {
    connection->pending_error = error;
    connection->has_pending_error = 1;
  }
  (void)ftun_socks5_schedule(connection);
}

static void ftun_socks5_path_completed(ftun_operation_t *operation,
  ftun_error_t error, ftun_path_t *path, void *user)
{
  ftun_socks5_connection_t *connection = (ftun_socks5_connection_t *)user;
  ftun_path_info_t info;
  ftun_status_t status;
  (void)operation;
  connection->child = NULL;
  connection->control_path = path;
  if (connection->cancelling || connection->has_pending_error) {
    (void)ftun_socks5_schedule(connection);
    return;
  }
  if (error.status != FTUN_OK) {
    if (ftun_socks5_retryable(error.status) &&
        connection->next_proxy_candidate < connection->proxy_candidate_count) {
      status = ftun_socks5_start_proxy_attempt(connection);
      if (status == FTUN_OK) return;
      error = ftun_socks5_error(status, FTUN_SOCKS5_STAGE_PROXY_DIAL);
    }
    (void)ftun_socks5_owned_finish(connection, error);
    return;
  }
  status = ftun_path_get_info(path, &info);
  if (status == FTUN_OK) status = ftun_path_stream(path, &connection->control_stream);
  if (status == FTUN_OK) {
    connection->proxy_endpoint = info.endpoint;
    connection->proxy_domain = info.domain;
    connection->selected_network_generation = info.network_generation;
    status = ftun_socks5_begin_handshake(connection);
  }
  if (status != FTUN_OK) (void)ftun_socks5_owned_finish(connection,
    ftun_socks5_error(status, FTUN_SOCKS5_STAGE_METHOD));
}

static bool ftun_socks5_logical_endpoint_equal(const ftun_endpoint_t *left,
  const ftun_endpoint_t *right)
{
  if (left == NULL || right == NULL || left->kind != right->kind || left->port != right->port) return false;
  if (left->kind == FTUN_ADDRESS_IPV4) return memcmp(left->address, right->address, 4u) == 0;
  return left->kind == FTUN_ADDRESS_DOMAIN && left->domain.length == right->domain.length &&
    memcmp(left->domain.data, right->domain.data, left->domain.length) == 0;
}

static ftun_status_t ftun_socks5_datagram_send_start(void *user,
  ftun_datagram_send_token_t send, const ftun_endpoint_t *target, const ftun_packet_t *packet)
{
  ftun_socks5_connection_t *connection = user;
  ftun_buffer_t *buffer = NULL;
  ftun_buffer_slice_t slice = {0};
  ftun_packet_t wire = {0};
  ftun_bytes_t payload;
  uint8_t *storage;
  size_t capacity, written;
  ftun_status_t status;
  bool was_busy = connection->busy;
  if (!connection->ready || connection->wire_datagram == NULL) return FTUN_E_AGAIN;
  if (connection->channel_failure != FTUN_OK) return connection->channel_failure;
  if (!ftun_socks5_logical_endpoint_equal(target, &connection->target)) return FTUN_E_REJECTED;
  if (connection->datagram_send.channel != NULL) return FTUN_E_AGAIN;
  status = ftun_packet_view(packet, &payload);
  if (status != FTUN_OK) return status;
  if (payload.length > UINT16_MAX) return FTUN_E_LIMIT;
  connection->busy = true;
  status = ftun_buffer_acquire(connection->budget, payload.length + 263u, &buffer);
  if (status == FTUN_OK) status = ftun_buffer_data(buffer, &storage, &capacity);
  if (status == FTUN_OK) status = ftun_socks5_connection_encode_udp(connection,
    payload, storage, capacity, &written);
  if (status == FTUN_OK) status = ftun_buffer_slice(buffer, 0u, written, &slice);
  if (status == FTUN_OK) status = ftun_packet_init(&wire, &slice, packet->source_id);
  if (status == FTUN_OK) {
    connection->datagram_send = send;
    status = ftun_datagram_send(connection->wire_datagram, &connection->relay, &wire);
    if (status != FTUN_OK) memset(&connection->datagram_send, 0, sizeof(connection->datagram_send));
  }
  (void)ftun_packet_release(&wire);
  (void)ftun_buffer_slice_release(&slice);
  (void)ftun_buffer_release(&buffer);
  connection->busy = was_busy;
  return status;
}

static ftun_status_t ftun_socks5_datagram_send_cancel(void *user,
  ftun_datagram_send_token_t send)
{
  ftun_socks5_connection_t *connection = user;
  ftun_status_t status;
  if (connection->datagram_send.channel != send.channel ||
      connection->datagram_send.slot != send.slot ||
      connection->datagram_send.generation != send.generation) return FTUN_E_STALE;
  connection->cancelling_send = true;
  status = ftun_datagram_stop(connection->wire_datagram);
  connection->cancelling_send = false;
  if (status == FTUN_OK) memset(&connection->datagram_send, 0, sizeof(connection->datagram_send));
  return status;
}

static void ftun_socks5_datagram_destroy(void *user)
{
  /* connection 拥有控制/物理通道；逻辑 Datagram 销毁不能提前释放它。 */
  (void)user;
}

static ftun_status_t ftun_socks5_datagram_create(ftun_socks5_connection_t *connection)
{
  ftun_datagram_options_t options = connection->datagram_options;
  ftun_datagram_backend_t backend = {0};
  if (options.budget == NULL) options.budget = connection->budget;
  backend.context = connection;
  backend.send_start = ftun_socks5_datagram_send_start;
  backend.send_cancel = ftun_socks5_datagram_send_cancel;
  backend.destroy = ftun_socks5_datagram_destroy;
  return ftun_datagram_create(&options, &backend, &connection->datagram);
}

static void ftun_socks5_wire_result(ftun_datagram_t *channel, ftun_error_t error,
  const ftun_endpoint_t *target, const ftun_packet_t *packet, void *user)
{
  ftun_socks5_connection_t *connection = user;
  ftun_datagram_send_token_t send = connection->datagram_send;
  bool was_busy = connection->busy;
  (void)channel;
  (void)target;
  (void)packet;
  /* 外层 cancel hook 执行期间不能完成它的 token；由 hook 的 OK 终结。 */
  if (connection->cancelling_send) return;
  connection->busy = true;
  if (send.channel != NULL && ftun_datagram_send_complete(send, error) == FTUN_OK) {
    memset(&connection->datagram_send, 0, sizeof(connection->datagram_send));
  }
  connection->busy = was_busy;
}

static ftun_status_t ftun_socks5_wire_receive(ftun_datagram_t *channel,
  const ftun_endpoint_t *source, const ftun_packet_t *packet, void *user)
{
  ftun_socks5_connection_t *connection = user;
  ftun_socks5_udp_datagram_t decoded;
  ftun_packet_t logical = {0};
  ftun_buffer_slice_t slice;
  ftun_bytes_t wire;
  size_t consumed = 0u;
  ftun_status_t status;
  bool was_busy = connection->busy;
  (void)channel;
  if (!connection->ready) return FTUN_E_AGAIN;
  if (connection->datagram == NULL) return FTUN_E_CANCELLED;
  status = ftun_packet_view(packet, &wire);
  if (status == FTUN_OK) status = ftun_socks5_connection_decode_udp(connection, source, wire, &decoded, &consumed);
  if (status != FTUN_OK || consumed != wire.length) return FTUN_OK;
  if (!ftun_socks5_logical_endpoint_equal(&decoded.endpoint, &connection->target) &&
      !(connection->target.kind == FTUN_ADDRESS_DOMAIN && decoded.endpoint.kind == FTUN_ADDRESS_IPV4 &&
        decoded.endpoint.port == connection->target.port)) return FTUN_OK;
  slice = packet->payload;
  slice.offset += wire.length - decoded.payload.length;
  slice.length = decoded.payload.length;
  status = ftun_packet_init(&logical, &slice, packet->source_id);
  connection->busy = true;
  if (status == FTUN_OK) status = ftun_datagram_deliver(connection->datagram,
    &connection->target, &logical);
  (void)ftun_packet_release(&logical);
  connection->busy = was_busy;
  return status;
}

static void ftun_socks5_data_completed(ftun_operation_t *operation,
  ftun_error_t error, ftun_path_t *path, void *user)
{
  ftun_socks5_connection_t *connection = user;
  ftun_status_t status = error.status;
  (void)operation;
  connection->child = NULL;
  connection->data_path = path;
  if (connection->cancelling || connection->has_pending_error) {
    (void)ftun_socks5_schedule(connection);
    return;
  }
  if (status == FTUN_OK) status = ftun_path_datagram(path, &connection->wire_datagram);
  if (status == FTUN_OK) {
    uint8_t byte;
    size_t length = 0u;
    status = ftun_stream_read(connection->control_stream, &byte, 1u, &length);
    status = status == FTUN_E_AGAIN ? FTUN_OK : status == FTUN_OK ? FTUN_E_PROTOCOL : status;
  }
  if (status == FTUN_OK) connection->state = FTUN_SOCKS5_STATE_READY;
  (void)ftun_socks5_owned_finish(connection,
    ftun_socks5_error(status, FTUN_SOCKS5_STAGE_UDP_DIAL));
}

static ftun_status_t ftun_socks5_reject(
  ftun_socks5_connection_t *connection, ftun_status_t original)
{
  ftun_status_t status;
  ftun_status_t cleanup = FTUN_OK;
  status = ftun_operation_set_cancel_hook(connection->operation, NULL, NULL);
  if (status != FTUN_OK) cleanup = status;
  status = ftun_operation_reject(&connection->operation);
  if (status != FTUN_OK && cleanup == FTUN_OK) cleanup = status;
  if (connection->operation == NULL) {
    (void)ftun_event_source_cancel(&connection->pump_source);
    (void)ftun_socks5_close_sockets(connection);
    ftun_socks5_release_context(connection);
  }
  return cleanup == FTUN_OK ? original : cleanup;
}

static ftun_status_t ftun_socks5_connect_internal(
  ftun_core_t *core, const ftun_socks5_connect_request_t *request,
  const ftun_dial_io_t *dial_io, const ftun_socks5_io_t *protocol_io,
  ftun_operation_t **out)
{
  ftun_socks5_connection_t *connection;
  ftun_reservation_t *reservation = NULL;
  ftun_endpoint_t target;
  ftun_status_t status;
  size_t proxy_candidate_count = 0u;
  size_t allocation_size;
  if (out != NULL) *out = NULL;
  if (out == NULL || !ftun_socks5_request_valid(request) ||
      (dial_io != NULL && !ftun_socks5_dial_io_valid(dial_io)) ||
      (protocol_io != NULL && !ftun_socks5_protocol_io_valid(protocol_io))) {
    return FTUN_E_INVALID;
  }
  if (request->scope != NULL) {
    uint64_t generation;
    if (dial_io != NULL || protocol_io != NULL) return FTUN_E_INVALID;
    status = ftun_path_scope_generation(request->scope, &generation);
    if (status != FTUN_OK) return status;
    if (generation != request->target->generation) return FTUN_E_STALE;
    if (request->transport == FTUN_DIAL_UDP && request->datagram.budget != NULL) {
      bool same = false;
      status = ftun_budget_same_root(request->budget, request->datagram.budget, &same);
      if (status != FTUN_OK || !same) return status == FTUN_OK ? FTUN_E_INVALID : status;
    }
  }
  if (request->transport == FTUN_DIAL_UDP && !request->proxy->udp_enabled) {
    return FTUN_E_UNSUPPORTED;
  }
  status = ftun_socks5_proxy_validate(request->proxy,
                                      &proxy_candidate_count);
  if (status != FTUN_OK) return status;
  status = ftun_socks5_target_select(request->target, &target);
  if (status != FTUN_OK) return status;
  if (proxy_candidate_count >
      (SIZE_MAX - sizeof(*connection)) / sizeof(*connection->proxy_candidates)) {
    return FTUN_E_LIMIT;
  }
  allocation_size = sizeof(*connection) + proxy_candidate_count *
                    sizeof(*connection->proxy_candidates);
  status = ftun_budget_reserve(request->budget, allocation_size, &reservation);
  if (status != FTUN_OK) return status;
  connection = (ftun_socks5_connection_t *)calloc(1u, allocation_size);
  if (connection == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  connection->core = core;
  connection->reservation = reservation;
  if (request->scope != NULL) {
    status = ftun_path_scope_retain(request->scope);
    if (status != FTUN_OK) { ftun_socks5_release_context(connection); return status; }
    connection->scope = request->scope;
    connection->stream_options = request->stream;
    connection->datagram_options = request->datagram;
    connection->notify = request->notify;
    connection->notify_user = request->notify_user;
  }
  connection->loop = request->loop;
  connection->operations = request->operations;
  connection->budget = request->budget;
  connection->proxy_candidates = (ftun_endpoint_t *)(connection + 1);
  connection->proxy_candidate_count = proxy_candidate_count;
  if (request->proxy->server.kind == FTUN_ADDRESS_IPV4) {
    connection->proxy_candidates[0] = request->proxy->server;
  } else {
    memcpy(connection->proxy_candidates, request->proxy->resolved,
           proxy_candidate_count * sizeof(*connection->proxy_candidates));
  }
  if (request->network_view != NULL) {
    status = ftun_network_view_retain((ftun_network_view_t *)
                                      request->network_view);
    if (status != FTUN_OK) {
      ftun_socks5_release_context(connection);
      return status;
    }
    connection->network_view = (ftun_network_view_t *)request->network_view;
  }
  connection->network_generation = request->network_generation;
  connection->requested_domain = request->requested_domain;
  connection->target = target;
  if (target.kind == FTUN_ADDRESS_DOMAIN) {
    memcpy(connection->target_domain, target.domain.data,
           target.domain.length);
    connection->target.domain.data = (const char *)connection->target_domain;
  }
  connection->username_length = request->proxy->username.length;
  connection->password_length = request->proxy->password.length;
  if (connection->username_length != 0u) {
    memcpy(connection->username, request->proxy->username.data,
           connection->username_length);
    memcpy(connection->password, request->proxy->password.data,
           connection->password_length);
  }
  connection->protection.mark = request->protection.mark;
  if (request->protection.interface_name.length != 0u) {
    memcpy(connection->interface_name,
           request->protection.interface_name.data,
           request->protection.interface_name.length);
    connection->protection.interface_name.data = connection->interface_name;
    connection->protection.interface_name.length =
      request->protection.interface_name.length;
  }
  connection->deadline_ms = request->deadline_ms;
  connection->transport = request->transport;
  connection->control_socket = FTUN_INVALID_SOCKET;
  connection->data_socket = FTUN_INVALID_SOCKET;
  connection->completion = request->completion;
  connection->completion_user = request->user;
  connection->protocol_io = protocol_io == NULL ?
                            ftun_socks5_system_io : *protocol_io;
  if (dial_io != NULL) {
    connection->dial_io = *dial_io;
    connection->custom_dial_io = 1;
  }
  connection->state = FTUN_SOCKS5_STATE_DIAL_PROXY;

  status = ftun_operation_accept(request->operations, ftun_socks5_completed,
                                 connection, &connection->operation,
                                 &connection->completion_token);
  if (status != FTUN_OK) {
    ftun_socks5_release_context(connection);
    return status;
  }
  status = ftun_operation_set_cancel_hook(connection->operation,
                                          ftun_socks5_cancel, connection);
  if (status != FTUN_OK) return ftun_socks5_reject(connection, status);
  if (connection->scope != NULL) {
    status = ftun_event_task_start(connection->loop, ftun_socks5_pump_ready,
      connection, &connection->pump_source);
    if (status != FTUN_OK) return ftun_socks5_reject(connection, status);
  }
  status = ftun_socks5_start_proxy_attempt(connection);
  if (status != FTUN_OK) return ftun_socks5_reject(connection, status);
  *out = connection->operation;
  return FTUN_OK;
}

/* TASK-OUTBOUND-004 / TEST-OUTBOUND-004，目标 0.2.0：SOCKS5 出站阶段机。 */
ftun_status_t ftun_socks5_connect_with_io(
  ftun_core_t *core, const ftun_socks5_connect_request_t *request,
  const ftun_dial_io_t *dial_io, const ftun_socks5_io_t *protocol_io,
  ftun_operation_t **out)
{
  if (dial_io == NULL || protocol_io == NULL) {
    if (out != NULL) *out = NULL;
    return FTUN_E_INVALID;
  }
  return ftun_socks5_connect_internal(core, request, dial_io, protocol_io, out);
}

ftun_status_t ftun_socks5_connect(
  ftun_core_t *core, const ftun_socks5_connect_request_t *request,
  ftun_operation_t **out)
{
  return ftun_socks5_connect_internal(core, request, NULL, NULL, out);
}

ftun_status_t ftun_socks5_connection_get_info(
  const ftun_socks5_connection_t *connection,
  ftun_socks5_connection_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (connection == NULL || out == NULL || !connection->ready) {
    return FTUN_E_INVALID;
  }
  out->transport = connection->transport;
  out->control_socket = connection->control_socket;
  out->data_socket = connection->data_socket;
  out->target = connection->target;
  out->relay = connection->relay;
  out->proxy_domain = connection->proxy_domain;
  out->network_generation = connection->selected_network_generation;
  return FTUN_OK;
}

ftun_status_t ftun_socks5_connection_encode_udp(
  const ftun_socks5_connection_t *connection, ftun_bytes_t payload,
  uint8_t *output, size_t capacity, size_t *written)
{
  if (written != NULL) *written = 0u;
  if (connection == NULL || !connection->ready ||
      connection->transport != FTUN_DIAL_UDP) return FTUN_E_INVALID;
  return ftun_socks5_encode_udp_datagram(&connection->target, payload,
                                         output, capacity, written);
}

ftun_status_t ftun_socks5_connection_decode_udp(
  const ftun_socks5_connection_t *connection,
  const ftun_endpoint_t *physical_source, ftun_bytes_t input,
  ftun_socks5_udp_datagram_t *out, size_t *consumed)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (consumed != NULL) *consumed = 0u;
  if (connection == NULL || !connection->ready ||
      connection->transport != FTUN_DIAL_UDP || physical_source == NULL ||
      out == NULL || consumed == NULL) return FTUN_E_INVALID;
  if (!ftun_socks5_endpoint_equal(&connection->relay, physical_source)) {
    return FTUN_E_REJECTED;
  }
  return ftun_socks5_decode_udp_datagram(input, out, consumed);
}

ftun_status_t ftun_socks5_connection_close(
  ftun_socks5_connection_t **connection)
{
  ftun_socks5_connection_t *owned;
  ftun_status_t status;
  if (connection == NULL) return FTUN_E_INVALID;
  owned = *connection;
  if (owned == NULL) return FTUN_OK;
  if (!owned->ready || owned->operation != NULL || owned->child != NULL ||
      owned->io_source != NULL || owned->timer_source != NULL) {
    return FTUN_E_AGAIN;
  }
  if (owned->scope != NULL && (owned->busy || owned->scheduled)) return FTUN_E_AGAIN;
  owned->busy = true;
  status = ftun_socks5_close_sockets(owned);
  owned->busy = false;
  if (owned->scope != NULL && status != FTUN_OK) return status;
  owned->ready = 0;
  ftun_socks5_release_context(owned);
  *connection = NULL;
  return status;
}

ftun_status_t ftun_socks5_connection_path(ftun_socks5_connection_t *connection,
  ftun_path_t **out)
{
  if (out != NULL) *out = NULL;
  if (connection == NULL || out == NULL) return FTUN_E_INVALID;
  if (!connection->ready || connection->scope == NULL ||
      connection->transport != FTUN_DIAL_TCP || connection->control_path == NULL) return FTUN_E_AGAIN;
  *out = connection->control_path;
  return FTUN_OK;
}

ftun_status_t ftun_socks5_connection_datagram(ftun_socks5_connection_t *connection,
  ftun_datagram_t **out)
{
  if (out != NULL) *out = NULL;
  if (connection == NULL || out == NULL) return FTUN_E_INVALID;
  if (!connection->ready || connection->scope == NULL ||
      connection->transport != FTUN_DIAL_UDP || connection->datagram == NULL) return FTUN_E_AGAIN;
  *out = connection->datagram;
  return FTUN_OK;
}

ftun_status_t ftun_socks5_connection_resume(ftun_socks5_connection_t *connection)
{
  if (connection == NULL) return FTUN_E_INVALID;
  if (!connection->ready || connection->data_path == NULL) return FTUN_E_AGAIN;
  return ftun_path_resume(connection->data_path);
}

ftun_status_t ftun_socks5_connection_take_tcp(
  ftun_socks5_connection_t **connection, ftun_native_socket_t *out)
{
  ftun_socks5_connection_t *owned;
  ftun_native_socket_t socket;
  if (out != NULL) *out = FTUN_INVALID_SOCKET;
  if (connection == NULL || out == NULL) return FTUN_E_INVALID;
  owned = *connection;
  if (owned == NULL || !owned->ready || owned->operation != NULL ||
      owned->child != NULL || owned->io_source != NULL ||
      owned->timer_source != NULL || owned->transport != FTUN_DIAL_TCP ||
      owned->control_socket == FTUN_INVALID_SOCKET ||
      owned->data_socket != owned->control_socket) return FTUN_E_AGAIN;
  socket = owned->data_socket;
  owned->data_socket = FTUN_INVALID_SOCKET;
  owned->control_socket = FTUN_INVALID_SOCKET;
  owned->ready = 0;
  ftun_socks5_release_context(owned);
  *connection = NULL;
  *out = socket;
  return FTUN_OK;
}
