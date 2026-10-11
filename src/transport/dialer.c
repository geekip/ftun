#define _GNU_SOURCE 1
#include "dialer.h"
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
  ftun_event_loop_t *loop;
  ftun_operation_t *operation;
  ftun_event_source_t *io_source;
  ftun_event_source_t *timer_source;
  ftun_reservation_t *reservation;
  ftun_dial_io_t io;
  ftun_dial_result_t result;
  ftun_dial_completion_fn completion;
  void *completion_user;
  ftun_socket_policy_t policy;
  char interface_name[FTUN_LINUX_SOCKET_DEVICE_BYTES];
  ftun_error_t pending_error;
  int has_pending_error;
} ftun_dial_context_t;

static ftun_error_t ftun_dial_error(ftun_status_t status, uint32_t stage)
{
  ftun_error_t error;
  memset(&error, 0, sizeof(error));
  error.status = status;
  error.stage = stage;
  return error;
}

static int ftun_dial_transport_valid(ftun_dial_transport_t transport)
{
  return transport == FTUN_DIAL_TCP || transport == FTUN_DIAL_UDP;
}

static int ftun_dial_purpose_valid(ftun_dial_purpose_t purpose)
{
  return purpose >= FTUN_DIAL_PURPOSE_BUSINESS &&
         purpose <= FTUN_DIAL_PURPOSE_FRS_UPDATE;
}

static int ftun_dial_io_valid(const ftun_dial_io_t *io)
{
  return io != NULL && io->open_socket != NULL && io->protect_socket != NULL &&
         io->connect_socket != NULL && io->get_socket_error != NULL &&
         io->close_socket != NULL;
}

static int ftun_dial_request_valid(const ftun_dial_request_t *request)
{
  if (request == NULL || request->loop == NULL || request->operations == NULL ||
      request->budget == NULL || request->completion == NULL ||
      request->endpoint.kind != FTUN_ADDRESS_IPV4 ||
      request->endpoint.port == 0u || request->protection.mark == 0u ||
      !ftun_dial_transport_valid(request->transport) ||
      !ftun_dial_purpose_valid(request->purpose)) return 0;
  if (request->protection.interface_name.length >=
      FTUN_LINUX_SOCKET_DEVICE_BYTES) return 0;
  if (request->protection.interface_name.length != 0u &&
      request->protection.interface_name.data == NULL) return 0;
  return 1;
}

static ftun_status_t ftun_dial_errno_status(int error_code)
{
  if (error_code == 0) return FTUN_OK;
  if (error_code == EINPROGRESS || error_code == EALREADY ||
      error_code == EAGAIN) return FTUN_E_AGAIN;
#if EWOULDBLOCK != EAGAIN
  if (error_code == EWOULDBLOCK) return FTUN_E_AGAIN;
#endif
  if (error_code == ETIMEDOUT) return FTUN_E_TIMEOUT;
  if (error_code == ENOMEM || error_code == ENOBUFS || error_code == EMFILE ||
      error_code == ENFILE) return FTUN_E_LIMIT;
  if (error_code == EAFNOSUPPORT || error_code == EPROTONOSUPPORT ||
      error_code == EOPNOTSUPP) return FTUN_E_UNSUPPORTED;
  if (error_code == EBADF || error_code == ENOTSOCK || error_code == EINVAL) {
    return FTUN_E_INVALID;
  }
  if (error_code == EACCES || error_code == EPERM || error_code == ECONNREFUSED ||
      error_code == ENETUNREACH || error_code == EHOSTUNREACH) {
    return FTUN_E_REJECTED;
  }
  return FTUN_E_IO;
}

static ftun_status_t ftun_system_open_socket(void *context,
                                               ftun_dial_transport_t transport,
                                               ftun_native_socket_t *out)
{
  int descriptor;
  int type;
  int protocol;
  (void)context;
  if (out != NULL) *out = FTUN_INVALID_SOCKET;
  if (out == NULL || !ftun_dial_transport_valid(transport)) return FTUN_E_INVALID;
  type = transport == FTUN_DIAL_TCP ? SOCK_STREAM : SOCK_DGRAM;
  protocol = transport == FTUN_DIAL_TCP ? IPPROTO_TCP : IPPROTO_UDP;
  descriptor = socket(AF_INET, type | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
  if (descriptor < 0) return ftun_dial_errno_status(errno);
  *out = (ftun_native_socket_t)(unsigned int)descriptor;
  return FTUN_OK;
}

static ftun_status_t ftun_system_protect_socket(
  void *context, ftun_native_socket_t socket,
  const ftun_socket_policy_t *policy)
{
  (void)context;
  return ftun_linux_socket_protect(socket, policy);
}

static ftun_status_t ftun_system_connect_socket(
  void *context, ftun_native_socket_t socket, const ftun_endpoint_t *endpoint)
{
  struct sockaddr_in address;
  int descriptor;
  (void)context;
  if (socket > (ftun_native_socket_t)INT_MAX || endpoint == NULL ||
      endpoint->kind != FTUN_ADDRESS_IPV4 || endpoint->port == 0u) {
    return FTUN_E_INVALID;
  }
  descriptor = (int)socket;
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_port = htons(endpoint->port);
  memcpy(&address.sin_addr.s_addr, endpoint->address,
         sizeof(address.sin_addr.s_addr));
  if (connect(descriptor, (const struct sockaddr *)&address,
              (socklen_t)sizeof(address)) == 0) return FTUN_OK;
  if (errno == EISCONN) return FTUN_OK;
  return ftun_dial_errno_status(errno);
}

static ftun_status_t ftun_system_get_socket_error(void *context,
                                                   ftun_native_socket_t socket)
{
  socklen_t length;
  int descriptor;
  int error_code = 0;
  (void)context;
  if (socket > (ftun_native_socket_t)INT_MAX) return FTUN_E_INVALID;
  descriptor = (int)socket;
  length = (socklen_t)sizeof(error_code);
  if (getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &error_code, &length) < 0) {
    return ftun_dial_errno_status(errno);
  }
  if (length != (socklen_t)sizeof(error_code)) return FTUN_E_IO;
  return ftun_dial_errno_status(error_code);
}

static ftun_status_t ftun_system_close_socket(void *context,
                                               ftun_native_socket_t socket)
{
  int descriptor;
  (void)context;
  if (socket > (ftun_native_socket_t)INT_MAX) return FTUN_E_INVALID;
  descriptor = (int)socket;
  if (close(descriptor) != 0) return ftun_dial_errno_status(errno);
  return FTUN_OK;
}

static const ftun_dial_io_t ftun_system_dial_io = {
  ftun_system_open_socket,
  ftun_system_protect_socket,
  ftun_system_connect_socket,
  ftun_system_get_socket_error,
  ftun_system_close_socket,
  NULL
};

static ftun_status_t ftun_dial_cancel_sources(ftun_dial_context_t *context)
{
  ftun_status_t status;
  status = ftun_event_source_cancel(&context->io_source);
  if (status != FTUN_OK) return status;
  return ftun_event_source_cancel(&context->timer_source);
}

static ftun_status_t ftun_dial_close(ftun_dial_context_t *context)
{
  ftun_status_t status;
  if (context->result.socket == FTUN_INVALID_SOCKET) return FTUN_OK;
  status = context->io.close_socket(context->io.context, context->result.socket);
  context->result.socket = FTUN_INVALID_SOCKET;
  return status;
}

static ftun_status_t ftun_dial_cancel(void *user)
{
  ftun_dial_context_t *context = (ftun_dial_context_t *)user;
  ftun_status_t status;
  if (context == NULL) return FTUN_E_INVALID;
  status = ftun_dial_cancel_sources(context);
  if (status != FTUN_OK) return status;
  return ftun_dial_close(context);
}

static void ftun_dial_completed(ftun_operation_t *operation,
                                ftun_error_t error, void *user)
{
  ftun_dial_context_t *context = (ftun_dial_context_t *)user;
  ftun_reservation_t *reservation;
  ftun_dial_completion_fn completion;
  void *completion_user;
  if (context == NULL) return;
  if (error.status != FTUN_OK) {
    (void)ftun_dial_close(context);
  }
  completion = context->completion;
  completion_user = context->completion_user;
  reservation = context->reservation;
  context->operation = NULL;
  context->reservation = NULL;
  completion(operation, error, &context->result, completion_user);
  memset(context, 0, sizeof(*context));
  free(context);
  (void)ftun_reservation_release(&reservation);
}

static ftun_status_t ftun_dial_finish(ftun_dial_context_t *context,
                                      ftun_error_t error)
{
  ftun_status_t status;
  status = ftun_dial_cancel_sources(context);
  if (status != FTUN_OK) {
    context->pending_error = error;
    context->has_pending_error = 1;
    return status;
  }
  if (error.status != FTUN_OK) (void)ftun_dial_close(context);
  context->pending_error = error;
  context->has_pending_error = 0;
  return ftun_operation_complete(context->operation, error);
}

static void ftun_dial_io_ready(ftun_event_source_t *source,
                               uint32_t events, void *user)
{
  ftun_dial_context_t *context = (ftun_dial_context_t *)user;
  ftun_status_t status;
  (void)source;
  (void)events;
  if (context->has_pending_error) {
    (void)ftun_dial_finish(context, context->pending_error);
    return;
  }
  status = context->io.get_socket_error(context->io.context,
                                        context->result.socket);
  if (status == FTUN_E_AGAIN) return;
  (void)ftun_dial_finish(context,
    ftun_dial_error(status, FTUN_DIAL_STAGE_WAIT));
}

static void ftun_dial_timer_ready(ftun_event_source_t *source,
                                  uint32_t events, void *user)
{
  ftun_dial_context_t *context = (ftun_dial_context_t *)user;
  ftun_error_t error;
  (void)source;
  (void)events;
  error = context->has_pending_error ? context->pending_error :
          ftun_dial_error(FTUN_E_TIMEOUT, FTUN_DIAL_STAGE_TIMEOUT);
  (void)ftun_dial_finish(context, error);
}

static void ftun_dial_release_context(ftun_dial_context_t *context)
{
  ftun_reservation_t *reservation;
  if (context == NULL) return;
  reservation = context->reservation;
  context->reservation = NULL;
  memset(context, 0, sizeof(*context));
  free(context);
  (void)ftun_reservation_release(&reservation);
}

static ftun_status_t ftun_dial_reject(ftun_dial_context_t *context,
                                      ftun_status_t original)
{
  ftun_status_t status;
  ftun_status_t cleanup = FTUN_OK;
  status = ftun_dial_cancel_sources(context);
  if (status != FTUN_OK) return status;
  status = ftun_dial_close(context);
  if (status != FTUN_OK) cleanup = status;
  status = ftun_operation_set_cancel_hook(context->operation, NULL, NULL);
  if (status != FTUN_OK && cleanup == FTUN_OK) cleanup = status;
  status = ftun_operation_reject(&context->operation);
  if (status != FTUN_OK && cleanup == FTUN_OK) cleanup = status;
  if (context->operation == NULL) ftun_dial_release_context(context);
  return cleanup == FTUN_OK ? original : cleanup;
}

/* TASK-TRANSPORT-001 / TEST-TRANSPORT-001，目标 0.2.0：唯一物理拨号入口。 */
ftun_status_t ftun_dial_start_with_io(ftun_core_t *core,
                                      const ftun_dial_request_t *request,
                                      const ftun_dial_io_t *io,
                                      ftun_operation_t **out)
{
  ftun_dial_context_t *context;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  (void)core;
  if (out != NULL) *out = NULL;
  if (out == NULL || !ftun_dial_request_valid(request) ||
      !ftun_dial_io_valid(io)) return FTUN_E_INVALID;

  status = ftun_budget_reserve(request->budget, sizeof(*context), &reservation);
  if (status != FTUN_OK) return status;
  context = (ftun_dial_context_t *)calloc(1u, sizeof(*context));
  if (context == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  context->loop = request->loop;
  context->reservation = reservation;
  context->io = *io;
  context->result.socket = FTUN_INVALID_SOCKET;
  context->result.endpoint = request->endpoint;
  context->result.endpoint.domain.data = NULL;
  context->result.endpoint.domain.length = 0u;
  context->result.transport = request->transport;
  context->result.purpose = request->purpose;
  context->completion = request->completion;
  context->completion_user = request->user;
  context->policy.mark = request->protection.mark;
  if (request->protection.interface_name.length != 0u) {
    memcpy(context->interface_name, request->protection.interface_name.data,
           request->protection.interface_name.length);
    context->policy.interface_name.data = context->interface_name;
    context->policy.interface_name.length =
      request->protection.interface_name.length;
  }

  status = ftun_operation_accept(request->operations, ftun_dial_completed,
                                 context, &context->operation);
  if (status != FTUN_OK) {
    ftun_dial_release_context(context);
    return status;
  }
  status = ftun_operation_set_cancel_hook(context->operation,
                                          ftun_dial_cancel, context);
  if (status != FTUN_OK) return ftun_dial_reject(context, status);

  status = context->io.open_socket(context->io.context, request->transport,
                                   &context->result.socket);
  if (status != FTUN_OK) return ftun_dial_reject(context, status);
  if (context->result.socket == FTUN_INVALID_SOCKET) {
    return ftun_dial_reject(context, FTUN_E_STATE_CORRUPT);
  }
  status = context->io.protect_socket(context->io.context,
                                      context->result.socket,
                                      &context->policy);
  if (status != FTUN_OK) return ftun_dial_reject(context, status);
  status = context->io.connect_socket(context->io.context,
                                      context->result.socket,
                                      &context->result.endpoint);
  if (status == FTUN_OK) {
    status = ftun_operation_complete(context->operation,
      ftun_dial_error(FTUN_OK, FTUN_DIAL_STAGE_CONNECT));
    if (status != FTUN_OK) return ftun_dial_reject(context, status);
    *out = context->operation;
    return FTUN_OK;
  }
  if (status != FTUN_E_AGAIN) return ftun_dial_reject(context, status);

  status = ftun_event_timer_start(context->loop, request->deadline_ms,
                                  ftun_dial_timer_ready, context,
                                  &context->timer_source);
  if (status != FTUN_OK) return ftun_dial_reject(context, status);
  status = ftun_event_io_start(context->loop, context->result.socket,
                               FTUN_EVENT_WRITE | FTUN_EVENT_ERROR,
                               ftun_dial_io_ready, context,
                               &context->io_source);
  if (status != FTUN_OK) {
    ftun_status_t cleanup = ftun_event_source_cancel(&context->timer_source);
    if (cleanup != FTUN_OK) {
      context->pending_error = ftun_dial_error(status, FTUN_DIAL_STAGE_WAIT);
      context->has_pending_error = 1;
      *out = context->operation;
      return FTUN_OK;
    }
    return ftun_dial_reject(context, status);
  }
  *out = context->operation;
  return FTUN_OK;
}

ftun_status_t ftun_dial_start(ftun_core_t *core,
                              const ftun_dial_request_t *request,
                              ftun_operation_t **out)
{
  return ftun_dial_start_with_io(core, request, &ftun_system_dial_io, out);
}
