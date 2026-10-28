#include "transport/socket_path.h"
#include "platform/socket_liveness.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define FTUN_SOCKET_RECEIVE_BYTES 65536u
#define FTUN_SOCKET_UDP_BYTES 65507u
#define FTUN_SOCKET_RECEIVE_QUOTA 16u

typedef struct {
  ftun_budget_t *budget;
  ftun_reservation_t *reservation;
  ftun_buffer_pool_t *receive_pool;
  ftun_event_loop_t *loop;
  ftun_event_source_t *source;
  ftun_event_source_t *flush_source;
  ftun_path_t *path;
  ftun_stream_t *stream;
  ftun_datagram_t *datagram;
  ftun_endpoint_t peer;
  ftun_stream_write_token_t write;
  ftun_datagram_send_token_t send;
  ftun_packet_t received;
  ftun_path_completion_fn completion;
  void *completion_user;
  ftun_path_notify_fn notify;
  void *notify_user;
  size_t offset;
  ftun_status_t failure;
  ftun_status_t send_result;
  int socket;
  bool stopped;
  bool read_armed;
  bool receiving;
  bool received_pending;
  bool send_pending;
  bool write_armed;
  bool send_finished;
} ftun_socket_path_t;

static ftun_status_t ftun_socket_status(int error)
{
  if (error == EAGAIN || error == EWOULDBLOCK || error == EINTR) return FTUN_E_AGAIN;
  if (error == ENOMEM || error == ENOBUFS || error == EMSGSIZE) return FTUN_E_LIMIT;
  if (error == EACCES || error == EPERM || error == ECONNREFUSED) return FTUN_E_REJECTED;
  if (error == ETIMEDOUT) return FTUN_E_TIMEOUT;
  return FTUN_E_IO;
}

static ftun_error_t ftun_socket_error(ftun_status_t status)
{
  ftun_error_t error = {status, 0u, 0};
  return error;
}

static uint32_t ftun_socket_interests(const ftun_socket_path_t *driver)
{
  return FTUN_EVENT_ERROR | (driver->read_armed ? FTUN_EVENT_READ : 0u) |
    (driver->write_armed ? FTUN_EVENT_WRITE : 0u);
}

static ftun_status_t ftun_socket_update(ftun_socket_path_t *driver)
{
  if (driver->source == NULL) return driver->stopped ? FTUN_OK : FTUN_E_AGAIN;
  return ftun_event_io_update(driver->source, ftun_socket_interests(driver));
}

static void ftun_socket_notify(ftun_socket_path_t *driver, uint32_t events,
  ftun_status_t status)
{
  if (!driver->stopped && driver->notify != NULL) {
    driver->notify(driver->path, events, ftun_socket_error(status), driver->notify_user);
  }
}

static ftun_status_t ftun_socket_stop(void *user)
{
  ftun_socket_path_t *driver = (ftun_socket_path_t *)user;
  ftun_status_t status;
  driver->stopped = true;
  driver->read_armed = false;
  status = ftun_event_source_cancel(&driver->flush_source);
  if (status != FTUN_OK) return status;
  return ftun_event_source_cancel(&driver->source);
}

static ftun_status_t ftun_socket_resume(void *user)
{
  ftun_socket_path_t *driver = (ftun_socket_path_t *)user;
  ftun_status_t status;
  if (driver->stopped) return FTUN_E_CANCELLED;
  if (driver->failure != FTUN_OK) return driver->failure;
  driver->read_armed = driver->receiving ||
    (driver->stream != NULL && driver->notify != NULL);
  status = ftun_socket_update(driver);
  if (status != FTUN_OK) return status;
  /* 已从内核读出的背压包无需等待下一次网络事件。 */
  if (driver->received_pending) return ftun_event_io_ready(driver->source, FTUN_EVENT_READ);
  return FTUN_OK;
}

static void ftun_socket_destroy(void *user)
{
  ftun_socket_path_t *driver = (ftun_socket_path_t *)user;
  ftun_reservation_t *reservation = driver->reservation;
  if (driver->received_pending) (void)ftun_packet_release(&driver->received);
  if (driver->socket >= 0) (void)close(driver->socket);
  free(driver);
  (void)ftun_reservation_release(&reservation);
}

static ftun_status_t ftun_socket_local_endpoint(void *user, ftun_endpoint_t *out)
{
  ftun_socket_path_t *driver = (ftun_socket_path_t *)user;
  struct sockaddr_in address;
  socklen_t length = sizeof(address);
  if (driver->stopped || driver->socket < 0) return FTUN_E_CANCELLED;
  if (getsockname(driver->socket, (struct sockaddr *)&address, &length) != 0)
    return ftun_socket_status(errno);
  if (length < sizeof(address) || address.sin_family != AF_INET) return FTUN_E_UNSUPPORTED;
  out->kind = FTUN_ADDRESS_IPV4;
  memcpy(out->address, &address.sin_addr.s_addr, 4u);
  out->port = ntohs(address.sin_port);
  return FTUN_OK;
}

static ftun_status_t ftun_socket_send_progress_query(void *user, uint64_t *acked,
  uint32_t *queued)
{
  ftun_socket_path_t *driver = (ftun_socket_path_t *)user;
  if (driver->stopped || driver->socket < 0) return FTUN_E_CANCELLED;
  return ftun_socket_send_progress(driver->socket, acked, queued);
}

static ftun_status_t ftun_socket_read(void *user, void *buffer, size_t capacity,
  size_t *length)
{
  ftun_socket_path_t *driver = (ftun_socket_path_t *)user;
  ftun_status_t status;
  ssize_t count;
  *length = 0u;
  if (driver->stopped) return FTUN_E_CANCELLED;
  if (driver->failure != FTUN_OK) return driver->failure;
  /* 先订阅，失败时不能消费字节后再向调用方返回零接纳。 */
  if (driver->notify != NULL) {
    driver->read_armed = true;
    status = ftun_socket_update(driver);
    if (status != FTUN_OK) return status;
  }
  count = recv(driver->socket, buffer, capacity, MSG_DONTWAIT);
  if (count > 0) { *length = (size_t)count; return FTUN_OK; }
  status = count == 0 ? FTUN_E_EOF : ftun_socket_status(errno);
  if (status != FTUN_E_AGAIN) {
    driver->read_armed = false;
    (void)ftun_socket_update(driver);
    driver->failure = status;
  }
  return status;
}

static ftun_status_t ftun_socket_write(void *user, ftun_stream_write_token_t token,
  const ftun_buffer_slice_t *slice, size_t *accepted)
{
  ftun_socket_path_t *driver = (ftun_socket_path_t *)user;
  ftun_bytes_t bytes;
  ftun_status_t status;
  ssize_t sent;
  size_t amount;
  *accepted = 0u;
  if (driver->stopped) return FTUN_E_CANCELLED;
  /* 接收 EOF 是半关闭，不禁止反方向继续发送。 */
  if (driver->failure != FTUN_OK && driver->failure != FTUN_E_EOF) return driver->failure;
  if (driver->send_pending) return FTUN_E_AGAIN;
  status = ftun_buffer_slice_data(slice, &bytes);
  if (status != FTUN_OK) return status;
  /* 先保留完成任务，再消费字节；不能在已经发送后报告零接纳。 */
  status = ftun_event_task_ready(driver->flush_source);
  if (status != FTUN_OK) return status;
  amount = bytes.length > 65536u ? 65536u : bytes.length;
  sent = send(driver->socket, bytes.data, amount, MSG_DONTWAIT | MSG_NOSIGNAL);
  status = sent < 0 ? ftun_socket_status(errno)
    : sent == 0 ? FTUN_E_IO : FTUN_OK;
  driver->send_pending = true;
  driver->write = token;
  driver->offset = sent < 0 ? 0u : (size_t)sent;
  driver->send_finished = driver->offset == bytes.length ||
    (status != FTUN_OK && status != FTUN_E_AGAIN);
  driver->send_result = status == FTUN_E_AGAIN ? FTUN_OK : status;
  *accepted = slice->length;
  return FTUN_OK;
}

static ftun_status_t ftun_socket_cancel_pending(ftun_socket_path_t *driver)
{
  ftun_status_t status;
  bool was_armed = driver->write_armed;
  driver->send_pending = false;
  driver->write_armed = false;
  status = ftun_socket_update(driver);
  if (status != FTUN_OK) {
    driver->send_pending = true;
    driver->write_armed = was_armed;
    return status;
  }
  memset(&driver->write, 0, sizeof(driver->write));
  memset(&driver->send, 0, sizeof(driver->send));
  return FTUN_OK;
}

static ftun_status_t ftun_socket_write_cancel(void *user, ftun_stream_write_token_t token)
{
  ftun_socket_path_t *driver = (ftun_socket_path_t *)user;
  if (!driver->send_pending || driver->write.stream != token.stream ||
      driver->write.slot != token.slot || driver->write.generation != token.generation) {
    return FTUN_E_STALE;
  }
  return ftun_socket_cancel_pending(driver);
}

static ftun_status_t ftun_socket_shutdown(void *user)
{
  ftun_socket_path_t *driver = (ftun_socket_path_t *)user;
  if (driver->stopped) return FTUN_E_CANCELLED;
  if (driver->send_pending) return FTUN_E_AGAIN;
  return shutdown(driver->socket, SHUT_WR) == 0 ? FTUN_OK : ftun_socket_status(errno);
}

static ftun_status_t ftun_socket_send(void *user, ftun_datagram_send_token_t token,
  const ftun_endpoint_t *target, const ftun_packet_t *packet)
{
  ftun_socket_path_t *driver = (ftun_socket_path_t *)user;
  ftun_bytes_t bytes;
  ftun_status_t status;
  if (driver->stopped) return FTUN_E_CANCELLED;
  if (driver->failure != FTUN_OK) return driver->failure;
  if (target->kind != FTUN_ADDRESS_IPV4 || target->port != driver->peer.port ||
      memcmp(target->address, driver->peer.address, 4u) != 0) return FTUN_E_REJECTED;
  status = ftun_packet_view(packet, &bytes);
  if (status != FTUN_OK) return status;
  if (bytes.length > FTUN_SOCKET_UDP_BYTES) return FTUN_E_LIMIT;
  if (driver->send_pending) return FTUN_E_AGAIN;
  /* Datagram 允许 start 内完成整包，结果由通道延至 start 返回后交付。
   * 常见可写路径无需额外 owner 回合；真正背压仍使用预留任务与 WRITE。 */
  {
    ssize_t count = send(driver->socket, bytes.data, bytes.length,
      MSG_DONTWAIT | MSG_NOSIGNAL);
    if (count >= 0) {
      if ((size_t)count != bytes.length) return FTUN_E_IO;
      return ftun_datagram_send_complete(token, ftun_socket_error(FTUN_OK));
    }
    status = ftun_socket_status(errno);
    if (status != FTUN_E_AGAIN) return status;
  }
  status = ftun_event_task_ready(driver->flush_source);
  if (status != FTUN_OK) return status;
  driver->send_pending = true;
  driver->send = token;
  driver->send_finished = false;
  driver->send_result = FTUN_OK;
  return FTUN_OK;
}

static ftun_status_t ftun_socket_send_cancel(void *user, ftun_datagram_send_token_t token)
{
  ftun_socket_path_t *driver = (ftun_socket_path_t *)user;
  if (!driver->send_pending || driver->send.channel != token.channel ||
      driver->send.slot != token.slot || driver->send.generation != token.generation) {
    return FTUN_E_STALE;
  }
  return ftun_socket_cancel_pending(driver);
}

static void ftun_socket_flush(ftun_socket_path_t *driver)
{
  ftun_status_t status = FTUN_OK;
  bool was_armed;
  if (!driver->send_pending) return;
  if (!driver->send_finished) {
    ftun_bytes_t bytes;
    const ftun_packet_t *packet;
    const ftun_endpoint_t *target;
    ssize_t count;
    if (driver->stream != NULL) status = ftun_stream_write_data(driver->write, &bytes);
    else {
      status = ftun_datagram_send_view(driver->send, &target, &packet);
      if (status == FTUN_OK) status = ftun_packet_view(packet, &bytes);
    }
    if (status == FTUN_OK) {
      size_t remaining = bytes.length - driver->offset;
      const void *data = remaining == 0u ? NULL : bytes.data + driver->offset;
      size_t amount = driver->stream != NULL && remaining > 65536u ? 65536u : remaining;
      count = send(driver->socket, data, amount, MSG_DONTWAIT | MSG_NOSIGNAL);
      if (count < 0) status = ftun_socket_status(errno);
      else if (driver->stream != NULL) {
        driver->offset += (size_t)count;
        if (count == 0) status = FTUN_E_IO;
        else if (driver->offset < bytes.length) {
          status = ftun_event_task_ready(driver->flush_source);
          if (status == FTUN_OK) return;
        }
      } else if ((size_t)count != bytes.length) status = FTUN_E_IO;
    }
    if (status == FTUN_E_AGAIN) {
      driver->write_armed = true;
      status = ftun_socket_update(driver);
      if (status == FTUN_OK) return;
      driver->write_armed = false;
    }
    driver->send_result = status;
    driver->send_finished = true;
  }
  driver->send_pending = false;
  was_armed = driver->write_armed;
  driver->write_armed = false;
  status = ftun_socket_update(driver);
  if (status != FTUN_OK) {
    driver->send_pending = true;
    driver->write_armed = was_armed;
    ftun_socket_notify(driver, FTUN_PATH_ERROR, status);
    return;
  }
  if (driver->stream != NULL) {
    ftun_stream_write_token_t token = driver->write;
    memset(&driver->write, 0, sizeof(driver->write));
    (void)ftun_stream_write_complete(token, ftun_socket_error(driver->send_result));
  } else {
    ftun_datagram_send_token_t token = driver->send;
    memset(&driver->send, 0, sizeof(driver->send));
    (void)ftun_datagram_send_complete(token, ftun_socket_error(driver->send_result));
  }
  ftun_socket_notify(driver, FTUN_PATH_WRITABLE, driver->send_result);
}

static void ftun_socket_flush_ready(ftun_event_source_t *source,
  uint32_t events, void *user)
{
  ftun_socket_path_t *driver = user;
  ftun_path_t *held = driver->path;
  (void)source;
  (void)events;
  if (driver->stopped || ftun_path_retain(held) != FTUN_OK) return;
  /* owner 任务一次最多发送 64KiB，只有实际背压才订阅内核 WRITE。 */
  ftun_socket_flush(driver);
  (void)ftun_path_release(&held);
}

static ftun_status_t ftun_socket_receive_one(ftun_socket_path_t *driver)
{
  ftun_buffer_t *buffer = NULL;
  ftun_buffer_slice_t slice = {0};
  uint8_t *data;
  size_t capacity;
  ssize_t count;
  ftun_status_t status;
  if (driver->received_pending) return FTUN_OK;
  status = driver->receive_pool == NULL
    ? ftun_buffer_acquire(driver->budget, FTUN_SOCKET_RECEIVE_BYTES, &buffer)
    : ftun_buffer_pool_acquire(driver->receive_pool, FTUN_SOCKET_RECEIVE_BYTES, &buffer);
  if (status != FTUN_OK) return status;
  status = ftun_buffer_data(buffer, &data, &capacity);
  if (status == FTUN_OK) {
    count = recv(driver->socket, data, capacity, MSG_DONTWAIT);
    if (count < 0) status = ftun_socket_status(errno);
    else if ((size_t)count > FTUN_SOCKET_UDP_BYTES) status = FTUN_E_LIMIT;
    else status = ftun_buffer_slice(buffer, 0u, (size_t)count, &slice);
  }
  if (status == FTUN_OK) {
    status = ftun_packet_init(&driver->received, &slice, 0u);
    if (status == FTUN_OK) driver->received_pending = true;
  }
  (void)ftun_buffer_slice_release(&slice);
  (void)ftun_buffer_release(&buffer);
  return status;
}

static void ftun_socket_receive(ftun_socket_path_t *driver)
{
  size_t index;
  for (index = 0u; index < FTUN_SOCKET_RECEIVE_QUOTA && !driver->stopped; index++) {
    ftun_status_t status = ftun_socket_receive_one(driver);
    if (status == FTUN_E_AGAIN) return;
    if (status == FTUN_OK) {
      status = ftun_datagram_deliver(driver->datagram, &driver->peer, &driver->received);
      if (status != FTUN_E_AGAIN && status != FTUN_E_LIMIT) {
        (void)ftun_packet_release(&driver->received);
        driver->received_pending = false;
      }
    }
    if (status != FTUN_OK) {
      driver->read_armed = false;
      if (status != FTUN_E_AGAIN && status != FTUN_E_LIMIT) driver->failure = status;
      (void)ftun_socket_update(driver);
      ftun_socket_notify(driver, FTUN_PATH_ERROR, status);
      return;
    }
  }
}

static void ftun_socket_ready(ftun_event_source_t *source, uint32_t events, void *user)
{
  ftun_socket_path_t *driver = (ftun_socket_path_t *)user;
  ftun_path_t *held = driver->path;
  ftun_status_t status;
  (void)source;
  if (driver->stopped || ftun_path_retain(held) != FTUN_OK) return;
  if ((events & (FTUN_EVENT_WRITE | FTUN_EVENT_ERROR)) != 0u) ftun_socket_flush(driver);
  if (!driver->stopped && driver->read_armed &&
      (events & (FTUN_EVENT_READ | FTUN_EVENT_ERROR)) != 0u) {
    if (driver->datagram != NULL) ftun_socket_receive(driver);
    else {
      driver->read_armed = false;
      status = ftun_socket_update(driver);
      ftun_socket_notify(driver, status == FTUN_OK ? FTUN_PATH_READABLE : FTUN_PATH_ERROR, status);
    }
  }
  (void)ftun_path_release(&held);
}

static void ftun_socket_connected(ftun_operation_t *operation, ftun_error_t error,
  const ftun_dial_result_t *result, void *user)
{
  ftun_socket_path_t *driver = (ftun_socket_path_t *)user;
  ftun_path_completion_fn completion = driver->completion;
  void *completion_user = driver->completion_user;
  if (error.status == FTUN_OK) {
    if (result == NULL || result->socket > (ftun_native_socket_t)INT_MAX) {
      error.status = FTUN_E_STATE_CORRUPT;
    } else {
      driver->socket = (int)result->socket;
      error.status = ftun_event_io_start(driver->loop, result->socket,
        ftun_socket_interests(driver), ftun_socket_ready, driver, &driver->source);
    }
  }
  /* 回调可立即销毁 Path 及 driver，此后不得访问。 */
  completion(operation, error, driver->path, completion_user);
}

ftun_status_t ftun_socket_path_open(void *context, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *spec,
  ftun_operation_t **out)
{
  ftun_socket_path_t *driver;
  ftun_reservation_t *reservation = NULL;
  ftun_path_spec_t adopted;
  ftun_dial_request_t dial;
  ftun_budget_resources_t resources = {0};
  ftun_status_t status;
  (void)context;
  if (out != NULL) *out = NULL;
  if (core == NULL || request == NULL || spec == NULL || out == NULL ||
      request->completion == NULL || request->dial.budget == NULL ||
      request->dial.loop == NULL) return FTUN_E_INVALID;
  if (spec->receive_pool != NULL) {
    ftun_budget_t *pool_budget = NULL;
    bool same_root = false;
    status = ftun_buffer_pool_budget(spec->receive_pool, &pool_budget);
    if (status == FTUN_OK) status = ftun_budget_same_root(
      request->dial.budget, pool_budget, &same_root);
    if (status != FTUN_OK) return status;
    if (!same_root) return FTUN_E_REJECTED;
  }
  resources.memory_bytes = sizeof(*driver);
  resources.descriptors = 1u;
  status = ftun_budget_reserve_resources(request->dial.budget, resources, &reservation);
  if (status != FTUN_OK) return status;
  driver = (ftun_socket_path_t *)calloc(1u, sizeof(*driver));
  if (driver == NULL) { (void)ftun_reservation_release(&reservation); return FTUN_E_LIMIT; }
  driver->reservation = reservation;
  driver->budget = request->dial.budget;
  driver->receive_pool = spec->receive_pool;
  driver->loop = request->dial.loop;
  driver->socket = -1;
  driver->peer = request->dial.endpoint;
  driver->peer.domain.data = NULL;
  driver->peer.domain.length = 0u;
  driver->completion = request->completion;
  driver->completion_user = request->user;
  driver->notify = request->notify;
  driver->notify_user = request->notify_user;
  adopted = *spec;
  adopted.driver.stop = ftun_socket_stop;
  adopted.driver.resume = ftun_socket_resume;
  adopted.driver.context = driver;
  adopted.driver.local_endpoint = ftun_socket_local_endpoint;
  adopted.driver.send_progress = ftun_socket_send_progress_query;
  if (request->dial.transport == FTUN_DIAL_TCP) {
    ftun_stream_options_t options = request->stream;
    ftun_stream_backend_t backend = {0};
    if (options.budget == NULL) options.budget = request->dial.budget;
    if (options.operations == NULL) options.operations = request->dial.operations;
    if (options.operations != request->dial.operations) { ftun_socket_destroy(driver); return FTUN_E_REJECTED; }
    backend.read = ftun_socket_read;
    backend.write_start = ftun_socket_write;
    backend.write_cancel = ftun_socket_write_cancel;
    backend.shutdown_write = ftun_socket_shutdown;
    backend.destroy = ftun_socket_destroy;
    backend.context = driver;
    status = ftun_stream_create(&options, &backend, &driver->stream);
    if (status == FTUN_OK) {
      ftun_stream_t *channel = driver->stream;
      status = ftun_path_adopt_stream(&adopted, &channel, &driver->path);
      if (status != FTUN_OK) {
        (void)ftun_stream_stop(channel);
        (void)ftun_stream_destroy(&channel);
        return status;
      }
    }
  } else if (request->dial.transport == FTUN_DIAL_UDP) {
    ftun_datagram_options_t options = request->datagram;
    ftun_datagram_backend_t backend = {0};
    if (options.budget == NULL) options.budget = request->dial.budget;
    driver->receiving = options.receive != NULL;
    backend.send_start = ftun_socket_send;
    backend.send_cancel = ftun_socket_send_cancel;
    backend.destroy = ftun_socket_destroy;
    backend.context = driver;
    status = ftun_datagram_create(&options, &backend, &driver->datagram);
    if (status == FTUN_OK) {
      ftun_datagram_t *channel = driver->datagram;
      status = ftun_path_adopt_datagram(&adopted, &channel, &driver->path);
      if (status != FTUN_OK) {
        (void)ftun_datagram_stop(channel);
        (void)ftun_datagram_destroy(&channel);
        return status;
      }
    }
  } else status = FTUN_E_INVALID;
  if (status != FTUN_OK) { ftun_socket_destroy(driver); return status; }
  driver->read_armed = driver->receiving ||
    (driver->stream != NULL && driver->notify != NULL);
  dial = request->dial;
  dial.completion = ftun_socket_connected;
  dial.user = driver;
  status = ftun_event_task_start(driver->loop, ftun_socket_flush_ready,
    driver, &driver->flush_source);
  if (status == FTUN_OK) status = ftun_dial_start(core, &dial, out);
  if (status != FTUN_OK) {
    ftun_path_t *path = driver->path;
    (void)ftun_path_revoke(path);
    (void)ftun_path_destroy(&path);
  }
  return status;
}
