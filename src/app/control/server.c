#include "app/control/server.h"
#include "app/control/request.h"
#include "app/control/status.h"
#include "app/control.h"
#include "app/runtime_internal.h"
#include "core/context.h"
#include "app/config/compile.h"
#include "core/event/loop.h"
#include "core/limits.h"
#include "core/log/log.h"
#include "platform/clock.h"
#include "platform/ipc.h"
#include "platform/process.h"
#include "platform/socket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IO_TIMEOUT 5000u
static const ftun_log_event_t connected_event = {FTUN_LOG_CTL, FTUN_LOG_DEBUG, "ctl.client-connected", "client connected"};
static const ftun_log_event_t reload_event = {FTUN_LOG_CTL, FTUN_LOG_INFO, "ctl.reload-requested", "reload requested"};
static const ftun_log_event_t stop_event = {FTUN_LOG_CTL, FTUN_LOG_INFO, "ctl.stop-requested", "stop requested"};
static const ftun_log_event_t result_event = {FTUN_LOG_CTL, FTUN_LOG_INFO, "ctl.result", "result"};
static const ftun_log_event_t rejected_event = {FTUN_LOG_CTL, FTUN_LOG_WARN, "ctl.request-rejected", "request rejected"};
static const ftun_log_event_t busy_event = {FTUN_LOG_CTL, FTUN_LOG_WARN, "ctl.busy", "busy"};
typedef enum { FREE, READING, PARSING, RELOADING, STOPPING, WRITING } phase_t;
typedef struct {
  ftun_ctl_server_t *server;
  ftun_handle_t socket;
  ftun_event_source_t *io;
  phase_t phase;
  uint64_t deadline, operation, previous_generation;
  uint64_t uid;
  bool merged;
  size_t received, length, sent;
  char request[FTUN_CTL_REQUEST_MAX + 1u];
  char response[FTUN_CTL_RESPONSE_MAX];
} connection_t;

struct ftun_ctl_server {
  ftun_core_t *core;
  ftun_budget_t *budget;
  ftun_reservation_t reservation;
  ftun_ipc_listener_t listener;
  ftun_event_loop_t *loop;
  ftun_event_source_t *accept, *timer;
  ftun_status_t error;
  uint64_t boot, operation, reload_operation, accept_after;
  uint64_t timer_deadline;
  uint64_t accepted, rejected, merged, timeouts, write_failed;
  uint64_t reject_entities[7], stop_operation;
  uint64_t reload_uid, stop_uid, queued_reload, queued_uid, queued_at;
  bool reload_pending;
  connection_t connections[FTUN_CTL_CONNECTIONS];
  ftun_ctl_status_t snapshot;
  char path[];
};

static uint64_t clock_now(void)
{
  uint64_t now = 0u;
  (void)ftun_monotonic_now(&now);
  return now;
}

static void control_log(ftun_ctl_server_t *server, const ftun_log_event_t *event,
  uint64_t operation, uint64_t generation, ftun_error_t error, const char *result, uint64_t uid)
{
  if (event->level <= FTUN_LOG_WARN || ftun_log_enabled(server->core, event->level)) {
    ftun_log_field_t fields[] = {
      {.key = "source", .kind = FTUN_LOG_TEXT, .value.text = {"ipc", 3u}},
      {.key = "result", .kind = FTUN_LOG_TEXT, .value.text = {result, strlen(result)}},
      {.key = "uid", .kind = FTUN_LOG_U64, .value.u64 = uid}
    };
    ftun_log_record_t record = {.event = event, .operation = operation, .generation = generation,
      .error = error, .fields = fields, .field_count = uid == UINT64_MAX ? 2u : 3u};
    if (event->level <= FTUN_LOG_WARN) {
      size_t reason = strcmp(result, "invalid-request") == 0 ? 0u :
        strcmp(result, "boot-mismatch") == 0 ? 1u :
        strcmp(result, "peer-credentials") == 0 ? 2u :
        strcmp(result, "connections-full") == 0 ? 3u :
        error.status == FTUN_E_AGAIN ? 4u : error.status == FTUN_E_LIMIT ? 5u : 6u;
      (void)ftun_log_failure(server->core, &record, server->reject_entities[reason],
        (ftun_string_t){result, strlen(result)}, clock_now());
    }
    else (void)ftun_log_record(server->core, &record);
  }
}

static void fault(ftun_ctl_server_t *server, ftun_status_t status)
{
  if (server->error == FTUN_OK && status != FTUN_OK) server->error = status;
}

static void close_connection(connection_t *connection)
{
  if (connection->phase == FREE) return;
  ftun_status_t status = ftun_event_source_cancel(&connection->io);
  if (status != FTUN_OK) { fault(connection->server, FTUN_E_STATE_CORRUPT); return; }
  if (connection->socket >= 0) {
    fault(connection->server, ftun_socket_close((ftun_native_socket_t)connection->socket));
  }
  connection->socket = -1;
  connection->phase = FREE;
}

/* 常量字段直接格式化，外部字符串由cJSON转义到固定缓冲，不创建JSON堆对象。 */
static void reply(connection_t *connection, const char *result, const char *reason,
  uint32_t stage, uint64_t generation, const char *file)
{
  ftun_ctl_server_t *server = connection->server;
  int length = snprintf(connection->response, sizeof(connection->response),
    "{\"result\":\"%s\",\"boot\":\"%016llx\",\"pid\":%u,\"op_id\":%llu,"
    "\"generation\":%llu,\"previous_generation\":%llu,\"merged\":%s,"
    "\"status\":\"%s\",\"stage\":%u,\"file\":", result,
    (unsigned long long)server->boot, ftun_process_id(),
    (unsigned long long)connection->operation, (unsigned long long)generation,
    (unsigned long long)connection->previous_generation, connection->merged ? "true" : "false",
    reason, stage);
  if (length <= 0 || (size_t)length >= sizeof(connection->response)) goto invalid;
  connection->length = (size_t)length;
  size_t quoted = ftun_ctl_json_quote(file == NULL ? "" : file,
    connection->response + connection->length, sizeof(connection->response) - connection->length);
  if (quoted == 0u) goto invalid;
  connection->length += quoted;
  if (connection->length + 3u >= sizeof(connection->response)) goto invalid;
  memcpy(connection->response + connection->length, "}\n", 3u);
  connection->length += 2u;
  connection->sent = 0u;
  connection->phase = WRITING;
  connection->deadline = clock_now() + IO_TIMEOUT;
  if (connection->io != NULL && ftun_event_io_update(connection->io, FTUN_EVENT_WRITE) != FTUN_OK) goto invalid;
  return;
invalid:
  fault(server, FTUN_E_STATE_CORRUPT);
  close_connection(connection);
}

static void reply_config_error(connection_t *connection, const ftun_config_error_t *error)
{
  char detail[14336];
  if (connection->phase != WRITING || error->error.status == FTUN_OK) return;
  size_t length = ftun_config_error_json(error, detail, sizeof(detail));
  if (length == 0u || length + 1u >= sizeof(connection->response) - connection->length) {
    fault(connection->server, FTUN_E_STATE_CORRUPT);
    close_connection(connection);
    return;
  }
  size_t offset = connection->length - 2u;
  connection->response[offset++] = ',';
  memcpy(connection->response + offset, detail + 1u, length - 1u);
  offset += length - 1u;
  connection->response[offset++] = '\n';
  connection->response[offset] = '\0';
  connection->length = offset;
}

static void status_reply(connection_t *connection, ftun_ctl_operation_t operation)
{
  ftun_ctl_server_t *server = connection->server;
  size_t length;
  ftun_status_t status;
  uint32_t module = operation == FTUN_CTL_DNS_STATUS ? FTUN_BUILD_MODULE_DNS :
    operation == FTUN_CTL_PROXY_STATUS ? FTUN_BUILD_MODULE_PROXY : FTUN_BUILD_MODULE_CORE;
  if ((ftun_build_capabilities()->builtins & module) == 0u) {
    reply(connection, "failed", "not-built", 0u, 0u, NULL);
    return;
  }
  status = ftun_ctl_status_fill(server->core, &server->snapshot);
  if (status != FTUN_OK) {
    reply(connection, "failed", ftun_status_name(status), 0u, 0u, NULL);
    return;
  }
  reply(connection, "ok", "ok", 0u, server->snapshot.host.core.generation, NULL);
  if (connection->phase != WRITING) return;
  connection->length -= 2u;
  if (operation == FTUN_CTL_STATUS) {
    int count = snprintf(connection->response + connection->length,
      sizeof(connection->response) - connection->length,
      ",\"control\":{\"accepted\":%llu,\"rejected\":%llu,\"merged\":%llu,"
      "\"timeouts\":%llu,\"write_failed\":%llu}",
      (unsigned long long)server->accepted, (unsigned long long)server->rejected,
      (unsigned long long)server->merged, (unsigned long long)server->timeouts,
      (unsigned long long)server->write_failed);
    if (count < 0 || (size_t)count >= sizeof(connection->response) - connection->length) {
      reply(connection, "failed", "limit", 0u, server->snapshot.host.core.generation, NULL);
      return;
    }
    connection->length += (size_t)count;
  }
  status = ftun_ctl_status_json(&server->snapshot, operation,
    connection->response + connection->length, sizeof(connection->response) - connection->length, &length);
  if (status == FTUN_OK) connection->length += length;
  else reply(connection, "failed", ftun_status_name(status), 0u, server->snapshot.host.core.generation, NULL);
}

static void arm(ftun_ctl_server_t *server);
static void reload_done(ftun_operation_t *operation, ftun_app_command_result_t result, void *user);
static void start_queued_reload(ftun_ctl_server_t *server);

static ftun_status_t submit_reload(ftun_ctl_server_t *server, uint64_t generation)
{
  ftun_app_control_snapshot_t snapshot;
  ftun_app_command_t command = {0};
  ftun_operation_t *operation = NULL;
  ftun_status_t status = ftun_app_control_query(server->core, &snapshot);
  if (status != FTUN_OK) return status;
  command.kind = FTUN_APP_COMMAND_RELOAD;
  command.first = snapshot.config_path;
  command.expected = (ftun_app_generation_guard_t){true, generation};
  status = ftun_app_control_submit(server->core, &command, reload_done, server, &operation);
  server->reload_pending = status == FTUN_OK;
  return status;
}

/* admission为真表示后续批次未能提交：每个仍在等待的请求收到busy/rejected并计入rejected；
 * 已超时或--no-wait已得到回执的请求不重复计数，失败只出现在日志。 */
static void reply_reload(ftun_ctl_server_t *server, ftun_app_command_result_t result, bool admission)
{
  size_t i;
  bool busy = admission && (result.error.status == FTUN_E_AGAIN || result.error.status == FTUN_E_LIMIT);
  const char *outcome = busy ? "busy" : result.error.status == FTUN_OK ? "committed" :
    result.error.status == FTUN_E_RESTART_REQUIRED ? "restart-required" : "rejected";
  const char *reason = admission && result.error.status == FTUN_E_CANCELLED ?
    "not-executed" : ftun_status_name(result.error.status);
  control_log(server, admission ? (busy ? &busy_event : &rejected_event) : &result_event,
    server->reload_operation, result.generation, result.error,
    admission && result.error.status == FTUN_E_CANCELLED ? "not-executed" : outcome, server->reload_uid);
  for (i = 0u; i < FTUN_CTL_CONNECTIONS; i++) {
    connection_t *connection = &server->connections[i];
    if (connection->phase == RELOADING && connection->operation == server->reload_operation) {
      bool expired = clock_now() >= connection->deadline;
      if (expired) server->timeouts++;
      else if (admission) server->rejected++;
      reply(connection, expired ? "timeout" : result.error.status == FTUN_OK ?
        (connection->merged ? "merged" : "committed") :
        outcome, reason, result.error.stage, result.generation, result.file_error);
      if (!expired) reply_config_error(connection, &result.config_error);
    }
  }
}

static void reload_done(ftun_operation_t *operation, ftun_app_command_result_t result, void *user)
{
  ftun_ctl_server_t *server = user;
  (void)operation;
  server->reload_pending = false;
  reply_reload(server, result, false);
  if (server->queued_reload != 0u) {
    ftun_core_info_t info = {0};
    /* 停止期间事件循环不会再轮到定时器：立即判定后续批次，日志此时仍可写。 */
    bool closing = ftun_core_get_info(server->core, &info) == FTUN_OK &&
      (info.state == FTUN_CORE_STOPPING || info.state == FTUN_CORE_STOPPED);
    server->queued_at = closing ? 0u : clock_now() + 2u;
    if (closing) start_queued_reload(server);
  }
  arm(server);
}

static void start_queued_reload(ftun_ctl_server_t *server)
{
  if (!server->reload_pending && server->queued_reload != 0u && clock_now() >= server->queued_at) {
    ftun_core_info_t info = {0};
    server->reload_operation = server->queued_reload;
    server->queued_reload = 0u;
    server->reload_uid = server->queued_uid;
    ftun_status_t status = ftun_core_get_info(server->core, &info);
    if (status == FTUN_OK && (info.state == FTUN_CORE_STOPPING || info.state == FTUN_CORE_STOPPED))
      status = FTUN_E_CANCELLED;
    for (size_t i = 0u; i < FTUN_CTL_CONNECTIONS; i++) {
      if (server->connections[i].phase == RELOADING &&
          server->connections[i].operation == server->reload_operation)
        server->connections[i].previous_generation = info.generation;
    }
    /* 在后续owner轮提交：上一事务的完成回调及Worker槽此时已释放。 */
    if (status == FTUN_OK) status = submit_reload(server, info.generation);
    if (status != FTUN_OK) reply_reload(server, (ftun_app_command_result_t){
      .error = {status, 0u, 0}, .generation = info.generation}, true);
  }
}

static void dispatch(connection_t *connection)
{
  ftun_ctl_server_t *server = connection->server;
  ftun_ctl_request_t request;
  ftun_core_info_t info;
  ftun_status_t status = ftun_ctl_request_parse(server->budget,
    (ftun_bytes_t){(const uint8_t *)connection->request, connection->received}, &request);
  if (status == FTUN_E_AGAIN) return;
  if (status != FTUN_OK) {
    server->rejected++;
    control_log(server, &rejected_event, 0u, 0u, (ftun_error_t){status, 0u, 0}, "invalid-request", connection->uid);
    reply(connection, "invalid-request", ftun_status_name(status), 0u, 0u, NULL);
    return;
  }
  if (request.boot_present && request.boot != server->boot) {
    server->rejected++;
    control_log(server, &rejected_event, 0u, 0u, (ftun_error_t){FTUN_E_STALE, 0u, 0}, "boot-mismatch", connection->uid);
    reply(connection, "rejected", "boot-mismatch", 0u, 0u, NULL);
    return;
  }
  if (request.operation == FTUN_CTL_STATUS || request.operation == FTUN_CTL_DNS_STATUS ||
      request.operation == FTUN_CTL_PROXY_STATUS) { status_reply(connection, request.operation); return; }
  status = ftun_core_get_info(server->core, &info);
  if (status != FTUN_OK) { reply(connection, "failed", ftun_status_name(status), 0u, 0u, NULL); return; }
  connection->previous_generation = info.generation;
  connection->deadline = clock_now() + request.timeout_ms;
  if (request.operation == FTUN_CTL_STOP) {
    ftun_app_command_result_t result;
    ftun_app_generation_guard_t expected = {true, info.generation};
    connection->operation = ++server->operation;
    control_log(server, &stop_event, connection->operation, info.generation, (ftun_error_t){0}, "requested", connection->uid);
    status = ftun_app_control_stop(server->core, clock_now() +
      (request.timeout_ms == 0u ? 15000u : request.timeout_ms), expected, &result);
    if (status != FTUN_OK) {
      control_log(server, &result_event, connection->operation, info.generation, (ftun_error_t){status, 0u, 0}, "rejected", connection->uid);
      reply(connection, "failed", ftun_status_name(status), 0u, info.generation, NULL); return;
    }
    server->stop_operation = connection->operation;
    server->stop_uid = connection->uid;
    if (request.timeout_ms == 0u) reply(connection, "accepted", "ok", 0u, info.generation, NULL);
    else connection->phase = STOPPING;
  } else {
    if (server->reload_pending || server->queued_reload != 0u) {
      connection->merged = true;
      server->merged++;
      if (server->queued_reload == 0u) {
        server->queued_reload = ++server->operation;
        server->queued_uid = connection->uid;
      }
      connection->operation = server->queued_reload;
    } else {
      status = submit_reload(server, info.generation);
      if (status != FTUN_OK) {
        server->rejected++;
        control_log(server, status == FTUN_E_AGAIN || status == FTUN_E_LIMIT ? &busy_event : &rejected_event,
          0u, info.generation, (ftun_error_t){status, 0u, 0}, ftun_status_name(status), connection->uid);
        reply(connection, status == FTUN_E_AGAIN || status == FTUN_E_LIMIT ? "busy" : "rejected",
          ftun_status_name(status), 0u, info.generation, NULL);
        return;
      }
      server->reload_operation = ++server->operation;
      server->reload_uid = connection->uid;
      connection->operation = server->reload_operation;
    }
    control_log(server, &reload_event, connection->operation, info.generation, (ftun_error_t){0}, connection->merged ? "merged" : "requested", connection->uid);
    connection->previous_generation = info.generation;
    if (request.timeout_ms == 0u) reply(connection, "accepted", "ok", 0u, info.generation, NULL);
    else connection->phase = RELOADING;
  }
  if ((connection->phase == RELOADING || connection->phase == STOPPING) &&
      connection->io != NULL && ftun_event_io_update(connection->io, FTUN_EVENT_READ) != FTUN_OK) {
    fault(server, FTUN_E_STATE_CORRUPT);
  }
}

static void write_connection(connection_t *connection)
{
  ftun_status_t status;
  if (clock_now() >= connection->deadline) {
    connection->server->timeouts++;
    connection->server->write_failed++;
    close_connection(connection);
    return;
  }
  ptrdiff_t written = ftun_socket_send_nowait(connection->socket,
    connection->response + connection->sent, connection->length - connection->sent, &status);
  if (written > 0) {
    connection->sent += (size_t)written;
    if (connection->sent == connection->length) close_connection(connection);
  } else if (status != FTUN_E_AGAIN) {
    connection->server->write_failed++;
    close_connection(connection);
  }
}

static void connection_ready(ftun_event_source_t *source, uint32_t events, void *user)
{
  connection_t *connection = user;
  ftun_status_t status;
  ptrdiff_t received;
  (void)source; (void)events;
  if (connection->phase != WRITING && clock_now() >= connection->deadline) {
    connection->server->timeouts++;
    reply(connection, "timeout", "timeout", 0u, 0u, NULL);
    arm(connection->server);
    return;
  }
  if (connection->phase == WRITING) write_connection(connection);
  else if (connection->phase == READING) {
    received = ftun_socket_receive_nowait(connection->socket,
      connection->request + connection->received, sizeof(connection->request) - connection->received, &status);
    if (received > 0) {
      char *newline;
      connection->received += (size_t)received;
      newline = memchr(connection->request, '\n', connection->received);
      if (newline != NULL) {
        size_t length = (size_t)(newline - connection->request);
        if (length + 1u != connection->received) reply(connection, "invalid-request", "extra-data", 0u, 0u, NULL);
        else {
          if (length != 0u && connection->request[length - 1u] == '\r') length--;
          connection->received = length;
          connection->phase = PARSING;
          if (ftun_event_io_update(connection->io, FTUN_EVENT_ERROR) != FTUN_OK) fault(connection->server, FTUN_E_STATE_CORRUPT);
          dispatch(connection);
        }
      } else if (connection->received == sizeof(connection->request)) reply(connection, "invalid-request", "too-large", 0u, 0u, NULL);
    } else if (received == 0 || status != FTUN_E_AGAIN) close_connection(connection);
  } else if (connection->phase == RELOADING || connection->phase == STOPPING) {
    char extra;
    received = ftun_socket_receive_nowait(connection->socket, &extra, 1u, &status);
    if (received >= 0 || status != FTUN_E_AGAIN) close_connection(connection);
  }
  arm(connection->server);
}

static void timer_ready(ftun_event_source_t *source, uint32_t events, void *user)
{
  ftun_ctl_server_t *server = user;
  uint64_t now = clock_now();
  size_t i;
  (void)source; (void)events;
  fault(server, ftun_event_source_cancel(&server->timer));
  start_queued_reload(server);
  if (server->accept_after != 0u && now >= server->accept_after) {
    server->accept_after = 0u;
    fault(server, ftun_event_io_update(server->accept, FTUN_EVENT_READ));
  }
  for (i = 0u; i < FTUN_CTL_CONNECTIONS; i++) {
    connection_t *connection = &server->connections[i];
    if (connection->phase == FREE) continue;
    if (now >= connection->deadline) {
      server->timeouts++;
      if (connection->phase == WRITING) { server->write_failed++; close_connection(connection); }
      else reply(connection, "timeout", "timeout", 0u, 0u, NULL);
    } else if (connection->phase == PARSING) dispatch(connection);
  }
  arm(server);
}

static void arm(ftun_ctl_server_t *server)
{
  uint64_t deadline = server->accept_after == 0u ? UINT64_MAX : server->accept_after;
  size_t i;
  if (server->loop == NULL) return;
  if (!server->reload_pending && server->queued_reload != 0u && server->queued_at < deadline)
    deadline = server->queued_at;
  for (i = 0u; i < FTUN_CTL_CONNECTIONS; i++) {
    connection_t *connection = &server->connections[i];
    uint64_t next = connection->deadline;
    if (connection->phase == FREE) continue;
    if (connection->phase == PARSING && clock_now() + 2u < next) next = clock_now() + 2u;
    if (next < deadline) deadline = next;
  }
  /* 连续查询不能反复撤销已经排队的同期限回调，最早期限不变就保留。 */
  if (server->timer != NULL && server->timer_deadline == deadline) return;
  if (ftun_event_source_cancel(&server->timer) != FTUN_OK) { fault(server, FTUN_E_STATE_CORRUPT); return; }
  server->timer_deadline = deadline;
  if (deadline != UINT64_MAX) fault(server, ftun_event_control_timer_start(server->loop,
    deadline, timer_ready, server, &server->timer));
}

static void accept_ready(ftun_event_source_t *source, uint32_t events, void *user)
{
  ftun_ctl_server_t *server = user;
  size_t count, i;
  (void)source; (void)events;
  for (count = 0u; count < FTUN_CTL_CONNECTIONS; count++) {
    ftun_handle_t socket;
    ftun_socket_accept_disposition_t disposition;
    bool allowed;
    connection_t *connection = NULL;
    ftun_status_t status = ftun_socket_accept(server->listener.socket, &socket, NULL, &disposition);
    if (status != FTUN_OK) {
      if (disposition == FTUN_SOCKET_ACCEPT_BACKOFF) {
        server->accept_after = clock_now() + 25u;
        fault(server, ftun_event_io_update(server->accept, FTUN_EVENT_ERROR));
      } else if (disposition == FTUN_SOCKET_ACCEPT_FATAL) fault(server, FTUN_E_STATE_CORRUPT);
      break;
    }
    for (i = 0u; i < FTUN_CTL_CONNECTIONS; i++) {
      if (server->connections[i].phase == FREE) { connection = &server->connections[i]; break; }
    }
    if (connection == NULL) {
      char response[128];
      int length = snprintf(response, sizeof(response), "{\"result\":\"busy\",\"boot\":\"%016llx\"}\n", (unsigned long long)server->boot);
      (void)ftun_socket_send_nowait(socket, response, (size_t)length, &status);
      fault(server, ftun_socket_close((ftun_native_socket_t)socket));
      server->rejected++;
      control_log(server, &busy_event, 0u, 0u, (ftun_error_t){FTUN_E_LIMIT, 0u, 0}, "connections-full", UINT64_MAX);
      continue;
    }
    connection->server = server;
    connection->socket = socket;
    connection->phase = READING;
    connection->received = connection->length = connection->sent = 0u;
    connection->operation = connection->previous_generation = 0u;
    connection->merged = false;
    connection->deadline = clock_now() + IO_TIMEOUT;
    server->accepted++;
    status = ftun_event_control_io_start(server->loop, (ftun_native_socket_t)socket,
      FTUN_EVENT_READ, connection_ready, connection, &connection->io);
    if (status != FTUN_OK) { close_connection(connection); server->rejected++; continue; }
    status = ftun_ipc_peer_allowed(socket, &allowed, &connection->uid);
    if (status != FTUN_OK || !allowed) {
      server->rejected++;
      reply(connection, status == FTUN_OK ? "permission-denied" : "failed",
        "peer-credentials", 0u, 0u, NULL);
      control_log(server, &rejected_event, 0u, 0u, (ftun_error_t){FTUN_E_REJECTED, 0u, 0}, "peer-credentials", connection->uid);
    } else control_log(server, &connected_event, 0u, 0u, (ftun_error_t){0}, "connected", connection->uid);
  }
  arm(server);
}

ftun_status_t ftun_ctl_server_create(ftun_core_t *core, const char *path, ftun_ctl_server_t **out)
{
  ftun_budget_t *budget = NULL;
  ftun_core_control_t *control;
  ftun_ctl_server_t *server;
  ftun_reservation_t reservation = {0};
  ftun_budget_resources_t resources = {sizeof(*server) + strlen(path) + 1u, FTUN_CTL_CONNECTIONS + 2u, FTUN_CTL_CONNECTIONS};
  ftun_status_t status;
  /* 独立根子域保护全部控制峰值，配置Worker也不能借走解析及watcher额度。 */
  ftun_budget_options_t options = {{1024u * 1024u, FTUN_CTL_CONNECTIONS + 2u,
    2u * FTUN_CTL_CONNECTIONS + 2u}, {0}, {1024u * 1024u,
    FTUN_CTL_CONNECTIONS + 2u, 2u * FTUN_CTL_CONNECTIONS + 2u}};
  *out = NULL;
  status = ftun_core_control(core, &control);
  if (status == FTUN_OK) status = ftun_budget_create_resources(control->root_budget, &options, &budget);
  if (status == FTUN_OK) status = ftun_budget_reserve_resources(budget, resources, &reservation);
  if (status != FTUN_OK) { (void)ftun_budget_destroy(&budget); return status; }
  server = calloc(1u, resources.memory_bytes);
  if (server == NULL) { ftun_reservation_release(&reservation); (void)ftun_budget_destroy(&budget); return FTUN_E_LIMIT; }
  server->core = core;
  server->budget = budget;
  server->reservation = reservation;
  server->boot = ftun_log_boot_id();
  for (size_t i = 0u; i < 7u; i++) server->reject_entities[i] = ftun_correlation_next();
  memcpy(server->path, path, strlen(path) + 1u);
  status = ftun_ipc_listen(server->path, &server->listener);
  if (status != FTUN_OK) {
    free(server);
    ftun_reservation_release(&reservation);
    (void)ftun_budget_destroy(&budget);
    return status;
  }
  *out = server;
  return FTUN_OK;
}

ftun_status_t ftun_ctl_server_attach(ftun_ctl_server_t *server, ftun_event_loop_t *loop)
{
  ftun_status_t status = ftun_event_loop_bind_control(loop, server->budget, FTUN_CTL_EVENT_SOURCES);
  if (status != FTUN_OK) return status;
  server->loop = loop;
  return ftun_event_control_io_start(loop, (ftun_native_socket_t)server->listener.socket,
    FTUN_EVENT_READ, accept_ready, server, &server->accept);
}

ftun_status_t ftun_ctl_server_detach(ftun_ctl_server_t *server)
{
  ftun_status_t status;
  size_t i;
  if (server == NULL || server->loop == NULL) return FTUN_OK;
  status = ftun_event_source_cancel(&server->timer);
  if (status == FTUN_OK) status = ftun_event_source_cancel(&server->accept);
  if (status != FTUN_OK) return status;
  for (i = 0u; i < FTUN_CTL_CONNECTIONS; i++) {
    connection_t *connection = &server->connections[i];
    status = ftun_event_source_cancel(&connection->io);
    if (status != FTUN_OK) return status;
    if (connection->phase == READING || connection->phase == PARSING) close_connection(connection);
  }
  status = ftun_event_loop_bind_control(server->loop, NULL, 0u);
  if (status != FTUN_OK) return status;
  fault(server, ftun_ipc_listener_close(&server->listener));
  server->loop = NULL;
  return FTUN_OK;
}

ftun_status_t ftun_ctl_server_error(ftun_ctl_server_t *server)
{
  return server == NULL ? FTUN_OK : server->error;
}

ftun_status_t ftun_ctl_server_finish(ftun_ctl_server_t *server, ftun_status_t result)
{
  ftun_core_info_t info;
  uint64_t deadline = clock_now() + IO_TIMEOUT;
  size_t i;
  if (server == NULL) return FTUN_OK;
  if (server->loop != NULL) return FTUN_E_AGAIN;
  if (ftun_core_get_info(server->core, &info) != FTUN_OK) return FTUN_E_STATE_CORRUPT;
  /* run返回后不会再交付用户回调，即使取消的Worker仍在后台结束。 */
  server->reload_pending = false;
  for (i = 0u; i < FTUN_CTL_CONNECTIONS; i++) {
    connection_t *connection = &server->connections[i];
    if (connection->phase == STOPPING) {
      reply(connection, result == FTUN_OK && info.state == FTUN_CORE_STOPPED && server->error == FTUN_OK ? "stopped" :
        result == FTUN_E_TIMEOUT ? "timeout" : "failed", ftun_status_name(result), 0u, info.generation, NULL);
    } else if (connection->phase == RELOADING) {
      bool queued = server->queued_reload != 0u && connection->operation == server->queued_reload;
      if (queued) server->rejected++;
      reply(connection, queued ? "rejected" : "timeout", queued ? "not-executed" : "result-unknown",
        0u, info.generation, NULL);
    }
    while (connection->phase == WRITING) {
      write_connection(connection);
      if (connection->phase == WRITING && !ftun_blocking_socket_wait(connection->socket, FTUN_POLLER_WRITE, deadline)) {
        server->write_failed++;
        close_connection(connection);
      }
    }
  }
  server->queued_reload = 0u;
  return server->error;
}

void ftun_ctl_server_runtime_stopped(ftun_ctl_server_t *server, ftun_error_t error, uint64_t generation)
{
  /* 日志在finish之前已关闭；停止时未提交的后续批次在此留下确定未执行的记录。 */
  if (server != NULL && server->queued_reload != 0u) {
    control_log(server, &rejected_event, server->queued_reload, generation,
      (ftun_error_t){FTUN_E_CANCELLED, 0u, 0}, "not-executed", server->queued_uid);
  }
  if (server != NULL && server->stop_operation != 0u) {
    control_log(server, &result_event, server->stop_operation, generation, error, "runtime-stopped", server->stop_uid);
    server->stop_operation = 0u;
  }
}

ftun_status_t ftun_ctl_server_destroy(ftun_ctl_server_t **server)
{
  ftun_ctl_server_t *owned = *server;
  ftun_reservation_t reservation;
  ftun_budget_t *budget;
  ftun_status_t status;
  size_t i;
  if (owned == NULL) return FTUN_OK;
  if (owned->loop != NULL || owned->reload_pending) return FTUN_E_AGAIN;
  for (i = 0u; i < FTUN_CTL_CONNECTIONS; i++) close_connection(&owned->connections[i]);
  fault(owned, ftun_ipc_listener_close(&owned->listener));
  reservation = owned->reservation;
  budget = owned->budget;
  status = owned->error;
  free(owned);
  *server = NULL;
  ftun_reservation_release(&reservation);
  if (ftun_budget_destroy(&budget) != FTUN_OK) return FTUN_E_STATE_CORRUPT;
  return status;
}

ftun_status_t ftun_ctl_server_discard(ftun_ctl_server_t **server)
{
  if (*server == NULL) return FTUN_OK;
  if ((*server)->loop != NULL || (*server)->reload_pending) return FTUN_E_STALE;
  fault(*server, ftun_ipc_listener_discard(&(*server)->listener));
  return ftun_ctl_server_destroy(server);
}
