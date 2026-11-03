#include "app/cli/internal.h"
#include "app/cli/render.h"
#include "core/config/document.h"
#include "platform/clock.h"
#include "platform/ipc.h"
#include "platform/pidfile.h"
#include "platform/process.h"
#include "platform/socket.h"
#include <stdio.h>
#include <string.h>

#define FTUN_CLI_REPLY_BYTES 65536u

typedef struct {
  char text[FTUN_CLI_REPLY_BYTES + 128u];
  ftun_config_json_t document;
  bool submitted;
} ftun_cli_reply_t;

static const char *ftun_cli_reply_string(const cJSON *object, const char *key)
{
  const cJSON *value = cJSON_GetObjectItemCaseSensitive(object, key);
  return cJSON_IsString(value) ? value->valuestring : "";
}

static double ftun_cli_reply_number(const cJSON *object, const char *key)
{
  const cJSON *value = cJSON_GetObjectItemCaseSensitive(object, key);
  return cJSON_IsNumber(value) ? value->valuedouble : 0;
}

static bool ftun_cli_before(uint64_t deadline)
{
  uint64_t now;
  return ftun_monotonic_now(&now) == FTUN_OK && now < deadline;
}

/* 独立命令进程独占一个流及有界响应。短读写只推进偏移，不重发请求。
 * 预拒绝可能早于send，故send失败仍读取已排队的busy/permission-denied。 */
static ftun_status_t ftun_cli_exchange(ftun_handle_t stream, const char *request,
  uint64_t deadline, ftun_cli_reply_t *reply)
{
  size_t sent = 0u, used = 0u, length = strlen(request);
  ftun_status_t status = FTUN_OK;
  memset(reply, 0, sizeof(*reply));
  while (sent < length) {
    ptrdiff_t count;
    if (!ftun_cli_before(deadline)) return FTUN_E_TIMEOUT;
    count = ftun_socket_send_nowait(stream, request + sent, length - sent, &status);
    if (count > 0) sent += (size_t)count;
    else if (status == FTUN_E_AGAIN) {
      if (!ftun_blocking_socket_wait(stream, FTUN_POLLER_WRITE, deadline)) return FTUN_E_TIMEOUT;
    } else break;
  }
  reply->submitted = sent == length;
  while (used < FTUN_CLI_REPLY_BYTES) {
    ptrdiff_t count;
    char *newline;
    if (!ftun_cli_before(deadline)) return FTUN_E_TIMEOUT;
    count = ftun_socket_receive_nowait(stream, reply->text + used,
      FTUN_CLI_REPLY_BYTES - used, &status);
    if (count <= 0) {
      if (count < 0 && status == FTUN_E_AGAIN) {
        if (!ftun_blocking_socket_wait(stream, FTUN_POLLER_READ, deadline)) return FTUN_E_TIMEOUT;
        continue;
      }
      return count == 0 ? FTUN_E_EOF : status;
    }
    used += (size_t)count;
    newline = memchr(reply->text, '\n', used);
    if (newline != NULL) {
      if (newline != reply->text + used - 1u) return FTUN_E_INVALID;
      reply->text[used] = '\0';
      return ftun_config_json_open(NULL,
        (ftun_bytes_t){(const uint8_t *)reply->text, used}, &reply->document);
    }
  }
  return FTUN_E_LIMIT;
}

static bool ftun_cli_is_query(const char *operation)
{
  return strcmp(operation, "stop") != 0 && strcmp(operation, "reload") != 0;
}

static int ftun_cli_reply_code(const cJSON *root, const char *operation, bool no_wait)
{
  const char *result = ftun_cli_reply_string(root, "result");
  if ((ftun_cli_is_query(operation) && strcmp(result, "ok") == 0) ||
      (strcmp(operation, "reload") == 0 &&
        (strcmp(result, "committed") == 0 || strcmp(result, "merged") == 0)) ||
      (strcmp(operation, "stop") == 0 && strcmp(result, "stopped") == 0) ||
      (no_wait && strcmp(result, "accepted") == 0)) return FTUN_EXIT_OK;
  if (strcmp(result, "timeout") == 0) return FTUN_EXIT_UNKNOWN;
  if (strcmp(result, "invalid-request") == 0) return FTUN_EXIT_USAGE;
  if (strcmp(result, "rejected") == 0 || strcmp(result, "restart-required") == 0 ||
      strcmp(result, "busy") == 0 || strcmp(result, "not-running") == 0 ||
      strcmp(result, "permission-denied") == 0 || strcmp(result, "failed") == 0) return FTUN_EXIT_FAIL;
  return FTUN_EXIT_UNKNOWN;
}

static int ftun_cli_print_reply(const ftun_cli_args_t *args, const char *operation,
  ftun_cli_reply_t *reply, int code, uint64_t started)
{
  const cJSON *root = reply->document.root;
  int written;
  uint64_t now = started;
  (void)ftun_monotonic_now(&now);
  if (!args->json && code == FTUN_EXIT_OK && ftun_cli_is_query(operation)) {
    code = ftun_cli_status_render(operation, root);
    ftun_config_json_close(&reply->document);
    return code;
  }
  if (args->json) {
    /* 保留线上整数的十进制表示，避免cJSON double重编码损失op_id精度。 */
    char *end = strrchr(reply->text, '}');
    size_t available = sizeof(reply->text) - (size_t)(end - reply->text);
    (void)snprintf(end, available, ",\"elapsed_ms\":%llu}\n", (unsigned long long)(now - started));
    if (ftun_cli_output(1, reply->text) != FTUN_EXIT_OK) {
      (void)ftun_cli_output(2, "ftun: control output failed\n");
      code = FTUN_EXIT_FAIL;
    }
  } else {
    char text[32768], file[24578] = "\"\"";
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(root, "file");
    if (cJSON_IsString(value) && !cJSON_PrintPreallocated((cJSON *)value, file, sizeof(file), false)) {
      ftun_config_json_close(&reply->document);
      return FTUN_EXIT_FAIL;
    }
    written = snprintf(text, sizeof(text),
      "ftun: %s: %s (pid=%.0f, boot=%s, op_id=%.0f, generation=%.0f, previous_generation=%.0f, merged=%s, stage=%.0f, status=%s, file=%s, phase=%s, field=%s, message=%s, elapsed_ms=%llu)\n",
      operation, ftun_cli_reply_string(root, "result"), ftun_cli_reply_number(root, "pid"),
      ftun_cli_reply_string(root, "boot"), ftun_cli_reply_number(root, "op_id"),
      ftun_cli_reply_number(root, "generation"), ftun_cli_reply_number(root, "previous_generation"),
      cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, "merged")) ? "true" : "false",
      ftun_cli_reply_number(root, "stage"), ftun_cli_reply_string(root, "status"),
      file, ftun_cli_reply_string(root, "phase"), ftun_cli_reply_string(root, "field"),
      ftun_cli_reply_string(root, "message"), (unsigned long long)(now - started));
    if (written < 0 || (size_t)written >= sizeof(text) ||
        ftun_cli_output(2, text) != FTUN_EXIT_OK) code = FTUN_EXIT_FAIL;
  }
  ftun_config_json_close(&reply->document);
  return code;
}

static int ftun_cli_control_result(const ftun_cli_args_t *args, const char *operation,
  const char *result, const char *message, uint32_t pid, const char *via, int code, uint64_t started)
{
  uint64_t now = started;
  (void)ftun_monotonic_now(&now);
  if (args->json) {
    cJSON *object = cJSON_CreateObject();
    if (object == NULL || cJSON_AddStringToObject(object, "result", result) == NULL ||
        cJSON_AddStringToObject(object, "op", operation) == NULL ||
        cJSON_AddStringToObject(object, "message", message) == NULL ||
        cJSON_AddNumberToObject(object, "pid", pid) == NULL ||
        cJSON_AddStringToObject(object, "via", via) == NULL ||
        cJSON_AddBoolToObject(object, "terminal", code != FTUN_EXIT_UNKNOWN) == NULL ||
        cJSON_AddNumberToObject(object, "elapsed_ms", (double)(now - started)) == NULL) {
      cJSON_Delete(object);
      object = NULL;
    }
    if (ftun_cli_json_write(object) != FTUN_EXIT_OK) return FTUN_EXIT_FAIL;
  } else {
    char text[1024];
    (void)snprintf(text, sizeof(text), "ftun: %s: %s (pid=%u, via=%s, elapsed_ms=%llu)\n",
      operation, message, pid, via, (unsigned long long)(now - started));
    if (ftun_cli_output(2, text) != FTUN_EXIT_OK) return FTUN_EXIT_FAIL;
  }
  return code;
}

static ftun_status_t ftun_cli_wait_exit(uint32_t pid, uint64_t deadline)
{
  for (;;) {
    uint64_t now;
    bool exited = false;
    ftun_status_t status;
    status = ftun_process_exited(pid, &exited);
    if (status == FTUN_OK && exited) return FTUN_OK;
    if (status != FTUN_OK) return status;
    if (ftun_monotonic_now(&now) != FTUN_OK) return FTUN_E_IO;
    if (now >= deadline) return FTUN_E_TIMEOUT;
    ftun_thread_pause((uint32_t)(deadline - now < 50u ? deadline - now : 50u));
  }
}

static int ftun_cli_control_signal(const ftun_cli_args_t *args,
  const char *operation, uint64_t deadline, uint64_t started)
{
  bool stop = strcmp(operation, "stop") == 0;
  ftun_status_t status;
  int error;
  if (ftun_process_signal(args->pid, stop ? FTUN_SIGNAL_TERMINATE : FTUN_SIGNAL_HANGUP,
      &error) != FTUN_OK) {
    return ftun_cli_control_result(args, operation, "failed", strerror(error),
      args->pid, "signal", FTUN_EXIT_FAIL, started);
  }
  if (!stop || args->no_wait) {
    return ftun_cli_control_result(args, operation, "accepted",
      stop ? "sent termination signal; result unknown" : "sent reload signal; result unknown",
      args->pid, "signal", FTUN_EXIT_UNKNOWN, started);
  }
  status = ftun_cli_wait_exit(args->pid, deadline);
  return ftun_cli_control_result(args, operation,
    status == FTUN_OK ? "stopped" : status == FTUN_E_TIMEOUT ? "timeout" : "failed",
    status == FTUN_OK ? "process exited" : "signal sent; process exit not confirmed",
    args->pid, "signal", status == FTUN_OK ? FTUN_EXIT_OK : FTUN_EXIT_UNKNOWN, started);
}

int ftun_cli_control(const ftun_cli_args_t *args, const char *operation)
{
  char pidfile[4096], endpoint[4096], boot[17], request[128];
  uint32_t pid = 0u;
  bool query = ftun_cli_is_query(operation);
  uint64_t now, deadline, started;
  uint32_t seconds = args->timeout_seconds != 0u ? args->timeout_seconds
    : query ? 5u : strcmp(operation, "stop") == 0 ? 15u : 30u;
  ftun_handle_t stream = -1;
  ftun_cli_reply_t reply;
  ftun_status_t status;
  const char *result;
  int code;
  if (ftun_monotonic_now(&now) != FTUN_OK)
    return ftun_cli_failure(operation, "failed", "monotonic clock unavailable", args->json);
  started = now;
  deadline = now + (uint64_t)seconds * 1000u;
  status = ftun_pidfile_path(args->pidfile, pidfile, sizeof(pidfile));
  if (status == FTUN_OK) status = ftun_pidfile_probe(pidfile, &pid);
  if (args->pid_text != NULL && (status != FTUN_OK || pid != args->pid)) {
    if (query) return ftun_cli_failure(operation, "not-running", "no known endpoint for PID; use -p FILE", args->json);
    return ftun_cli_control_signal(args, operation, deadline, started);
  }
  if (status != FTUN_OK) return ftun_cli_failure(operation,
    status == FTUN_E_EOF ? "not-running" : "failed",
    status == FTUN_E_EOF ? "no running instance" : "cannot read locked PID file", args->json);
  status = ftun_pidfile_socket_path(pidfile, endpoint, sizeof(endpoint));
  if (status == FTUN_OK) status = ftun_ipc_connect(endpoint, deadline, &stream);
  if (!query && args->pid_text != NULL && (status == FTUN_E_EOF || status == FTUN_E_UNSUPPORTED))
    return ftun_cli_control_signal(args, operation, deadline, started);
  if (status != FTUN_OK) return ftun_cli_failure(operation,
    status == FTUN_E_REJECTED ? "permission-denied" : "failed", ftun_status_name(status), args->json);
  status = ftun_cli_exchange(stream, "{\"op\":\"status\"}\n", deadline, &reply);
  (void)ftun_socket_close((ftun_native_socket_t)stream);
  if (status != FTUN_OK) return ftun_cli_failure(operation, "failed",
    "cannot verify control endpoint identity", args->json);
  result = ftun_cli_reply_string(reply.document.root, "result");
  if (strcmp(result, "ok") != 0) {
    code = ftun_cli_reply_code(reply.document.root, "status", false);
    if (code == FTUN_EXIT_FAIL || code == FTUN_EXIT_USAGE)
      return ftun_cli_print_reply(args, operation, &reply, code, started);
    ftun_config_json_close(&reply.document);
    return ftun_cli_failure(operation, "failed", "invalid identity response", args->json);
  }
  result = ftun_cli_reply_string(reply.document.root, "boot");
  if (ftun_cli_reply_number(reply.document.root, "pid") != pid || strlen(result) != 16u ||
      strspn(result, "0123456789abcdefABCDEF") != 16u) {
    ftun_config_json_close(&reply.document);
    return ftun_cli_failure(operation, "rejected", "control endpoint identity mismatch", args->json);
  }
  if (strcmp(operation, "status") == 0) return ftun_cli_print_reply(args, operation, &reply, FTUN_EXIT_OK, started);
  memcpy(boot, result, sizeof(boot));
  ftun_config_json_close(&reply.document);
  status = ftun_ipc_connect(endpoint, deadline, &stream);
  if (status != FTUN_OK) return ftun_cli_failure(operation, "failed", ftun_status_name(status), args->json);
  if (ftun_monotonic_now(&now) != FTUN_OK || now >= deadline) {
    (void)ftun_socket_close((ftun_native_socket_t)stream);
    return ftun_cli_failure(operation, "timeout", "request not submitted before deadline", args->json);
  }
  (void)snprintf(request, sizeof(request), "{\"op\":\"%s\",\"boot\":\"%s\",\"timeout_ms\":%u}\n",
    operation, boot, args->no_wait ? 0u : (uint32_t)(deadline - now));
  status = ftun_cli_exchange(stream, request, deadline, &reply);
  (void)ftun_socket_close((ftun_native_socket_t)stream);
  if (status != FTUN_OK) return ftun_cli_control_result(args, operation,
    status == FTUN_E_TIMEOUT ? "timeout" : "failed",
    reply.submitted ? "request submitted; result unknown" : "request not submitted",
    pid, "socket", reply.submitted && !query ? FTUN_EXIT_UNKNOWN : FTUN_EXIT_FAIL, started);
  result = ftun_cli_reply_string(reply.document.root, "result");
  if (!(strcmp(result, "rejected") == 0 &&
        strcmp(ftun_cli_reply_string(reply.document.root, "status"), "boot-mismatch") == 0) &&
      strcmp(result, "busy") != 0 && strcmp(result, "permission-denied") != 0 &&
      (strcmp(ftun_cli_reply_string(reply.document.root, "boot"), boot) != 0 ||
       ftun_cli_reply_number(reply.document.root, "pid") != pid)) {
    ftun_config_json_close(&reply.document);
    return ftun_cli_control_result(args, operation, "failed", "response identity mismatch; result unknown",
      pid, "socket", query ? FTUN_EXIT_FAIL : FTUN_EXIT_UNKNOWN, started);
  }
  code = ftun_cli_reply_code(reply.document.root, operation, args->no_wait);
  if (code == FTUN_EXIT_UNKNOWN && strcmp(result, "timeout") != 0) {
    ftun_config_json_close(&reply.document);
    return ftun_cli_control_result(args, operation, "failed", "unexpected response; result unknown",
      pid, "socket", query ? FTUN_EXIT_FAIL : FTUN_EXIT_UNKNOWN, started);
  }
  if (strcmp(operation, "stop") == 0 && strcmp(result, "stopped") == 0) {
    status = ftun_cli_wait_exit(pid, deadline);
    if (status != FTUN_OK) {
      ftun_config_json_close(&reply.document);
      return ftun_cli_control_result(args, operation,
        status == FTUN_E_TIMEOUT ? "timeout" : "failed", "process exit not confirmed; result unknown",
        pid, "socket", query ? FTUN_EXIT_FAIL : FTUN_EXIT_UNKNOWN, started);
    }
  }
  return ftun_cli_print_reply(args, operation, &reply, query && code == FTUN_EXIT_UNKNOWN ? FTUN_EXIT_FAIL : code, started);
}
