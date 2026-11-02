#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "app/cli/result.h"

#include "platform/clock.h"
#include "platform/file.h"

#include "platform/thread.h"
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define FTUN_CLI_RESULT_CAPACITY 32u
#define FTUN_CLI_RESULT_TOTAL (FTUN_CLI_RESULT_CAPACITY + 2u)
#define FTUN_CLI_RESULT_LINE_BYTES (768u + 4u * FTUN_APP_CONTROL_PATH_CAPACITY)

enum {
  FTUN_CLI_RESULT_FREE = 0,
  FTUN_CLI_RESULT_RESERVED,
  FTUN_CLI_RESULT_READY,
  FTUN_CLI_RESULT_WRITING
};

struct ftun_cli_result_ticket {
  struct ftun_cli_result_sink *sink;
  ftun_status_t status;
  uint32_t stage;
  uint32_t module, pid;
  char background_reasons[FTUN_CLI_READY_REASONS_CAPACITY];
  uint8_t kind;
  uint8_t state;
  char file_error[FTUN_APP_CONTROL_PATH_CAPACITY];
};

struct ftun_cli_result_sink {
  ftun_budget_t *budget;
  ftun_reservation_t reservation;
  ftun_mutex_t mutex;
  ftun_condition_t available;
  ftun_condition_t exited_condition;
  ftun_thread_t thread;
  bool initialized[FTUN_CLI_RESULT_TOTAL];
  size_t ready_slots[FTUN_CLI_RESULT_TOTAL];
  size_t ready_head;
  size_t ready_tail;
  size_t ready_count;
  size_t reserved_count;
  uint64_t deadline_ms;
  uint64_t accepted;
  uint64_t written;
  uint64_t write_failed;
  uint64_t admission_rejected;
  uint64_t rejection_notices;
  ftun_status_t rejection_status;
  uint64_t undelivered;
  unsigned int references;
  ftun_handle_t descriptor;
  int accepting;
  int stopping;
  int failed;
  int timed_out;
  int exited;
  ftun_cli_result_ticket_t tickets[FTUN_CLI_RESULT_TOTAL];
};

/* 只在持锁预留时初始化；writer及发布方只接收已交付的ticket。 */
static ftun_cli_result_ticket_t *ftun_cli_result_ticket_slot(ftun_cli_result_sink_t *sink, size_t slot)
{
  ftun_cli_result_ticket_t *ticket = &sink->tickets[slot];
  if (!sink->initialized[slot]) {
    memset(ticket, 0, sizeof(*ticket));
    ticket->sink = sink;
    sink->initialized[slot] = true;
  }
  return ticket;
}

static void ftun_cli_result_count(uint64_t *value)
{
  if (*value != UINT64_MAX) (*value)++;
}

static void ftun_cli_result_add(uint64_t *value, uint64_t added)
{
  if (UINT64_MAX - *value < added) {
    *value = UINT64_MAX;
  } else {
    *value += added;
  }
}

static void ftun_cli_result_release(ftun_cli_result_sink_t *sink)
{
  int destroy = 0;
  ftun_budget_t *budget;
  ftun_reservation_t reservation;
  ftun_mutex_lock(&sink->mutex);
  if (sink->references != 0u) sink->references--;
  destroy = sink->references == 0u;
  ftun_mutex_unlock(&sink->mutex);
  if (!destroy) return;
  budget = sink->budget;
  reservation = sink->reservation;
  if (sink->descriptor >= 0) (void)ftun_file_close(sink->descriptor);
  ftun_condition_destroy(&sink->exited_condition);
  ftun_condition_destroy(&sink->available);
  ftun_mutex_destroy(&sink->mutex);
  free(sink);
  ftun_reservation_release(&reservation);
  (void)ftun_budget_destroy(&budget);
}

static const char *ftun_cli_result_module(uint32_t module)
{
  switch (module) {
    case FTUN_BUILD_MODULE_CORE: return "core";
    case FTUN_BUILD_MODULE_DNS: return "dns";
    case FTUN_BUILD_MODULE_TUN: return "tun";
    case FTUN_BUILD_MODULE_FRS: return "frs";
    case FTUN_BUILD_MODULE_FAKEIP: return "fakeip";
    case FTUN_BUILD_MODULE_PROXY: return "proxy";
    default: return "app";
  }
}

static const char *ftun_cli_result_stage(uint32_t stage)
{
  switch (stage) {
    case FTUN_STAGE_CONFIG_READ: return "config-read";
    case FTUN_STAGE_CONFIG_PREPARE: return "prepare";
    case FTUN_STAGE_STATE_RESTORE: return "state-restore";
    case FTUN_STAGE_COMMIT: return "commit";
    case FTUN_STAGE_CONTROL: return "control";
    default: return "setup";
  }
}

static size_t ftun_cli_result_format(const ftun_cli_result_ticket_t *ticket,
                                     char line[FTUN_CLI_RESULT_LINE_BYTES])
{
  int length;
  switch ((ftun_cli_result_kind_t)ticket->kind) {
    case FTUN_CLI_RESULT_RELOAD_COMMITTED:
      length = snprintf(line, FTUN_CLI_RESULT_LINE_BYTES,
                        "ftun: reload committed\n");
      break;
    case FTUN_CLI_RESULT_RELOAD_REJECTED:
      length = snprintf(line, FTUN_CLI_RESULT_LINE_BYTES,
        "ftun: reload rejected at stage %u: %s\n", ticket->stage,
        ftun_status_name(ticket->status));
      break;
    case FTUN_CLI_RESULT_RELOAD_REQUEST_REJECTED:
      length = snprintf(line, FTUN_CLI_RESULT_LINE_BYTES,
        "ftun: reload request rejected: %s\n",
        ftun_status_name(ticket->status));
      break;
    case FTUN_CLI_RESULT_STOP_FAILED:
      length = snprintf(line, FTUN_CLI_RESULT_LINE_BYTES,
        "ftun: stop request failed: %s\n", ftun_status_name(ticket->status));
      break;
    case FTUN_CLI_RESULT_BACKGROUND_READY:
      length = ticket->background_reasons[0] == '\0' ?
        snprintf(line, FTUN_CLI_RESULT_LINE_BYTES, "ftun: ready (pid %u); %s\n", ticket->pid,
          ticket->file_error[0] == '\0' ? "logging disabled" : "log file") :
        snprintf(line, FTUN_CLI_RESULT_LINE_BYTES, "ftun: ready (degraded: %s) (pid %u); %s\n",
          ticket->background_reasons, ticket->pid, ticket->file_error[0] == '\0' ? "logging disabled" : "log file");
      break;
    case FTUN_CLI_RESULT_RUN_READY:
      length = snprintf(line, FTUN_CLI_RESULT_LINE_BYTES, "ftun: ready\n");
      break;
    case FTUN_CLI_RESULT_RUN_FAILED:
      length = snprintf(line, FTUN_CLI_RESULT_LINE_BYTES,
        "ftun: run: %s %s failed: %s\n", ftun_cli_result_module(ticket->module),
        ftun_cli_result_stage(ticket->stage), ftun_status_name(ticket->status));
      break;
    default:
      return 0u;
  }
  if (length <= 0) return 0u;
  if (ticket->file_error[0] != '\0') {
    static const char hex[] = "0123456789abcdef";
    const unsigned char *path = (const unsigned char *)ticket->file_error;
    size_t used = (size_t)length - 1u;
    if (ticket->kind == FTUN_CLI_RESULT_RUN_READY) {
      static const char prefix[] = " (degraded: ";
      memcpy(line + used, prefix, sizeof(prefix) - 1u);
      used += sizeof(prefix) - 1u;
    } else {
      line[used++] = ':'; line[used++] = ' '; line[used++] = '"';
    }
    /* 每字节至多4字符，缓冲按路径上限预留，不能把路径变成另一条诊断。 */
    for (; *path != 0u; ++path) {
      if (*path == '\\' || *path == '"') {
        line[used++] = '\\'; line[used++] = (char)*path;
      } else if (*path < 32u || *path == 127u) {
        line[used++] = '\\'; line[used++] = 'x';
        line[used++] = hex[*path >> 4u]; line[used++] = hex[*path & 15u];
      } else {
        line[used++] = (char)*path;
      }
    }
    line[used++] = ticket->kind == FTUN_CLI_RESULT_RUN_READY ? ')' : '"';
    line[used++] = '\n'; line[used] = '\0';
    return used;
  }
  if ((size_t)length >= FTUN_CLI_RESULT_LINE_BYTES) {
    line[FTUN_CLI_RESULT_LINE_BYTES - 2u] = '\n';
    line[FTUN_CLI_RESULT_LINE_BYTES - 1u] = '\0';
    return FTUN_CLI_RESULT_LINE_BYTES - 1u;
  }
  return (size_t)length;
}

static ftun_status_t ftun_cli_result_write(ftun_cli_result_sink_t *sink,
                                           const char *line, size_t length)
{
  size_t offset = 0u;
  while (offset < length) {
    uint64_t deadline;
    uint64_t now = 0u;
    ptrdiff_t written;
    ftun_status_t io_status;
    ftun_mutex_lock(&sink->mutex);
    deadline = sink->stopping ? sink->deadline_ms : UINT64_MAX;
    ftun_mutex_unlock(&sink->mutex);
    if (deadline != UINT64_MAX) {
      if (ftun_monotonic_now(&now) != FTUN_OK) return FTUN_E_IO;
      if (now >= deadline) return FTUN_E_TIMEOUT;
    }
    written = ftun_file_write_some(sink->descriptor, line + offset, length - offset, &io_status);
    if (written > 0) {
      offset += (size_t)written;
      continue;
    }
    if (written < 0 && io_status == FTUN_E_AGAIN &&
        ftun_file_wait_writable(sink->descriptor, 100u) != FTUN_E_IO) continue;
    return FTUN_E_IO;
  }
  return FTUN_OK;
}

static void ftun_cli_result_drop_ready(ftun_cli_result_sink_t *sink)
{
  while (sink->ready_count != 0u) {
    size_t slot = sink->ready_slots[sink->ready_head];
    ftun_cli_result_ticket_t *ticket = &sink->tickets[slot];
    sink->ready_head = (sink->ready_head + 1u) % FTUN_CLI_RESULT_TOTAL;
    sink->ready_count--;
    if (ticket->state == FTUN_CLI_RESULT_READY) {
      ticket->state = FTUN_CLI_RESULT_FREE;
      ftun_cli_result_count(&sink->undelivered);
    }
  }
}

static void *ftun_cli_result_writer(void *user)
{
  ftun_cli_result_sink_t *sink = (ftun_cli_result_sink_t *)user;
  ftun_status_t signal_status = ftun_thread_block_sigpipe();
  for (;;) {
    ftun_cli_result_ticket_t *ticket = NULL;
    ftun_cli_result_ticket_t notice;
    char line[FTUN_CLI_RESULT_LINE_BYTES];
    size_t length;
    size_t slot;
    uint64_t notices = 0u;
    ftun_status_t status;
    ftun_mutex_lock(&sink->mutex);
    while (sink->ready_count == 0u && sink->rejection_notices == 0u &&
           !sink->stopping) {
      ftun_condition_wait(&sink->available, &sink->mutex);
    }
    if (sink->ready_count == 0u && sink->rejection_notices == 0u &&
        sink->stopping) {
      sink->exited = 1;
      ftun_condition_broadcast(&sink->exited_condition);
      ftun_mutex_unlock(&sink->mutex);
      ftun_cli_result_release(sink);
      return NULL;
    }
    if (sink->ready_count != 0u) {
      slot = sink->ready_slots[sink->ready_head];
      sink->ready_head = (sink->ready_head + 1u) % FTUN_CLI_RESULT_TOTAL;
      sink->ready_count--;
      ticket = &sink->tickets[slot];
      if (ticket->state != FTUN_CLI_RESULT_READY) {
        sink->failed = 1;
        ftun_cli_result_count(&sink->write_failed);
        ftun_mutex_unlock(&sink->mutex);
        continue;
      }
      ticket->state = FTUN_CLI_RESULT_WRITING;
    } else {
      memset(&notice, 0, sizeof(notice));
      notice.kind = (uint8_t)FTUN_CLI_RESULT_RELOAD_REQUEST_REJECTED;
      notice.status = sink->rejection_status;
      notices = sink->rejection_notices;
      sink->rejection_notices = 0u;
      ticket = &notice;
    }
    length = ftun_cli_result_format(ticket, line);
    if (notices > 1u) {
      int formatted = snprintf(line, sizeof(line),
        "ftun: reload requests rejected: %s (count=%llu)\n",
        ftun_status_name(ticket->status), (unsigned long long)notices);
      length = formatted > 0 && (size_t)formatted < sizeof(line)
        ? (size_t)formatted : 0u;
    }
    ftun_mutex_unlock(&sink->mutex);
    status = signal_status != FTUN_OK ? signal_status :
      (length == 0u ? FTUN_E_STATE_CORRUPT
                    : ftun_cli_result_write(sink, line, length));
    ftun_mutex_lock(&sink->mutex);
    if (ticket != &notice) ticket->state = FTUN_CLI_RESULT_FREE;
    if (status == FTUN_OK) {
      ftun_cli_result_count(&sink->written);
    } else {
      sink->failed = 1;
      if (status == FTUN_E_TIMEOUT) sink->timed_out = 1;
      ftun_cli_result_count(&sink->write_failed);
      ftun_cli_result_add(&sink->undelivered, notices == 0u ? 1u : notices);
      ftun_cli_result_drop_ready(sink);
      ftun_cli_result_add(&sink->undelivered, sink->rejection_notices);
      sink->rejection_notices = 0u;
    }
    ftun_mutex_unlock(&sink->mutex);
  }
}

ftun_status_t ftun_cli_result_sink_create(ftun_handle_t descriptor,
                                          ftun_cli_result_sink_t **out)
{
  ftun_cli_result_sink_t *sink;
  ftun_budget_t *budget = NULL;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_budget_options_t options = {0};
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (descriptor < 0 || out == NULL) return FTUN_E_INVALID;
  options.limit = (ftun_budget_resources_t){sizeof(*sink), 1u, FTUN_CLI_RESULT_TOTAL};
  status = ftun_budget_create_resources(NULL, &options, &budget);
  if (status == FTUN_OK) status = ftun_budget_reserve_resources(budget, options.limit, &reservation);
  if (status != FTUN_OK) {
    (void)ftun_budget_destroy(&budget);
    return status;
  }
  sink = (ftun_cli_result_sink_t *)malloc(sizeof(*sink));
  if (sink == NULL) {
    ftun_reservation_release(&reservation);
    (void)ftun_budget_destroy(&budget);
    return FTUN_E_LIMIT;
  }
  memset(sink, 0, offsetof(ftun_cli_result_sink_t, tickets));
  sink->budget = budget;
  sink->reservation = reservation;
  sink->descriptor = -1;
  if (ftun_mutex_init(&sink->mutex) != FTUN_OK) goto io;
  if (ftun_condition_init(&sink->available) != FTUN_OK) goto mutex_io;
  if (ftun_condition_init(&sink->exited_condition) != FTUN_OK) goto available_io;
  (void)ftun_file_duplicate(descriptor, &sink->descriptor);
  if (sink->descriptor < 0) goto exited_io;
  sink->accepting = 1;
  sink->references = 2u;
  if (ftun_thread_create(&sink->thread, ftun_cli_result_writer, sink) != FTUN_OK) {
    goto descriptor_io;
  }
  *out = sink;
  return FTUN_OK;

descriptor_io:
  (void)ftun_file_close(sink->descriptor);
exited_io:
  ftun_condition_destroy(&sink->exited_condition);
available_io:
  ftun_condition_destroy(&sink->available);
mutex_io:
  ftun_mutex_destroy(&sink->mutex);
io:
  free(sink);
  ftun_reservation_release(&reservation);
  (void)ftun_budget_destroy(&budget);
  return FTUN_E_IO;
}

ftun_status_t ftun_cli_result_reserve(ftun_cli_result_sink_t *sink,
                                      ftun_cli_result_ticket_t **out)
{
  size_t index;
  if (out != NULL) *out = NULL;
  if (sink == NULL || out == NULL) return FTUN_E_INVALID;
  ftun_mutex_lock(&sink->mutex);
  if (!sink->accepting || sink->failed) {
    ftun_status_t status = sink->failed ? FTUN_E_IO : FTUN_E_CANCELLED;
    ftun_cli_result_count(&sink->admission_rejected);
    ftun_mutex_unlock(&sink->mutex);
    return status;
  }
  for (index = 0u; index < FTUN_CLI_RESULT_CAPACITY; index++) {
    ftun_cli_result_ticket_t *ticket = ftun_cli_result_ticket_slot(sink, index);
    if (ticket->state != FTUN_CLI_RESULT_FREE) continue;
    ticket->state = FTUN_CLI_RESULT_RESERVED;
    ticket->module = 0u;
    ticket->pid = 0u;
    ticket->background_reasons[0] = '\0';
    sink->reserved_count++;
    ftun_cli_result_count(&sink->accepted);
    *out = ticket;
    ftun_mutex_unlock(&sink->mutex);
    return FTUN_OK;
  }
  ftun_cli_result_count(&sink->admission_rejected);
  ftun_mutex_unlock(&sink->mutex);
  return FTUN_E_LIMIT;
}

ftun_status_t ftun_cli_result_reserve_terminal(ftun_cli_result_sink_t *sink,
  ftun_cli_result_kind_t kind, ftun_cli_result_ticket_t **out)
{
  ftun_cli_result_ticket_t *ticket;
  ftun_status_t status = FTUN_OK;
  if (out != NULL) *out = NULL;
  if (sink == NULL || out == NULL ||
      (kind != FTUN_CLI_RESULT_STOP_FAILED &&
       kind != FTUN_CLI_RESULT_RUN_FAILED)) return FTUN_E_INVALID;
  ftun_mutex_lock(&sink->mutex);
  ticket = ftun_cli_result_ticket_slot(sink, FTUN_CLI_RESULT_CAPACITY +
    (kind == FTUN_CLI_RESULT_RUN_FAILED ? 1u : 0u));
  if (!sink->accepting || sink->failed) {
    status = sink->failed ? FTUN_E_IO : FTUN_E_CANCELLED;
  } else if (ticket->state != FTUN_CLI_RESULT_FREE) {
    status = FTUN_E_LIMIT;
  } else {
    ticket->state = FTUN_CLI_RESULT_RESERVED;
    ticket->module = 0u;
    ticket->pid = 0u;
    ticket->background_reasons[0] = '\0';
    sink->reserved_count++;
    ftun_cli_result_count(&sink->accepted);
    *out = ticket;
  }
  if (status != FTUN_OK) ftun_cli_result_count(&sink->admission_rejected);
  ftun_mutex_unlock(&sink->mutex);
  return status;
}

ftun_status_t ftun_cli_result_report_admission_rejected(
  ftun_cli_result_sink_t *sink, ftun_status_t status)
{
  if (sink == NULL || status == FTUN_OK) return FTUN_E_INVALID;
  ftun_mutex_lock(&sink->mutex);
  if (!sink->accepting || sink->failed) {
    ftun_status_t rejected = sink->failed ? FTUN_E_IO : FTUN_E_CANCELLED;
    ftun_mutex_unlock(&sink->mutex);
    return rejected;
  }
  if (sink->rejection_notices == UINT64_MAX) {
    ftun_cli_result_count(&sink->undelivered);
    ftun_mutex_unlock(&sink->mutex);
    return FTUN_E_LIMIT;
  }
  sink->rejection_status = status;
  sink->rejection_notices++;
  ftun_condition_signal(&sink->available);
  ftun_mutex_unlock(&sink->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_cli_result_publish(ftun_cli_result_ticket_t *ticket,
                                      ftun_cli_result_kind_t kind,
                                      ftun_status_t status, uint32_t stage)
{
  return ftun_cli_result_publish_file(ticket, kind, status, stage, NULL);
}

ftun_status_t ftun_cli_result_publish_file(ftun_cli_result_ticket_t *ticket,
  ftun_cli_result_kind_t kind, ftun_status_t status, uint32_t stage, const char *path)
{
  ftun_cli_result_sink_t *sink;
  size_t slot;
  size_t path_length = path == NULL ? 0u : strnlen(path, FTUN_APP_CONTROL_PATH_CAPACITY);
  if (path_length >= FTUN_APP_CONTROL_PATH_CAPACITY) return FTUN_E_LIMIT;
  if (ticket == NULL || ticket->sink == NULL ||
      kind < FTUN_CLI_RESULT_RELOAD_COMMITTED ||
      kind > FTUN_CLI_RESULT_BACKGROUND_READY) return FTUN_E_INVALID;
  sink = ticket->sink;
  slot = (size_t)(ticket - sink->tickets);
  if (slot >= FTUN_CLI_RESULT_TOTAL) return FTUN_E_INVALID;
  ftun_mutex_lock(&sink->mutex);
  if (ticket->state != FTUN_CLI_RESULT_RESERVED ||
      sink->reserved_count == 0u) {
    ftun_mutex_unlock(&sink->mutex);
    return FTUN_E_STALE;
  }
  sink->reserved_count--;
  ticket->kind = (uint8_t)kind;
  ticket->status = status;
  ticket->stage = stage;
  if (path_length != 0u) memcpy(ticket->file_error, path, path_length);
  ticket->file_error[path_length] = '\0';
  if (sink->failed) {
    ticket->state = FTUN_CLI_RESULT_FREE;
    ftun_cli_result_count(&sink->undelivered);
    ftun_mutex_unlock(&sink->mutex);
    return FTUN_E_IO;
  }
  ticket->state = FTUN_CLI_RESULT_READY;
  sink->ready_slots[sink->ready_tail] = slot;
  sink->ready_tail = (sink->ready_tail + 1u) % FTUN_CLI_RESULT_TOTAL;
  sink->ready_count++;
  ftun_condition_signal(&sink->available);
  ftun_mutex_unlock(&sink->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_cli_result_publish_run_failure(ftun_cli_result_ticket_t *ticket,
  ftun_status_t status, uint32_t stage, uint32_t module, const char *path)
{
  if (ticket == NULL) return FTUN_E_INVALID;
  ticket->module = module;
  return ftun_cli_result_publish_file(ticket, FTUN_CLI_RESULT_RUN_FAILED, status, stage, path);
}

ftun_status_t ftun_cli_result_publish_ready(ftun_cli_result_ticket_t *ticket, const char *reasons)
{
  return ftun_cli_result_publish_file(ticket, FTUN_CLI_RESULT_RUN_READY, FTUN_OK, 0u, reasons);
}

ftun_status_t ftun_cli_result_publish_background_ready(ftun_cli_result_ticket_t *ticket,
  uint32_t pid, const char *log_file, const char *reasons)
{
  size_t length = strnlen(reasons, FTUN_CLI_READY_REASONS_CAPACITY);
  if (length == FTUN_CLI_READY_REASONS_CAPACITY) return FTUN_E_LIMIT;
  if (ticket == NULL) return FTUN_E_INVALID;
  ticket->pid = pid;
  memcpy(ticket->background_reasons, reasons, length + 1u);
  return ftun_cli_result_publish_file(ticket, FTUN_CLI_RESULT_BACKGROUND_READY, FTUN_OK, 0u, log_file);
}

ftun_status_t ftun_cli_result_abandon(ftun_cli_result_ticket_t *ticket)
{
  ftun_cli_result_sink_t *sink;
  size_t slot;
  if (ticket == NULL || ticket->sink == NULL) return FTUN_E_INVALID;
  sink = ticket->sink;
  slot = (size_t)(ticket - sink->tickets);
  if (slot >= FTUN_CLI_RESULT_TOTAL) return FTUN_E_INVALID;
  ftun_mutex_lock(&sink->mutex);
  if (ticket->state != FTUN_CLI_RESULT_RESERVED ||
      sink->reserved_count == 0u) {
    ftun_mutex_unlock(&sink->mutex);
    return FTUN_E_STALE;
  }
  sink->reserved_count--;
  ticket->state = FTUN_CLI_RESULT_FREE;
  ftun_mutex_unlock(&sink->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_cli_result_get_usage(ftun_cli_result_sink_t *sink,
                                        ftun_cli_result_usage_t *out)
{
  ftun_budget_usage_t resources;
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (sink == NULL || out == NULL) return FTUN_E_INVALID;
  ftun_mutex_lock(&sink->mutex);
  status = ftun_budget_get_usage(sink->budget, &resources);
  if (status != FTUN_OK) {
    ftun_mutex_unlock(&sink->mutex);
    return status;
  }
  out->owned_resources = resources.used_resources;
  out->budget_metadata_bytes = resources.metadata_bytes;
  out->capacity = FTUN_CLI_RESULT_TOTAL;
  out->reserved = sink->reserved_count;
  out->ready = sink->ready_count;
  out->accepted = sink->accepted;
  out->written = sink->written;
  out->write_failed = sink->write_failed;
  out->admission_rejected = sink->admission_rejected;
  out->rejection_notices = sink->rejection_notices;
  out->undelivered = sink->undelivered;
  out->accepting = sink->accepting != 0;
  out->stopping = sink->stopping != 0;
  out->exited = sink->exited != 0;
  ftun_mutex_unlock(&sink->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_cli_result_sink_stop_until(ftun_cli_result_sink_t **sink_ptr,
                                              uint64_t deadline_ms)
{
  ftun_cli_result_sink_t *sink;
  ftun_status_t wait_status = FTUN_OK;
  int exited;
  ftun_status_t result;
  size_t index;
  if (sink_ptr == NULL) return FTUN_E_INVALID;
  sink = *sink_ptr;
  if (sink == NULL) return FTUN_OK;
  ftun_mutex_lock(&sink->mutex);
  sink->accepting = 0;
  sink->stopping = 1;
  sink->deadline_ms = deadline_ms;
  for (index = 0u; index < FTUN_CLI_RESULT_TOTAL; index++) {
    if (!sink->initialized[index]) continue;
    if (sink->tickets[index].state == FTUN_CLI_RESULT_RESERVED) {
      sink->tickets[index].state = FTUN_CLI_RESULT_FREE;
      if (sink->reserved_count != 0u) sink->reserved_count--;
      ftun_cli_result_count(&sink->undelivered);
    }
  }
  ftun_condition_broadcast(&sink->available);
  while (!sink->exited && wait_status == FTUN_OK) {
    wait_status = ftun_condition_wait_until(&sink->exited_condition,
                                            &sink->mutex, deadline_ms);
  }
  exited = sink->exited;
  result = sink->timed_out ? FTUN_E_TIMEOUT :
    (sink->failed ? FTUN_E_IO : FTUN_OK);
  ftun_mutex_unlock(&sink->mutex);
  *sink_ptr = NULL;
  if (exited) {
    if (ftun_thread_join(&sink->thread) != FTUN_OK) {
      ftun_cli_result_release(sink);
      return FTUN_E_IO;
    }
    ftun_cli_result_release(sink);
    return result;
  }
  if (ftun_thread_detach(&sink->thread) != FTUN_OK) {
    /* 仍保留调用方引用，避免未知线程状态下释放；这是不可恢复系统错误。 */
    *sink_ptr = sink;
    return FTUN_E_IO;
  }
  ftun_cli_result_release(sink);
  return wait_status == FTUN_E_TIMEOUT ? FTUN_E_TIMEOUT : FTUN_E_IO;
}
