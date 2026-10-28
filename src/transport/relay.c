#include "relay.h"
#include "core/budget.h"
#include "util/buffer.h"
#include <stdlib.h>
#include <string.h>

typedef struct ftun_relay_direction ftun_relay_direction_t;

struct ftun_relay_direction {
  ftun_relay_t *relay;
  ftun_stream_t *source;
  ftun_stream_t *destination;
  ftun_buffer_t *buffer;
  ftun_operation_t *operation;
  ftun_buffer_wait_token_t buffer_wait;
  /* Operation 队列满时的等待节点；排队期间不重试写入，也不占用 owner 配额。 */
  ftun_operation_waiter_t operation_wait;
  size_t offset;
  size_t length;
  size_t accepted;
  int source_eof;
  int read_ready;
  int read_paused;
  int write_pending;
  int write_blocked;
  int shutdown_done;
  int shutdown_blocked;
  int buffer_waiting;
  int buffer_ready;
  int operation_waiting;
};

struct ftun_relay {
  ftun_budget_t *budget;
  ftun_buffer_pool_t *pool;
  ftun_reservation_t *reservation;
  ftun_relay_direction_t left_to_right;
  ftun_relay_direction_t right_to_left;
  size_t high_water;
  size_t low_water;
  size_t max_work;
  size_t total_read;
  size_t total_written;
  unsigned int cursor;
  ftun_status_t terminal_status;
  ftun_relay_progress_fn progress;
  void *progress_user;
  int stopped;
  int processing;
};

static ftun_status_t ftun_relay_fail(ftun_relay_t *relay,
                                     ftun_status_t status);

static int ftun_relay_options_valid(const ftun_relay_options_t *options)
{
  return options != NULL && options->high_water_bytes != 0u &&
         options->low_water_bytes < options->high_water_bytes &&
         options->max_work_per_round != 0u;
}

static void ftun_relay_release_buffer(ftun_relay_direction_t *direction)
{
  if (direction->buffer != NULL) {
    (void)ftun_buffer_release(&direction->buffer);
  }
  direction->offset = 0u;
  direction->length = 0u;
}

static ftun_status_t ftun_relay_add(size_t *total, size_t value)
{
  if (*total > SIZE_MAX - value) return FTUN_E_LIMIT;
  *total += value;
  return FTUN_OK;
}

static ftun_status_t ftun_relay_cancel_direction(
  ftun_relay_direction_t *direction)
{
  ftun_status_t status = FTUN_OK;
  if (direction->buffer_waiting) {
    status = ftun_buffer_pool_wait_cancel(&direction->buffer_wait);
    if (status == FTUN_E_STALE) status = FTUN_OK;
    if (status == FTUN_OK) {
      direction->buffer_waiting = 0;
      memset(&direction->buffer_wait, 0, sizeof(direction->buffer_wait));
    }
  }
  if (direction->operation_waiting) {
    (void)ftun_operation_queue_wait_cancel(&direction->operation_wait);
    direction->operation_waiting = 0;
  }
  if (direction->operation != NULL) {
    ftun_status_t current = ftun_operation_cancel(direction->operation);
    if (current == FTUN_E_STALE) current = FTUN_OK;
    if (status == FTUN_OK) status = current;
  }
  ftun_relay_release_buffer(direction);
  direction->buffer_ready = 0;
  direction->read_ready = 0;
  direction->write_blocked = 0;
  direction->shutdown_blocked = 0;
  return status;
}

static ftun_status_t ftun_relay_fail(ftun_relay_t *relay,
                                     ftun_status_t status)
{
  ftun_status_t cleanup;
  if (relay->terminal_status == FTUN_OK) relay->terminal_status = status;
  relay->stopped = 1;
  cleanup = ftun_relay_cancel_direction(&relay->left_to_right);
  if (cleanup == FTUN_OK) {
    cleanup = ftun_relay_cancel_direction(&relay->right_to_left);
  } else {
    (void)ftun_relay_cancel_direction(&relay->right_to_left);
  }
  return cleanup == FTUN_OK ? status : cleanup;
}

static void ftun_relay_operation_ready(void *user)
{
  ftun_relay_direction_t *direction = (ftun_relay_direction_t *)user;
  ftun_relay_t *relay;
  if (direction == NULL || direction->relay == NULL) return;
  relay = direction->relay;
  direction->operation_waiting = 0;
  if (relay->progress != NULL) relay->progress(relay->progress_user);
}

static void ftun_relay_buffer_ready(void *user)
{
  ftun_relay_direction_t *direction = (ftun_relay_direction_t *)user;
  ftun_relay_t *relay;
  ftun_status_t status;
  if (direction == NULL || direction->relay == NULL) return;
  relay = direction->relay;
  direction->buffer_waiting = 0;
  memset(&direction->buffer_wait, 0, sizeof(direction->buffer_wait));
  if (!relay->stopped && direction->buffer == NULL) {
    status = ftun_buffer_pool_acquire(relay->pool, relay->high_water,
                                      &direction->buffer);
    if (status == FTUN_OK) {
      direction->buffer_ready = 1;
    } else {
      (void)ftun_relay_fail(relay, status);
    }
  }
  if (relay->progress != NULL) relay->progress(relay->progress_user);
}

static void ftun_relay_write_completed(ftun_operation_t *operation,
                                       ftun_error_t error, void *user)
{
  ftun_relay_direction_t *direction = (ftun_relay_direction_t *)user;
  ftun_relay_t *relay = direction->relay;
  (void)operation;
  direction->operation = NULL;
  direction->write_pending = 0;
  if (relay->stopped) {
    direction->accepted = 0u;
    ftun_relay_release_buffer(direction);
    return;
  }
  if (error.status != FTUN_OK || direction->buffer == NULL ||
      direction->accepted == 0u || direction->accepted > direction->length) {
    direction->accepted = 0u;
    (void)ftun_relay_fail(relay, error.status == FTUN_OK
      ? FTUN_E_STATE_CORRUPT : error.status);
    return;
  }
  direction->offset += direction->accepted;
  direction->length -= direction->accepted;
  if (ftun_relay_add(&relay->total_written, direction->accepted) != FTUN_OK) {
    direction->accepted = 0u;
    (void)ftun_relay_fail(relay, FTUN_E_LIMIT);
    return;
  }
  direction->accepted = 0u;
  if (direction->length == 0u) ftun_relay_release_buffer(direction);
  if (direction->length <= relay->low_water) direction->read_paused = 0;
}

static ftun_status_t ftun_relay_buffer(ftun_relay_direction_t *direction,
                                       uint8_t **data, size_t *capacity)
{
  ftun_relay_t *relay = direction->relay;
  ftun_status_t status;
  if (direction->buffer == NULL) {
    status = relay->pool == NULL
      ? ftun_buffer_acquire(relay->budget, relay->high_water,
                            &direction->buffer)
      : ftun_buffer_pool_acquire(relay->pool, relay->high_water,
                                 &direction->buffer);
    if (status == FTUN_E_LIMIT && relay->pool != NULL) {
      if (direction->buffer_waiting) return FTUN_E_AGAIN;
      status = ftun_buffer_pool_wait(relay->pool, relay->high_water,
        ftun_relay_buffer_ready, direction, &direction->buffer_wait);
      if (status == FTUN_OK) {
        direction->buffer_waiting = 1;
        return FTUN_E_AGAIN;
      }
      if (status == FTUN_E_AGAIN) {
        status = ftun_buffer_pool_acquire(relay->pool, relay->high_water,
                                          &direction->buffer);
      }
    }
    if (status != FTUN_OK) return status;
  }
  status = ftun_buffer_data(direction->buffer, data, capacity);
  if (status != FTUN_OK) return status;
  if (*capacity < relay->high_water) return FTUN_E_STATE_CORRUPT;
  if (!direction->write_pending && direction->offset != 0u &&
      direction->length != 0u) {
    memmove(*data, *data + direction->offset, direction->length);
    direction->offset = 0u;
  } else if (direction->length == 0u) {
    direction->offset = 0u;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_relay_read_direction(
  ftun_relay_direction_t *direction, int *did_work)
{
  ftun_relay_t *relay = direction->relay;
  uint8_t *data = NULL;
  size_t capacity = 0u;
  size_t received = 0u;
  size_t available;
  ftun_status_t status;
  *did_work = 0;
  if (direction->source_eof || direction->read_paused ||
      direction->length >= relay->high_water) return FTUN_OK;
  status = ftun_relay_buffer(direction, &data, &capacity);
  if (status == FTUN_E_AGAIN && direction->buffer_waiting) return FTUN_OK;
  if (status != FTUN_OK) return status;
  if (direction->offset > relay->high_water ||
      direction->length > relay->high_water - direction->offset) {
    return FTUN_E_STATE_CORRUPT;
  }
  available = relay->high_water - direction->offset - direction->length;
  if (available == 0u) {
    direction->read_paused = 1;
    return FTUN_OK;
  }
  status = ftun_stream_read(direction->source,
                            data + direction->offset + direction->length,
                            available, &received);
  direction->buffer_ready = 0;
  *did_work = 1;
  if (status == FTUN_OK) {
    direction->length += received;
    status = ftun_relay_add(&relay->total_read, received);
    if (status != FTUN_OK) return status;
    if (direction->length >= relay->high_water) direction->read_paused = 1;
    return FTUN_OK;
  }
  if (status == FTUN_E_EOF) {
    direction->read_ready = 0;
    direction->source_eof = 1;
    if (direction->length == 0u) ftun_relay_release_buffer(direction);
    return FTUN_OK;
  }
  if (status == FTUN_E_AGAIN) {
    direction->read_ready = 0;
    if (direction->length == 0u) ftun_relay_release_buffer(direction);
    return FTUN_OK;
  }
  return status;
}

static ftun_status_t ftun_relay_progress_direction(
  ftun_relay_direction_t *direction, int destination_writable, int *did_work)
{
  ftun_buffer_slice_t slice;
  ftun_operation_t *operation = NULL;
  size_t accepted = 0u;
  ftun_stream_limit_t limit = FTUN_STREAM_LIMIT_NONE;
  ftun_status_t status;
  *did_work = 0;
  if (direction->write_pending || direction->shutdown_done) return FTUN_OK;
  if (direction->operation_waiting) return FTUN_OK;
  if (direction->length != 0u) {
    if (direction->write_blocked && !destination_writable) return FTUN_OK;
    memset(&slice, 0, sizeof(slice));
    status = ftun_buffer_slice(direction->buffer, direction->offset,
                               direction->length, &slice);
    if (status != FTUN_OK) return status;
    status = ftun_stream_write_ref_ex(
      direction->destination, &slice, ftun_relay_write_completed, direction,
      &accepted, &operation, &limit);
    (void)ftun_buffer_slice_release(&slice);
    *did_work = 1;
    if (status == FTUN_E_AGAIN) {
      direction->write_blocked = 1;
      return FTUN_OK;
    }
    if (status == FTUN_E_LIMIT) {
      direction->write_blocked = 0;
      /* 全局 Operation 队列满：等有额度回收再重试，而不是每轮空转。 */
      if (limit == FTUN_STREAM_LIMIT_OPERATIONS) {
        status = ftun_operation_queue_wait(
          ftun_stream_operations(direction->destination),
          &direction->operation_wait, ftun_relay_operation_ready, direction);
        if (status == FTUN_OK) {
          direction->operation_waiting = 1;
          *did_work = 0;
        } else if (status != FTUN_E_AGAIN) {
          return status;
        }
      }
      return FTUN_OK;
    }
    if (status != FTUN_OK) return status;
    direction->operation = operation;
    direction->accepted = accepted;
    direction->write_pending = 1;
    direction->write_blocked = 0;
    return FTUN_OK;
  }
  if (!direction->source_eof) return FTUN_OK;
  if (direction->shutdown_blocked && !destination_writable) return FTUN_OK;
  status = ftun_stream_shutdown_write(direction->destination);
  *did_work = 1;
  if (status == FTUN_E_AGAIN) {
    direction->shutdown_blocked = 1;
    return FTUN_OK;
  }
  if (status != FTUN_OK) return status;
  direction->shutdown_done = 1;
  direction->shutdown_blocked = 0;
  return FTUN_OK;
}

static int ftun_relay_direction_readable(const ftun_relay_direction_t *direction)
{
  const ftun_relay_t *relay = direction->relay;
  return !relay->stopped && !direction->source_eof &&
         !direction->read_paused && !direction->buffer_waiting &&
         direction->length < relay->high_water;
}

static int ftun_relay_direction_writable(const ftun_relay_direction_t *direction)
{
  const ftun_relay_t *relay = direction->relay;
  if (relay->stopped || direction->write_pending || direction->shutdown_done) return 0;
  if (direction->operation_waiting) return 0;
  if (direction->length != 0u) return direction->write_blocked;
  return direction->source_eof && direction->shutdown_blocked;
}

static int ftun_relay_complete(const ftun_relay_t *relay)
{
  return relay->terminal_status == FTUN_OK && !relay->stopped &&
         relay->left_to_right.shutdown_done &&
         relay->right_to_left.shutdown_done &&
         relay->left_to_right.operation == NULL &&
         relay->right_to_left.operation == NULL;
}

/* 双向有界背压。 */
ftun_status_t ftun_relay_start_with_options(
  ftun_core_t *core, ftun_stream_t *left, ftun_stream_t *right,
  const ftun_relay_options_t *options, ftun_relay_t **out)
{
  ftun_relay_t *relay;
  ftun_budget_t *left_budget = NULL;
  ftun_budget_t *right_budget = NULL;
  ftun_reservation_t *reservation = NULL;
  bool same_budget_root = false;
  ftun_status_t status;
  (void)core;
  if (out != NULL) *out = NULL;
  if (out == NULL || left == NULL || right == NULL || left == right ||
      !ftun_relay_options_valid(options)) return FTUN_E_INVALID;
  status = ftun_stream_budget(left, &left_budget);
  if (status == FTUN_OK) status = ftun_stream_budget(right, &right_budget);
  if (status == FTUN_OK) {
    status = ftun_budget_same_root(left_budget, right_budget,
                                   &same_budget_root);
  }
  if (status != FTUN_OK) return status;
  if (!same_budget_root) return FTUN_E_REJECTED;
  status = ftun_budget_reserve(left_budget, sizeof(*relay), &reservation);
  if (status != FTUN_OK) return status;
  relay = (ftun_relay_t *)calloc(1u, sizeof(*relay));
  if (relay == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  relay->budget = left_budget;
  relay->reservation = reservation;
  relay->high_water = options->high_water_bytes;
  relay->low_water = options->low_water_bytes;
  relay->max_work = options->max_work_per_round;
  relay->left_to_right.relay = relay;
  relay->left_to_right.source = left;
  relay->left_to_right.destination = right;
  relay->right_to_left.relay = relay;
  relay->right_to_left.source = right;
  relay->right_to_left.destination = left;
  *out = relay;
  return FTUN_OK;
}

ftun_status_t ftun_relay_start(ftun_core_t *core, ftun_stream_t *left,
                               ftun_stream_t *right, ftun_relay_t **out)
{
  const ftun_relay_options_t options = {
    FTUN_RELAY_DEFAULT_HIGH_WATER,
    FTUN_RELAY_DEFAULT_LOW_WATER,
    FTUN_RELAY_DEFAULT_MAX_WORK
  };
  return ftun_relay_start_with_options(core, left, right, &options, out);
}

ftun_status_t ftun_relay_start_with_pool_options(
  ftun_core_t *core, ftun_stream_t *left, ftun_stream_t *right,
  ftun_buffer_pool_t *pool, const ftun_relay_options_t *options,
  ftun_relay_progress_fn progress, void *progress_user, ftun_relay_t **out)
{
  ftun_status_t status;
  if (pool == NULL || (progress == NULL && progress_user != NULL)) {
    if (out != NULL) *out = NULL;
    return FTUN_E_INVALID;
  }
  status = ftun_relay_start_with_options(core, left, right, options, out);
  if (status == FTUN_OK) {
    (*out)->pool = pool;
    (*out)->progress = progress;
    (*out)->progress_user = progress_user;
  }
  return status;
}

ftun_status_t ftun_relay_process(ftun_relay_t *relay,
                                 uint32_t left_events,
                                 uint32_t right_events,
                                 size_t *out_work)
{
  const uint32_t allowed = FTUN_EVENT_READ | FTUN_EVENT_WRITE | FTUN_EVENT_ERROR;
  size_t work = 0u;
  size_t scans = 0u;
  ftun_status_t status;
  if (out_work != NULL) *out_work = 0u;
  if (relay == NULL || out_work == NULL ||
      (left_events & ~allowed) != 0u || (right_events & ~allowed) != 0u) {
    return FTUN_E_INVALID;
  }
  if (relay->processing) return FTUN_E_AGAIN;
  if (relay->stopped) return relay->terminal_status == FTUN_OK
    ? FTUN_E_CANCELLED : relay->terminal_status;
  if ((left_events & FTUN_EVENT_ERROR) != 0u ||
      (right_events & FTUN_EVENT_ERROR) != 0u) {
    return ftun_relay_fail(relay, FTUN_E_IO);
  }
  relay->processing = 1;
  /* 就绪状态跨配额、背压和写完成保留，读空后等待新的提示。 */
  if ((left_events & FTUN_EVENT_READ) != 0u) relay->left_to_right.read_ready = 1;
  if ((right_events & FTUN_EVENT_READ) != 0u) relay->right_to_left.read_ready = 1;
  while (work < relay->max_work && scans < 4u) {
    int did_work = 0;
    unsigned int slot = relay->cursor;
    relay->cursor = (relay->cursor + 1u) % 4u;
    scans++;
    if (slot == 0u && (relay->left_to_right.read_ready ||
                       relay->left_to_right.buffer_ready) &&
        ftun_relay_direction_readable(&relay->left_to_right)) {
      status = ftun_relay_read_direction(&relay->left_to_right, &did_work);
    } else if (slot == 1u && (relay->right_to_left.read_ready ||
                              relay->right_to_left.buffer_ready) &&
               ftun_relay_direction_readable(&relay->right_to_left)) {
      status = ftun_relay_read_direction(&relay->right_to_left, &did_work);
    } else if (slot == 2u) {
      status = ftun_relay_progress_direction(
        &relay->left_to_right,
        (right_events & FTUN_EVENT_WRITE) != 0u, &did_work);
    } else if (slot == 3u) {
      status = ftun_relay_progress_direction(
        &relay->right_to_left,
        (left_events & FTUN_EVENT_WRITE) != 0u, &did_work);
    } else {
      status = FTUN_OK;
    }
    if (status != FTUN_OK) {
      relay->processing = 0;
      *out_work = work + (did_work ? 1u : 0u);
      if (status == FTUN_E_LIMIT && !did_work) return status;
      return ftun_relay_fail(relay, status);
    }
    if (did_work) {
      work++;
      scans = 0u;
    }
  }
  relay->processing = 0;
  *out_work = work;
  return FTUN_OK;
}

ftun_status_t ftun_relay_stop(ftun_relay_t *relay)
{
  ftun_status_t left_status;
  ftun_status_t right_status;
  if (relay == NULL) return FTUN_E_INVALID;
  relay->stopped = 1;
  if (relay->terminal_status == FTUN_OK) {
    relay->terminal_status = FTUN_E_CANCELLED;
  }
  left_status = ftun_relay_cancel_direction(&relay->left_to_right);
  right_status = ftun_relay_cancel_direction(&relay->right_to_left);
  return left_status != FTUN_OK ? left_status : right_status;
}

ftun_status_t ftun_relay_get_usage(const ftun_relay_t *relay,
                                   ftun_relay_usage_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (relay == NULL || out == NULL) return FTUN_E_INVALID;
  out->left_to_right_buffered = relay->left_to_right.length;
  out->right_to_left_buffered = relay->right_to_left.length;
  out->total_read_bytes = relay->total_read;
  out->total_written_bytes = relay->total_written;
  if (ftun_relay_direction_readable(&relay->left_to_right)) {
    out->left_interests |= FTUN_EVENT_READ;
  }
  if (ftun_relay_direction_readable(&relay->right_to_left)) {
    out->right_interests |= FTUN_EVENT_READ;
  }
  if (ftun_relay_direction_writable(&relay->right_to_left)) {
    out->left_interests |= FTUN_EVENT_WRITE;
  }
  if (ftun_relay_direction_writable(&relay->left_to_right)) {
    out->right_interests |= FTUN_EVENT_WRITE;
  }
  out->terminal_status = relay->terminal_status;
  out->left_eof = relay->left_to_right.source_eof != 0;
  out->right_eof = relay->right_to_left.source_eof != 0;
  out->left_write_shutdown = relay->right_to_left.shutdown_done != 0;
  out->right_write_shutdown = relay->left_to_right.shutdown_done != 0;
  out->stopped = relay->stopped != 0;
  out->complete = ftun_relay_complete(relay) != 0;
  out->left_buffer_waiting = relay->left_to_right.buffer_waiting != 0;
  out->right_buffer_waiting = relay->right_to_left.buffer_waiting != 0;
  return FTUN_OK;
}

ftun_status_t ftun_relay_destroy(ftun_relay_t **relay)
{
  ftun_relay_t *owned;
  ftun_reservation_t *reservation;
  ftun_status_t status;
  if (relay == NULL) return FTUN_E_INVALID;
  owned = *relay;
  if (owned == NULL) return FTUN_OK;
  if ((!owned->stopped && !ftun_relay_complete(owned)) || owned->processing ||
      owned->left_to_right.operation != NULL ||
      owned->right_to_left.operation != NULL ||
      owned->left_to_right.buffer != NULL ||
      owned->right_to_left.buffer != NULL ||
      owned->left_to_right.buffer_waiting ||
      owned->right_to_left.buffer_waiting) return FTUN_E_AGAIN;
  reservation = owned->reservation;
  status = ftun_reservation_release(&reservation);
  if (status != FTUN_OK) return status;
  owned->reservation = NULL;
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *relay = NULL;
  return FTUN_OK;
}
