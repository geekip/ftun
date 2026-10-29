#include "libs/transport/stream.h"
#include <stdlib.h>
#include <string.h>

struct ftun_stream {
  ftun_budget_t *budget;
  ftun_operation_queue_t *operations;
  ftun_reservation_t reservation;
  ftun_stream_backend_t backend;
  ftun_completion_fn completion;
  void *completion_user;
  void (*progress)(void *user);
  void *progress_user;
  size_t max_pending_writes;
  size_t max_pending_bytes;
  size_t pending_writes;
  size_t pending_bytes;
  size_t completions;
  size_t backend_calls;
  size_t reference_count;
  uint64_t next_generation;
  ftun_stream_write_t *storage;
  ftun_stream_write_t *free_head;
  int accepting;
  int write_shutdown;
  int aborting;
  int destroying;
};

struct ftun_stream_write {
  ftun_stream_t *stream;
  ftun_operation_t *operation;
  ftun_operation_token_t completion_token;
  ftun_stream_write_t *free_next;
  ftun_buffer_slice_t slice;
  ftun_completion_fn completion;
  void *completion_user;
  size_t slot;
  uint64_t generation;
  int starting;
  int cancelling;
  int backend_owned;
};

static int ftun_stream_backend_valid(const ftun_stream_backend_t *backend)
{
  return backend != NULL && backend->write_start != NULL &&
         backend->write_cancel != NULL && backend->destroy != NULL;
}

static int ftun_stream_options_valid(const ftun_stream_options_t *options)
{
  return options != NULL && options->budget != NULL &&
         options->operations != NULL && options->max_pending_writes != 0u &&
         options->max_pending_bytes != 0u && options->completion != NULL;
}

static ftun_stream_write_token_t ftun_stream_write_token(
  const ftun_stream_write_t *write)
{
  ftun_stream_write_token_t token;
  memset(&token, 0, sizeof(token));
  if (write != NULL) {
    token.stream = write->stream;
    token.slot = write->slot;
    token.generation = write->generation;
  }
  return token;
}

static ftun_stream_write_t *ftun_stream_write_resolve(
  ftun_stream_write_token_t token)
{
  ftun_stream_write_t *write;
  if (token.stream == NULL || token.generation == 0u ||
      token.slot >= token.stream->max_pending_writes) return NULL;
  write = &token.stream->storage[token.slot];
  if (write->stream != token.stream || write->generation != token.generation) {
    return NULL;
  }
  return write;
}

static ftun_status_t ftun_stream_write_cancel(void *user)
{
  ftun_stream_write_t *write = (ftun_stream_write_t *)user;
  ftun_status_t status;
  if (write == NULL || write->stream == NULL || write->starting) {
    return FTUN_E_STATE_CORRUPT;
  }
  if (!write->backend_owned) return FTUN_OK;
  write->cancelling = 1;
  write->stream->backend_calls++;
  status = write->stream->backend.write_cancel(
    write->stream->backend.context, ftun_stream_write_token(write));
  write->stream->backend_calls--;
  write->cancelling = 0;
  if (status != FTUN_OK) return status;
  write->backend_owned = 0;
  return FTUN_OK;
}

static void ftun_stream_write_dispatched(ftun_operation_t *operation,
                                         ftun_error_t error, void *user)
{
  ftun_stream_write_t *write = (ftun_stream_write_t *)user;
  ftun_stream_t *stream;
  ftun_status_t release_status;
  if (write == NULL || write->stream == NULL) return;
  stream = write->stream;
  if (stream->pending_writes == 0u ||
      stream->pending_bytes < write->slice.length) {
    error.status = FTUN_E_STATE_CORRUPT;
  } else {
    stream->pending_writes--;
    stream->pending_bytes -= write->slice.length;
  }
  release_status = ftun_buffer_slice_release(&write->slice);
  if (release_status != FTUN_OK) error.status = release_status;
  write->operation = NULL;
  write->stream = NULL;
  stream->completions++;
  write->completion(operation, error, write->completion_user);
  if (stream->progress != NULL) stream->progress(stream->progress_user);
  memset(write, 0, sizeof(*write));
  write->free_next = stream->free_head;
  stream->free_head = write;
  stream->completions--;
}

static void ftun_stream_write_release(ftun_stream_write_t *write)
{
  ftun_stream_t *stream;
  if (write == NULL) return;
  stream = write->stream;
  (void)ftun_buffer_slice_release(&write->slice);
  memset(write, 0, sizeof(*write));
  write->free_next = stream->free_head;
  stream->free_head = write;
}

static ftun_status_t ftun_stream_write_reject(ftun_stream_write_t *write,
                                               ftun_status_t result)
{
  ftun_status_t status;
  status = ftun_operation_set_cancel_hook(write->operation, NULL, NULL);
  if (status != FTUN_OK) return status;
  status = ftun_operation_reject(&write->operation);
  if (status != FTUN_OK) return status;
  ftun_stream_write_release(write);
  return result;
}

/* 保留引用至完成事件。 */
ftun_status_t ftun_stream_create(const ftun_stream_options_t *options,
                                 const ftun_stream_backend_t *backend,
                                 ftun_stream_t **out)
{
  ftun_stream_t *stream;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_status_t status;
  size_t charge;
  size_t index;
  if (out != NULL) *out = NULL;
  if (out == NULL || !ftun_stream_options_valid(options) ||
      !ftun_stream_backend_valid(backend)) return FTUN_E_INVALID;
  if (options->max_pending_writes >
      (SIZE_MAX - sizeof(*stream)) / sizeof(ftun_stream_write_t)) {
    return FTUN_E_LIMIT;
  }
  charge = sizeof(*stream) + options->max_pending_writes *
    sizeof(ftun_stream_write_t);
  status = ftun_budget_reserve(options->budget, charge, &reservation);
  if (status != FTUN_OK) return status;
  stream = (ftun_stream_t *)calloc(1u, sizeof(*stream));
  if (stream != NULL) {
    stream->storage = (ftun_stream_write_t *)calloc(
      options->max_pending_writes, sizeof(*stream->storage));
  }
  if (stream == NULL || stream->storage == NULL) {
    if (stream != NULL) free(stream->storage);
    free(stream);
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  stream->budget = options->budget;
  stream->operations = options->operations;
  stream->reservation = reservation;
  stream->backend = *backend;
  stream->completion = options->completion;
  stream->completion_user = options->completion_user;
  stream->progress = options->progress;
  stream->progress_user = options->progress_user;
  stream->max_pending_writes = options->max_pending_writes;
  stream->max_pending_bytes = options->max_pending_bytes;
  stream->reference_count = 1u;
  stream->accepting = 1;
  for (index = 0u; index < options->max_pending_writes; index++) {
    stream->storage[index].free_next = stream->free_head;
    stream->free_head = &stream->storage[index];
  }
  *out = stream;
  return FTUN_OK;
}

ftun_status_t ftun_stream_write_ref_ex(
  ftun_stream_t *stream, const ftun_buffer_slice_t *slice,
  ftun_completion_fn completion, void *completion_user,
  size_t *accepted, ftun_operation_t **out, ftun_stream_limit_t *reason)
{
  ftun_stream_write_t *write;
  ftun_bytes_t bytes;
  ftun_status_t status;
  size_t available;
  size_t offered;
  size_t backend_accepted = 0u;
  if (reason != NULL) *reason = FTUN_STREAM_LIMIT_NONE;
  if (accepted != NULL) *accepted = 0u;
  if (out != NULL) *out = NULL;
  if (stream == NULL || slice == NULL || completion == NULL ||
      accepted == NULL || out == NULL) {
    return FTUN_E_INVALID;
  }
  status = ftun_buffer_slice_data(slice, &bytes);
  if (status != FTUN_OK || bytes.length == 0u) return FTUN_E_INVALID;
  if (!stream->accepting) return FTUN_E_CANCELLED;
  if (stream->pending_writes >= stream->max_pending_writes ||
      stream->pending_bytes >= stream->max_pending_bytes) {
    if (reason != NULL) *reason = FTUN_STREAM_LIMIT_STREAM;
    return FTUN_E_LIMIT;
  }
  available = stream->max_pending_bytes - stream->pending_bytes;
  offered = bytes.length < available ? bytes.length : available;
  if (offered == 0u) {
    if (reason != NULL) *reason = FTUN_STREAM_LIMIT_STREAM;
    return FTUN_E_LIMIT;
  }

  write = stream->free_head;
  if (write == NULL) return FTUN_E_STATE_CORRUPT;
  stream->free_head = write->free_next;
  memset(write, 0, sizeof(*write));
  write->stream = stream;
  stream->next_generation++;
  if (stream->next_generation == 0u) stream->next_generation++;
  write->slot = (size_t)(write - stream->storage);
  write->generation = stream->next_generation;
  write->completion = completion;
  write->completion_user = completion_user;
  status = ftun_operation_accept(stream->operations,
                                 ftun_stream_write_dispatched, write,
                                 &write->operation, &write->completion_token);
  if (status != FTUN_OK) {
    ftun_stream_write_release(write);
    if (status == FTUN_E_LIMIT && reason != NULL) {
      *reason = FTUN_STREAM_LIMIT_OPERATIONS;
    }
    return status;
  }
  status = ftun_buffer_slice_clone(slice, &write->slice);
  if (status != FTUN_OK) return ftun_stream_write_reject(write, status);
  write->slice.length = offered;
  status = ftun_operation_set_cancel_hook(write->operation,
                                          ftun_stream_write_cancel, write);
  if (status != FTUN_OK) return ftun_stream_write_reject(write, status);

  write->starting = 1;
  stream->backend_calls++;
  status = stream->backend.write_start(stream->backend.context,
                                       ftun_stream_write_token(write),
                                       &write->slice, &backend_accepted);
  stream->backend_calls--;
  write->starting = 0;
  if (status != FTUN_OK) {
    if (status == FTUN_E_LIMIT && reason != NULL) {
      *reason = FTUN_STREAM_LIMIT_BACKEND;
    }
    return ftun_stream_write_reject(write, status);
  }
  write->backend_owned = 1;
  if (backend_accepted == 0u || backend_accepted > offered) {
    write->cancelling = 1;
    stream->backend_calls++;
    status = stream->backend.write_cancel(stream->backend.context,
                                          ftun_stream_write_token(write));
    stream->backend_calls--;
    write->cancelling = 0;
    if (status != FTUN_OK) return status;
    write->backend_owned = 0;
    return ftun_stream_write_reject(write, FTUN_E_STATE_CORRUPT);
  }
  write->slice.length = backend_accepted;
  stream->pending_writes++;
  stream->pending_bytes += backend_accepted;
  *accepted = backend_accepted;
  *out = write->operation;
  return FTUN_OK;
}

ftun_status_t ftun_stream_write_ref_with_completion(
  ftun_stream_t *stream, const ftun_buffer_slice_t *slice,
  ftun_completion_fn completion, void *completion_user,
  size_t *accepted, ftun_operation_t **out)
{
  return ftun_stream_write_ref_ex(stream, slice, completion, completion_user,
                                  accepted, out, NULL);
}

ftun_operation_queue_t *ftun_stream_operations(const ftun_stream_t *stream)
{
  return stream == NULL ? NULL : stream->operations;
}

ftun_status_t ftun_stream_write_ref(ftun_stream_t *stream,
                                    const ftun_buffer_slice_t *slice,
                                    size_t *accepted,
                                    ftun_operation_t **out)
{
  if (accepted != NULL) *accepted = 0u;
  if (out != NULL) *out = NULL;
  if (stream == NULL) return FTUN_E_INVALID;
  return ftun_stream_write_ref_with_completion(
    stream, slice, stream->completion, stream->completion_user, accepted, out);
}

ftun_status_t ftun_stream_read(ftun_stream_t *stream, void *buffer,
                               size_t capacity, size_t *out_length)
{
  ftun_status_t status;
  if (out_length != NULL) *out_length = 0u;
  if (stream == NULL || buffer == NULL || capacity == 0u || out_length == NULL) {
    return FTUN_E_INVALID;
  }
  if (!stream->accepting) return FTUN_E_CANCELLED;
  if (stream->backend.read == NULL) return FTUN_E_UNSUPPORTED;
  stream->backend_calls++;
  status = stream->backend.read(stream->backend.context, buffer, capacity,
                                out_length);
  stream->backend_calls--;
  if (status == FTUN_OK) {
    if (*out_length == 0u || *out_length > capacity) {
      *out_length = 0u;
      return FTUN_E_STATE_CORRUPT;
    }
    return FTUN_OK;
  }
  if (*out_length != 0u) {
    *out_length = 0u;
    return FTUN_E_STATE_CORRUPT;
  }
  return status;
}

ftun_status_t ftun_stream_shutdown_write(ftun_stream_t *stream)
{
  ftun_status_t status;
  if (stream == NULL) return FTUN_E_INVALID;
  if (stream->write_shutdown) return FTUN_OK;
  if (stream->backend.shutdown_write == NULL) return FTUN_E_UNSUPPORTED;
  stream->backend_calls++;
  status = stream->backend.shutdown_write(stream->backend.context);
  stream->backend_calls--;
  if (status == FTUN_OK) stream->write_shutdown = 1;
  return status;
}

ftun_status_t ftun_stream_budget(ftun_stream_t *stream, ftun_budget_t **out)
{
  if (out != NULL) *out = NULL;
  if (stream == NULL || out == NULL) return FTUN_E_INVALID;
  *out = stream->budget;
  return FTUN_OK;
}

ftun_status_t ftun_stream_retain(ftun_stream_t *stream)
{
  if (stream == NULL) return FTUN_E_INVALID;
  if (stream->destroying) return FTUN_E_AGAIN;
  if (stream->reference_count == 0u) return FTUN_E_STATE_CORRUPT;
  if (stream->reference_count == SIZE_MAX) return FTUN_E_LIMIT;
  stream->reference_count++;
  return FTUN_OK;
}

ftun_status_t ftun_stream_release(ftun_stream_t **stream)
{
  ftun_stream_t *owned;
  if (stream == NULL) return FTUN_E_INVALID;
  owned = *stream;
  if (owned == NULL) return FTUN_OK;
  if (owned->reference_count <= 1u) return FTUN_E_STATE_CORRUPT;
  owned->reference_count--;
  *stream = NULL;
  return FTUN_OK;
}

ftun_status_t ftun_stream_write_data(ftun_stream_write_token_t token,
                                     ftun_bytes_t *out)
{
  ftun_stream_write_t *write;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (token.stream == NULL || token.generation == 0u || out == NULL) {
    return FTUN_E_INVALID;
  }
  write = ftun_stream_write_resolve(token);
  if (write == NULL || (!write->starting && !write->backend_owned)) {
    return FTUN_E_STALE;
  }
  return ftun_buffer_slice_data(&write->slice, out);
}

ftun_status_t ftun_stream_write_complete(ftun_stream_write_token_t token,
                                         ftun_error_t error)
{
  ftun_stream_write_t *write;
  ftun_status_t status;
  if (token.stream == NULL || token.generation == 0u) return FTUN_E_INVALID;
  if (error.status == FTUN_E_AGAIN) return FTUN_E_INVALID;
  write = ftun_stream_write_resolve(token);
  if (write == NULL || write->starting || !write->backend_owned) {
    return FTUN_E_STALE;
  }
  if (write->cancelling) return FTUN_E_AGAIN;
  status = ftun_operation_complete(write->completion_token, error);
  if (status != FTUN_OK) return status;
  write->backend_owned = 0;
  return FTUN_OK;
}

ftun_status_t ftun_stream_stop(ftun_stream_t *stream)
{
  if (stream == NULL) return FTUN_E_INVALID;
  stream->accepting = 0;
  return FTUN_OK;
}

ftun_status_t ftun_stream_abort(ftun_stream_t *stream)
{
  ftun_status_t first = FTUN_OK;
  size_t index;
  if (stream == NULL) return FTUN_E_INVALID;
  stream->accepting = 0;
  if (stream->aborting || stream->completions != 0u ||
      stream->backend_calls != 0u) return FTUN_E_AGAIN;
  /* 后端接纳/取消尚未返回时，不能通过嵌套调用释放其正在使用的槽位。 */
  for (index = 0u; index < stream->max_pending_writes; index++) {
    const ftun_stream_write_t *write = &stream->storage[index];
    if (write->starting || write->cancelling) return FTUN_E_AGAIN;
  }
  stream->aborting = 1;
  for (index = 0u; index < stream->max_pending_writes; index++) {
    ftun_stream_write_t *write = &stream->storage[index];
    ftun_status_t status;
    if (write->stream != stream || write->operation == NULL) continue;
    status = ftun_operation_cancel(write->operation);
    /* 同一轮之前或上次重试已取消、等待 dispatch 的项不再拥有 backend；
     * Operation 对重复 cancel 返回 STALE，此处仍是成功的静默状态。 */
    if (status == FTUN_E_STALE && !write->backend_owned) continue;
    if (first == FTUN_OK && status != FTUN_OK) first = status;
  }
  stream->aborting = 0;
  return first;
}

ftun_status_t ftun_stream_get_usage(const ftun_stream_t *stream,
                                    ftun_stream_usage_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (stream == NULL || out == NULL) return FTUN_E_INVALID;
  out->max_pending_writes = stream->max_pending_writes;
  out->max_pending_bytes = stream->max_pending_bytes;
  out->pending_writes = stream->pending_writes;
  out->pending_bytes = stream->pending_bytes;
  out->reference_count = stream->reference_count;
  out->accepting = stream->accepting != 0;
  out->in_completion = stream->completions != 0u;
  out->in_backend = stream->backend_calls != 0u;
  out->write_shutdown = stream->write_shutdown != 0;
  return FTUN_OK;
}

ftun_status_t ftun_stream_destroy(ftun_stream_t **stream)
{
  ftun_stream_t *owned;
  ftun_reservation_t reservation;
  ftun_status_t status;
  size_t index;
  if (stream == NULL) return FTUN_E_INVALID;
  owned = *stream;
  if (owned == NULL) return FTUN_OK;
  if (owned->accepting || owned->aborting || owned->backend_calls != 0u ||
      owned->reference_count != 1u ||
      owned->pending_writes != 0u ||
      owned->pending_bytes != 0u || owned->completions != 0u) {
    return FTUN_E_AGAIN;
  }
  /* start 返回前尚未计入 pending，也不能在后端嵌套 stop 后销毁。 */
  for (index = 0u; index < owned->max_pending_writes; index++) {
    if (owned->storage[index].stream != NULL) return FTUN_E_AGAIN;
  }
  reservation = owned->reservation;
  status = ftun_reservation_release(&reservation);
  if (status != FTUN_OK) return status;
  owned->reservation = (ftun_reservation_t){0};
  owned->destroying = 1;
  owned->backend_calls++;
  owned->backend.destroy(owned->backend.context);
  free(owned->storage);
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *stream = NULL;
  return FTUN_OK;
}
