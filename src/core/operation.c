#include "core/operation.h"
#include "platform/thread.h"
#include "platform/atomic.h"
#include <stdlib.h>
#include <string.h>

typedef enum {
  FTUN_OPERATION_ACCEPTED = 1,
  FTUN_OPERATION_TERMINAL,
  FTUN_OPERATION_CANCELLING,
  FTUN_OPERATION_CANCELLING_TERMINAL,
  FTUN_OPERATION_CANCELLING_COMPLETED,
  FTUN_OPERATION_CALLBACK
} ftun_operation_state_t;

struct ftun_operation {
  ftun_operation_queue_t *queue;
  ftun_operation_t *previous;
  ftun_operation_t *next;
  ftun_operation_t *ready_previous;
  ftun_operation_t *ready_next;
  ftun_operation_t *free_next;
  ftun_completion_fn callback;
  void *user;
  ftun_operation_cancel_hook_fn cancel_hook;
  void *cancel_user;
  ftun_error_t result;
  size_t slot;
  uint64_t generation;
  ftun_operation_state_t state;
  int control;
};

struct ftun_operation_queue {
  ftun_budget_t *budget;
  ftun_reservation_t reservation;
  ftun_operation_t *head;
  ftun_operation_t *tail;
  ftun_operation_t *ready_head;
  ftun_operation_t *ready_tail;
  ftun_operation_t *storage;
  ftun_operation_t *free_head;
  ftun_operation_waiter_t *waiter_head;
  ftun_operation_waiter_t *waiter_tail;
  size_t capacity;
  size_t inflight;
  ftun_atomic_size_t ready_count;
  size_t control_reserve;
  size_t normal_inflight;
  size_t control_inflight;
  size_t rejected_normal;
  size_t rejected_control;
  uint64_t next_generation;
  int accepting;
  int dispatching;
  int stop_running;
  size_t stop_cursor;
  ftun_mutex_t mutex;
};

static void ftun_operation_recycle(ftun_operation_queue_t *queue,
                                   ftun_operation_t *operation)
{
  memset(operation, 0, sizeof(*operation));
  operation->free_next = queue->free_head;
  queue->free_head = operation;
}

/* owner-loop 异步终结仲裁。 */
static ftun_error_t ftun_cancelled_error(void)
{
  ftun_error_t error;
  memset(&error, 0, sizeof(error));
  error.status = FTUN_E_CANCELLED;
  return error;
}

static void ftun_operation_unlink(ftun_operation_t *operation)
{
  ftun_operation_queue_t *queue = operation->queue;
  if (operation->previous != NULL) operation->previous->next = operation->next;
  else queue->head = operation->next;
  if (operation->next != NULL) operation->next->previous = operation->previous;
  else queue->tail = operation->previous;
  operation->previous = NULL;
  operation->next = NULL;
}

static void ftun_operation_ready_link(ftun_operation_t *operation)
{
  ftun_operation_queue_t *queue = operation->queue;
  operation->ready_previous = queue->ready_tail;
  operation->ready_next = NULL;
  if (queue->ready_tail != NULL) queue->ready_tail->ready_next = operation;
  else queue->ready_head = operation;
  queue->ready_tail = operation;
  (void)ftun_atomic_fetch_add_explicit(&queue->ready_count, 1u,
                                  FTUN_MEMORY_RELEASE);
}

static void ftun_operation_ready_unlink(ftun_operation_t *operation)
{
  ftun_operation_queue_t *queue = operation->queue;
  if (operation->ready_previous != NULL) {
    operation->ready_previous->ready_next = operation->ready_next;
  } else {
    queue->ready_head = operation->ready_next;
  }
  if (operation->ready_next != NULL) {
    operation->ready_next->ready_previous = operation->ready_previous;
  } else {
    queue->ready_tail = operation->ready_previous;
  }
  operation->ready_previous = NULL;
  operation->ready_next = NULL;
  if (ftun_atomic_load_explicit(&queue->ready_count, FTUN_MEMORY_RELAXED) != 0u) {
    (void)ftun_atomic_fetch_sub_explicit(&queue->ready_count, 1u,
                                    FTUN_MEMORY_RELAXED);
  }
}

ftun_status_t ftun_operation_queue_create_reserved(
  ftun_budget_t *budget, size_t capacity, size_t control_reserve,
  ftun_operation_queue_t **out)
{
  ftun_operation_queue_t *queue;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_status_t status;
  size_t index;
  size_t charge;
  if (out != NULL) *out = NULL;
  if (budget == NULL || out == NULL || capacity == 0u ||
      control_reserve >= capacity) return FTUN_E_INVALID;
  if (capacity > (SIZE_MAX - sizeof(*queue)) / sizeof(ftun_operation_t)) {
    return FTUN_E_LIMIT;
  }
  charge = sizeof(*queue) + capacity * sizeof(ftun_operation_t);
  status = ftun_budget_reserve_resources(budget,
    (ftun_budget_resources_t){charge, 0u, capacity}, &reservation);
  if (status != FTUN_OK) return status;
  queue = (ftun_operation_queue_t *)calloc(1u, sizeof(*queue));
  if (queue != NULL) {
    queue->storage = (ftun_operation_t *)calloc(capacity,
                                                sizeof(*queue->storage));
  }
  if (queue == NULL || queue->storage == NULL) {
    if (queue != NULL) free(queue->storage);
    free(queue);
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  queue->budget = budget;
  queue->reservation = reservation;
  queue->capacity = capacity;
  queue->control_reserve = control_reserve;
  ftun_atomic_init(&queue->ready_count, 0u);
  queue->accepting = 1;
  for (index = 0u; index < capacity; index++) {
    queue->storage[index].free_next = queue->free_head;
    queue->free_head = &queue->storage[index];
  }
  if (ftun_mutex_init(&queue->mutex) != FTUN_OK) {
    free(queue->storage);
    queue->storage = NULL;
    free(queue);
    ftun_reservation_release(&reservation);
    return FTUN_E_IO;
  }
  *out = queue;
  return FTUN_OK;
}

ftun_status_t ftun_operation_queue_create(ftun_budget_t *budget, size_t capacity,
                                          ftun_operation_queue_t **out)
{
  return ftun_operation_queue_create_reserved(budget, capacity, 0u, out);
}

static ftun_status_t ftun_operation_accept_kind(
  ftun_operation_queue_t *queue, ftun_completion_fn callback, void *user,
  int control, ftun_operation_t **out, ftun_operation_token_t *completion)
{
  ftun_operation_t *operation;
  if (out != NULL) *out = NULL;
  if (completion != NULL) memset(completion, 0, sizeof(*completion));
  if (queue == NULL || callback == NULL || out == NULL || completion == NULL) {
    return FTUN_E_INVALID;
  }
  ftun_mutex_lock(&queue->mutex);
  if (!queue->accepting) {
    ftun_mutex_unlock(&queue->mutex);
    return FTUN_E_CANCELLED;
  }
  if (queue->inflight >= queue->capacity ||
      (!control && queue->normal_inflight >=
        queue->capacity - queue->control_reserve)) {
    if (control) queue->rejected_control++;
    else queue->rejected_normal++;
    ftun_mutex_unlock(&queue->mutex);
    return FTUN_E_LIMIT;
  }
  operation = queue->free_head;
  if (operation == NULL) {
    ftun_mutex_unlock(&queue->mutex);
    return FTUN_E_STATE_CORRUPT;
  }
  queue->free_head = operation->free_next;
  memset(operation, 0, sizeof(*operation));
  queue->next_generation++;
  if (queue->next_generation == 0u) queue->next_generation++;
  operation->queue = queue;
  operation->slot = (size_t)(operation - queue->storage);
  operation->generation = queue->next_generation;
  operation->callback = callback;
  operation->user = user;
  operation->state = FTUN_OPERATION_ACCEPTED;
  operation->control = control;
  operation->previous = queue->tail;
  if (queue->tail != NULL) queue->tail->next = operation;
  else queue->head = operation;
  queue->tail = operation;
  queue->inflight++;
  if (control) queue->control_inflight++;
  else queue->normal_inflight++;
  *out = operation;
  completion->queue = queue;
  completion->slot = operation->slot;
  completion->generation = operation->generation;
  ftun_mutex_unlock(&queue->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_operation_accept(ftun_operation_queue_t *queue,
                                    ftun_completion_fn callback, void *user,
                                    ftun_operation_t **out,
                                    ftun_operation_token_t *completion)
{
  return ftun_operation_accept_kind(queue, callback, user, 0, out, completion);
}

ftun_status_t ftun_operation_accept_control(
  ftun_operation_queue_t *queue, ftun_completion_fn callback, void *user,
  ftun_operation_t **out, ftun_operation_token_t *completion)
{
  return ftun_operation_accept_kind(queue, callback, user, 1, out, completion);
}

static int ftun_operation_is_cancelling(ftun_operation_state_t state)
{
  return state == FTUN_OPERATION_CANCELLING ||
    state == FTUN_OPERATION_CANCELLING_TERMINAL ||
    state == FTUN_OPERATION_CANCELLING_COMPLETED;
}

static ftun_status_t ftun_operation_complete_kind(
  ftun_operation_token_t completion, ftun_error_t result, int defer)
{
  ftun_operation_queue_t *queue = completion.queue;
  ftun_operation_t *operation;
  if (queue == NULL || completion.generation == 0u) return FTUN_E_INVALID;
  ftun_mutex_lock(&queue->mutex);
  if (completion.slot >= queue->capacity) {
    ftun_mutex_unlock(&queue->mutex);
    return FTUN_E_INVALID;
  }
  operation = &queue->storage[completion.slot];
  if (operation->queue != queue ||
      operation->generation != completion.generation) {
    ftun_mutex_unlock(&queue->mutex);
    return FTUN_E_STALE;
  }
  /* 取消尚未取得终结权；失败后生产者仍须能提交原结果。已终结项在
   * cancel hook 窗口内仍是重复完成，不能把它误判成可重试的提交。 */
  if (operation->state != FTUN_OPERATION_ACCEPTED) {
    if (operation->state == FTUN_OPERATION_CANCELLING && defer) {
      /* void 完成适配器不能把 AGAIN 交还上游；复用已预留的结果槽，
       * 取消返回后再仲裁。此 OK 已接纳结果，后续提交全部按重复处理。 */
      operation->result = result;
      operation->state = FTUN_OPERATION_CANCELLING_COMPLETED;
      ftun_mutex_unlock(&queue->mutex);
      return FTUN_OK;
    }
    ftun_status_t status = operation->state == FTUN_OPERATION_CANCELLING
      ? FTUN_E_AGAIN : FTUN_E_STALE;
    ftun_mutex_unlock(&queue->mutex);
    return status;
  }
  operation->result = result;
  operation->state = FTUN_OPERATION_TERMINAL;
  ftun_operation_ready_link(operation);
  ftun_mutex_unlock(&queue->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_operation_complete(ftun_operation_token_t completion,
                                      ftun_error_t result)
{
  return ftun_operation_complete_kind(completion, result, 0);
}

ftun_status_t ftun_operation_complete_deferred(
  ftun_operation_token_t completion, ftun_error_t result)
{
  return ftun_operation_complete_kind(completion, result, 1);
}

ftun_status_t ftun_operation_set_cancel_hook(
  ftun_operation_t *operation, ftun_operation_cancel_hook_fn hook, void *user)
{
  if (operation == NULL || (hook == NULL && user != NULL)) return FTUN_E_INVALID;
  ftun_mutex_lock(&operation->queue->mutex);
  if (operation->state == FTUN_OPERATION_CALLBACK) {
    ftun_mutex_unlock(&operation->queue->mutex);
    return FTUN_E_STALE;
  }
  if (ftun_operation_is_cancelling(operation->state)) {
    ftun_mutex_unlock(&operation->queue->mutex);
    return FTUN_E_AGAIN;
  }
  operation->cancel_hook = hook;
  operation->cancel_user = user;
  ftun_mutex_unlock(&operation->queue->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_operation_reject(ftun_operation_t **operation)
{
  ftun_operation_t *owned;
  ftun_operation_queue_t *queue;
  if (operation == NULL) return FTUN_E_INVALID;
  owned = *operation;
  if (owned == NULL) return FTUN_OK;
  if (owned->queue == NULL) return FTUN_E_STALE;
  ftun_mutex_lock(&owned->queue->mutex);
  if (owned->state != FTUN_OPERATION_ACCEPTED) {
    ftun_mutex_unlock(&owned->queue->mutex);
    return FTUN_E_STALE;
  }
  queue = owned->queue;
  if (queue->inflight == 0u ||
      (owned->control && queue->control_inflight == 0u) ||
      (!owned->control && queue->normal_inflight == 0u)) {
    ftun_mutex_unlock(&queue->mutex);
    return FTUN_E_STATE_CORRUPT;
  }
  ftun_operation_unlink(owned);
  queue->inflight--;
  if (owned->control) {
    queue->control_inflight--;
  } else {
    queue->normal_inflight--;
  }
  ftun_operation_recycle(queue, owned);
  *operation = NULL;
  ftun_mutex_unlock(&queue->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_operation_cancel(ftun_operation_t *operation)
{
  ftun_operation_cancel_hook_fn hook;
  void *hook_user;
  ftun_operation_state_t previous;
  ftun_status_t status;
  if (operation == NULL) return FTUN_E_INVALID;
  ftun_mutex_lock(&operation->queue->mutex);
  if (operation->state == FTUN_OPERATION_CALLBACK) {
    ftun_mutex_unlock(&operation->queue->mutex);
    return FTUN_E_STALE;
  }
  if (operation->state == FTUN_OPERATION_TERMINAL &&
      operation->result.status == FTUN_E_CANCELLED) {
    ftun_mutex_unlock(&operation->queue->mutex);
    return FTUN_E_STALE;
  }
  if (ftun_operation_is_cancelling(operation->state)) {
    ftun_mutex_unlock(&operation->queue->mutex);
    return FTUN_E_AGAIN;
  }
  hook = operation->cancel_hook;
  hook_user = operation->cancel_user;
  previous = operation->state;
  if (hook != NULL) {
    operation->state = previous == FTUN_OPERATION_TERMINAL
      ? FTUN_OPERATION_CANCELLING_TERMINAL : FTUN_OPERATION_CANCELLING;
    ftun_mutex_unlock(&operation->queue->mutex);
    status = hook(hook_user);
    ftun_mutex_lock(&operation->queue->mutex);
    if (!ftun_operation_is_cancelling(operation->state)) {
      ftun_mutex_unlock(&operation->queue->mutex);
      return FTUN_E_STATE_CORRUPT;
    }
    if (status != FTUN_OK) {
      if (operation->state == FTUN_OPERATION_CANCELLING_COMPLETED) {
        operation->state = FTUN_OPERATION_TERMINAL;
        ftun_operation_ready_link(operation);
      } else {
        operation->state = previous;
      }
      ftun_mutex_unlock(&operation->queue->mutex);
      return status;
    }
  }
  operation->cancel_hook = NULL;
  operation->cancel_user = NULL;
  operation->result = ftun_cancelled_error();
  operation->state = FTUN_OPERATION_TERMINAL;
  if (previous != FTUN_OPERATION_TERMINAL) {
    ftun_operation_ready_link(operation);
  }
  ftun_mutex_unlock(&operation->queue->mutex);
  return FTUN_OK;
}

static void ftun_operation_waiter_unlink(ftun_operation_waiter_t *waiter)
{
  ftun_operation_queue_t *queue = waiter->queue;
  if (waiter->previous != NULL) waiter->previous->next = waiter->next;
  else queue->waiter_head = waiter->next;
  if (waiter->next != NULL) waiter->next->previous = waiter->previous;
  else queue->waiter_tail = waiter->previous;
  waiter->previous = NULL;
  waiter->next = NULL;
  waiter->queue = NULL;
}

/* 回收出额度后按排队顺序通知等待者；通知不持锁，回调里可以重新排队。 */
static void ftun_operation_wake_waiters(ftun_operation_queue_t *queue)
{
  size_t woken;
  for (woken = 0u; woken < FTUN_OPERATION_WAKE_QUOTA; woken++) {
    ftun_operation_waiter_t *waiter;
    ftun_operation_ready_fn ready;
    void *user;
    ftun_mutex_lock(&queue->mutex);
    waiter = queue->waiter_head;
    if (waiter == NULL || !queue->accepting ||
        queue->inflight >= queue->capacity ||
        queue->normal_inflight >= queue->capacity - queue->control_reserve) {
      ftun_mutex_unlock(&queue->mutex);
      return;
    }
    ready = waiter->ready;
    user = waiter->user;
    ftun_operation_waiter_unlink(waiter);
    ftun_mutex_unlock(&queue->mutex);
    ready(user);
  }
}

ftun_status_t ftun_operation_queue_wait(ftun_operation_queue_t *queue,
  ftun_operation_waiter_t *waiter, ftun_operation_ready_fn ready, void *user)
{
  ftun_status_t status = FTUN_OK;
  if (queue == NULL || waiter == NULL || ready == NULL) return FTUN_E_INVALID;
  ftun_mutex_lock(&queue->mutex);
  if (waiter->queue != NULL) {
    if (waiter->queue != queue) status = FTUN_E_INVALID;
  } else if (!queue->accepting) {
    status = FTUN_E_CANCELLED;
  } else if (queue->inflight < queue->capacity &&
             queue->normal_inflight < queue->capacity - queue->control_reserve) {
    status = FTUN_E_AGAIN;
  } else {
    waiter->queue = queue;
    waiter->ready = ready;
    waiter->user = user;
    waiter->next = NULL;
    waiter->previous = queue->waiter_tail;
    if (queue->waiter_tail != NULL) queue->waiter_tail->next = waiter;
    else queue->waiter_head = waiter;
    queue->waiter_tail = waiter;
  }
  ftun_mutex_unlock(&queue->mutex);
  return status;
}

ftun_status_t ftun_operation_queue_wait_cancel(ftun_operation_waiter_t *waiter)
{
  ftun_operation_queue_t *queue;
  if (waiter == NULL) return FTUN_E_INVALID;
  queue = waiter->queue;
  if (queue == NULL) return FTUN_E_STALE;
  ftun_mutex_lock(&queue->mutex);
  ftun_operation_waiter_unlink(waiter);
  ftun_mutex_unlock(&queue->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_operation_dispatch(ftun_operation_queue_t *queue,
                                      size_t max_callbacks, size_t *out_dispatched)
{
  size_t dispatched = 0u;
  if (out_dispatched != NULL) *out_dispatched = 0u;
  if (queue == NULL || max_callbacks == 0u || out_dispatched == NULL) return FTUN_E_INVALID;
  ftun_mutex_lock(&queue->mutex);
  if (queue->dispatching) {
    ftun_mutex_unlock(&queue->mutex);
    return FTUN_E_AGAIN;
  }
  queue->dispatching = 1;
  ftun_mutex_unlock(&queue->mutex);
  while (dispatched < max_callbacks) {
    ftun_operation_t *operation;
    ftun_completion_fn callback;
    void *user;
    ftun_error_t result;
    ftun_mutex_lock(&queue->mutex);
    operation = queue->ready_head;
    if (operation == NULL) {
      ftun_mutex_unlock(&queue->mutex);
      break;
    }
    if (operation->state != FTUN_OPERATION_TERMINAL) {
      ftun_mutex_unlock(&queue->mutex);
      break;
    }
    ftun_operation_ready_unlink(operation);
    ftun_operation_unlink(operation);
    operation->state = FTUN_OPERATION_CALLBACK;
    callback = operation->callback;
    user = operation->user;
    result = operation->result;
    operation->cancel_hook = NULL;
    operation->cancel_user = NULL;
    ftun_mutex_unlock(&queue->mutex);
    callback(operation, result, user);
    ftun_mutex_lock(&queue->mutex);
    if (queue->inflight == 0u) {
      queue->dispatching = 0;
      ftun_mutex_unlock(&queue->mutex);
      return FTUN_E_STATE_CORRUPT;
    }
    queue->inflight--;
    if (operation->control) {
      if (queue->control_inflight == 0u) {
        queue->dispatching = 0;
        ftun_mutex_unlock(&queue->mutex);
        return FTUN_E_STATE_CORRUPT;
      }
      queue->control_inflight--;
    } else {
      if (queue->normal_inflight == 0u) {
        queue->dispatching = 0;
        ftun_mutex_unlock(&queue->mutex);
        return FTUN_E_STATE_CORRUPT;
      }
      queue->normal_inflight--;
    }
    ftun_operation_recycle(queue, operation);
    ftun_mutex_unlock(&queue->mutex);
    dispatched++;
  }
  ftun_mutex_lock(&queue->mutex);
  queue->dispatching = 0;
  ftun_mutex_unlock(&queue->mutex);
  if (dispatched != 0u) ftun_operation_wake_waiters(queue);
  *out_dispatched = dispatched;
  return FTUN_OK;
}

static ftun_status_t ftun_operation_queue_stop_kind(
  ftun_operation_queue_t *queue, size_t max_slots, int restart,
  size_t *out_visited, bool *out_more)
{
  ftun_status_t result = FTUN_OK;
  size_t visited = 0u;
  if (out_visited != NULL) *out_visited = 0u;
  if (out_more != NULL) *out_more = false;
  if (queue == NULL || max_slots == 0u || out_visited == NULL ||
      out_more == NULL) return FTUN_E_INVALID;
  ftun_mutex_lock(&queue->mutex);
  queue->accepting = 0;
  if (queue->stop_running) {
    ftun_mutex_unlock(&queue->mutex);
    return FTUN_E_AGAIN;
  }
  queue->stop_running = 1;
  if (restart) queue->stop_cursor = 0u;
  /* 稳定槽位游标把扫描工作也计入配额。停止后不再接纳新项，允许在
   * 两次 step 之间 dispatch/recycle；下一轮完整扫描会重试失败 hook。 */
  while (visited < max_slots && queue->stop_cursor < queue->capacity &&
         queue->inflight != 0u) {
    ftun_operation_t *operation = &queue->storage[queue->stop_cursor++];
    ftun_status_t status;
    visited++;
    if (operation->queue != queue ||
        operation->state == FTUN_OPERATION_CALLBACK) continue;
    ftun_mutex_unlock(&queue->mutex);
    status = ftun_operation_cancel(operation);
    if (status != FTUN_OK && status != FTUN_E_STALE && result == FTUN_OK) {
      result = status;
    }
    ftun_mutex_lock(&queue->mutex);
  }
  *out_visited = visited;
  *out_more = queue->inflight != 0u && queue->stop_cursor < queue->capacity;
  if (!*out_more) queue->stop_cursor = 0u;
  queue->stop_running = 0;
  ftun_mutex_unlock(&queue->mutex);
  return result;
}

ftun_status_t ftun_operation_queue_stop_step(ftun_operation_queue_t *queue,
  size_t max_slots, size_t *out_visited, bool *out_more)
{
  return ftun_operation_queue_stop_kind(queue, max_slots, 0,
                                         out_visited, out_more);
}

ftun_status_t ftun_operation_queue_stop(ftun_operation_queue_t *queue)
{
  size_t visited;
  bool more;
  return ftun_operation_queue_stop_kind(queue, SIZE_MAX, 1, &visited, &more);
}

ftun_status_t ftun_operation_queue_reopen(ftun_operation_queue_t *queue)
{
  if (queue == NULL) return FTUN_E_INVALID;
  ftun_mutex_lock(&queue->mutex);
  if (queue->inflight != 0u || queue->dispatching || queue->stop_running) {
    ftun_mutex_unlock(&queue->mutex);
    return FTUN_E_AGAIN;
  }
  queue->stop_cursor = 0u;
  queue->accepting = 1;
  ftun_mutex_unlock(&queue->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_operation_queue_get_usage(const ftun_operation_queue_t *queue,
                                              ftun_operation_queue_usage_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (queue == NULL || out == NULL) return FTUN_E_INVALID;
  ftun_mutex_lock((ftun_mutex_t *)&queue->mutex);
  out->capacity = queue->capacity;
  out->inflight = queue->inflight;
  out->ready = ftun_atomic_load_explicit(&queue->ready_count,
                                    FTUN_MEMORY_ACQUIRE);
  out->control_reserve = queue->control_reserve;
  out->normal_inflight = queue->normal_inflight;
  out->control_inflight = queue->control_inflight;
  out->rejected_normal = queue->rejected_normal;
  out->rejected_control = queue->rejected_control;
  out->accepting = queue->accepting != 0;
  out->dispatching = queue->dispatching != 0;
  ftun_mutex_unlock((ftun_mutex_t *)&queue->mutex);
  return FTUN_OK;
}

bool ftun_operation_queue_has_ready(const ftun_operation_queue_t *queue)
{
  return queue != NULL && ftun_atomic_load_explicit(&queue->ready_count,
                                                FTUN_MEMORY_ACQUIRE) != 0u;
}

ftun_status_t ftun_operation_queue_budget(ftun_operation_queue_t *queue,
                                          ftun_budget_t **out)
{
  if (out != NULL) *out = NULL;
  if (queue == NULL || out == NULL) return FTUN_E_INVALID;
  *out = queue->budget;
  return FTUN_OK;
}

ftun_status_t ftun_operation_queue_destroy(ftun_operation_queue_t **queue)
{
  ftun_operation_queue_t *owned;
  ftun_reservation_t reservation;
  if (queue == NULL) return FTUN_E_INVALID;
  owned = *queue;
  if (owned == NULL) return FTUN_OK;
  ftun_mutex_lock(&owned->mutex);
  if (owned->dispatching || owned->inflight != 0u || owned->head != NULL ||
      owned->tail != NULL || owned->ready_head != NULL ||
      owned->ready_tail != NULL || owned->waiter_head != NULL ||
      ftun_atomic_load_explicit(&owned->ready_count, FTUN_MEMORY_RELAXED) != 0u) {
    ftun_mutex_unlock(&owned->mutex);
    return FTUN_E_AGAIN;
  }
  reservation = owned->reservation;
  ftun_reservation_release(&reservation);
  owned->reservation = (ftun_reservation_t){0};
  ftun_mutex_unlock(&owned->mutex);
  ftun_mutex_destroy(&owned->mutex);
  free(owned->storage);
  free(owned);
  *queue = NULL;
  return FTUN_OK;
}
