#include "operation.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
  FTUN_OPERATION_ACCEPTED = 1,
  FTUN_OPERATION_TERMINAL,
  FTUN_OPERATION_CANCELLING,
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
  int stop_visited;
  int control;
};

struct ftun_operation_queue {
  ftun_budget_t *budget;
  ftun_reservation_t *reservation;
  ftun_operation_t *head;
  ftun_operation_t *tail;
  ftun_operation_t *ready_head;
  ftun_operation_t *ready_tail;
  ftun_operation_t *storage;
  ftun_operation_t *free_head;
  size_t capacity;
  size_t inflight;
  _Atomic size_t ready_count;
  size_t control_reserve;
  size_t normal_inflight;
  size_t control_inflight;
  size_t rejected_normal;
  size_t rejected_control;
  uint64_t next_generation;
  int accepting;
  int dispatching;
  pthread_mutex_t mutex;
};

static void ftun_operation_recycle(ftun_operation_queue_t *queue,
                                   ftun_operation_t *operation)
{
  memset(operation, 0, sizeof(*operation));
  operation->free_next = queue->free_head;
  queue->free_head = operation;
}

/* TASK-CORE-005 / TEST-CORE-005，目标 0.2.0：owner-loop 异步终结仲裁。 */
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
  (void)atomic_fetch_add_explicit(&queue->ready_count, 1u,
                                  memory_order_release);
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
  if (atomic_load_explicit(&queue->ready_count, memory_order_relaxed) != 0u) {
    (void)atomic_fetch_sub_explicit(&queue->ready_count, 1u,
                                    memory_order_relaxed);
  }
}

ftun_status_t ftun_operation_queue_create_reserved(
  ftun_budget_t *budget, size_t capacity, size_t control_reserve,
  ftun_operation_queue_t **out)
{
  ftun_operation_queue_t *queue;
  ftun_reservation_t *reservation = NULL;
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
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  queue->budget = budget;
  queue->reservation = reservation;
  queue->capacity = capacity;
  queue->control_reserve = control_reserve;
  atomic_init(&queue->ready_count, 0u);
  queue->accepting = 1;
  for (index = 0u; index < capacity; index++) {
    queue->storage[index].free_next = queue->free_head;
    queue->free_head = &queue->storage[index];
  }
  if (pthread_mutex_init(&queue->mutex, NULL) != 0) {
    free(queue->storage);
    queue->storage = NULL;
    free(queue);
    (void)ftun_reservation_release(&reservation);
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
  (void)pthread_mutex_lock(&queue->mutex);
  if (!queue->accepting) {
    (void)pthread_mutex_unlock(&queue->mutex);
    return FTUN_E_CANCELLED;
  }
  if (queue->inflight >= queue->capacity ||
      (!control && queue->normal_inflight >=
        queue->capacity - queue->control_reserve)) {
    if (control) queue->rejected_control++;
    else queue->rejected_normal++;
    (void)pthread_mutex_unlock(&queue->mutex);
    return FTUN_E_LIMIT;
  }
  operation = queue->free_head;
  if (operation == NULL) {
    (void)pthread_mutex_unlock(&queue->mutex);
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
  (void)pthread_mutex_unlock(&queue->mutex);
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

ftun_status_t ftun_operation_complete(ftun_operation_token_t completion,
                                      ftun_error_t result)
{
  ftun_operation_queue_t *queue = completion.queue;
  ftun_operation_t *operation;
  if (queue == NULL || completion.generation == 0u) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&queue->mutex);
  if (completion.slot >= queue->capacity) {
    (void)pthread_mutex_unlock(&queue->mutex);
    return FTUN_E_INVALID;
  }
  operation = &queue->storage[completion.slot];
  if (operation->queue != queue ||
      operation->generation != completion.generation ||
      operation->state != FTUN_OPERATION_ACCEPTED) {
    (void)pthread_mutex_unlock(&queue->mutex);
    return FTUN_E_STALE;
  }
  operation->result = result;
  operation->state = FTUN_OPERATION_TERMINAL;
  ftun_operation_ready_link(operation);
  (void)pthread_mutex_unlock(&queue->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_operation_set_cancel_hook(
  ftun_operation_t *operation, ftun_operation_cancel_hook_fn hook, void *user)
{
  if (operation == NULL || (hook == NULL && user != NULL)) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&operation->queue->mutex);
  if (operation->state == FTUN_OPERATION_CALLBACK) {
    (void)pthread_mutex_unlock(&operation->queue->mutex);
    return FTUN_E_STALE;
  }
  if (operation->state == FTUN_OPERATION_CANCELLING) {
    (void)pthread_mutex_unlock(&operation->queue->mutex);
    return FTUN_E_AGAIN;
  }
  operation->cancel_hook = hook;
  operation->cancel_user = user;
  (void)pthread_mutex_unlock(&operation->queue->mutex);
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
  (void)pthread_mutex_lock(&owned->queue->mutex);
  if (owned->state != FTUN_OPERATION_ACCEPTED) {
    (void)pthread_mutex_unlock(&owned->queue->mutex);
    return FTUN_E_STALE;
  }
  queue = owned->queue;
  if (queue->inflight == 0u ||
      (owned->control && queue->control_inflight == 0u) ||
      (!owned->control && queue->normal_inflight == 0u)) {
    (void)pthread_mutex_unlock(&queue->mutex);
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
  (void)pthread_mutex_unlock(&queue->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_operation_cancel(ftun_operation_t *operation)
{
  ftun_operation_cancel_hook_fn hook;
  void *hook_user;
  ftun_operation_state_t previous;
  ftun_status_t status;
  if (operation == NULL) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&operation->queue->mutex);
  if (operation->state == FTUN_OPERATION_CALLBACK) {
    (void)pthread_mutex_unlock(&operation->queue->mutex);
    return FTUN_E_STALE;
  }
  if (operation->state == FTUN_OPERATION_TERMINAL &&
      operation->result.status == FTUN_E_CANCELLED) {
    (void)pthread_mutex_unlock(&operation->queue->mutex);
    return FTUN_E_STALE;
  }
  if (operation->state == FTUN_OPERATION_CANCELLING) {
    (void)pthread_mutex_unlock(&operation->queue->mutex);
    return FTUN_E_AGAIN;
  }
  hook = operation->cancel_hook;
  hook_user = operation->cancel_user;
  previous = operation->state;
  if (hook != NULL) {
    operation->state = FTUN_OPERATION_CANCELLING;
    (void)pthread_mutex_unlock(&operation->queue->mutex);
    status = hook(hook_user);
    (void)pthread_mutex_lock(&operation->queue->mutex);
    if (operation->state != FTUN_OPERATION_CANCELLING) {
      (void)pthread_mutex_unlock(&operation->queue->mutex);
      return FTUN_E_STATE_CORRUPT;
    }
    if (status != FTUN_OK) {
      operation->state = previous;
      (void)pthread_mutex_unlock(&operation->queue->mutex);
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
  (void)pthread_mutex_unlock(&operation->queue->mutex);
  return FTUN_OK;
}

ftun_status_t ftun_operation_dispatch(ftun_operation_queue_t *queue,
                                      size_t max_callbacks, size_t *out_dispatched)
{
  size_t dispatched = 0u;
  if (out_dispatched != NULL) *out_dispatched = 0u;
  if (queue == NULL || max_callbacks == 0u || out_dispatched == NULL) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&queue->mutex);
  if (queue->dispatching) {
    (void)pthread_mutex_unlock(&queue->mutex);
    return FTUN_E_AGAIN;
  }
  queue->dispatching = 1;
  (void)pthread_mutex_unlock(&queue->mutex);
  while (dispatched < max_callbacks) {
    ftun_operation_t *operation;
    ftun_completion_fn callback;
    void *user;
    ftun_error_t result;
    (void)pthread_mutex_lock(&queue->mutex);
    operation = queue->ready_head;
    if (operation == NULL) {
      (void)pthread_mutex_unlock(&queue->mutex);
      break;
    }
    if (operation->state != FTUN_OPERATION_TERMINAL) {
      (void)pthread_mutex_unlock(&queue->mutex);
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
    (void)pthread_mutex_unlock(&queue->mutex);
    callback(operation, result, user);
    (void)pthread_mutex_lock(&queue->mutex);
    if (queue->inflight == 0u) {
      queue->dispatching = 0;
      (void)pthread_mutex_unlock(&queue->mutex);
      return FTUN_E_STATE_CORRUPT;
    }
    queue->inflight--;
    if (operation->control) {
      if (queue->control_inflight == 0u) {
        queue->dispatching = 0;
        (void)pthread_mutex_unlock(&queue->mutex);
        return FTUN_E_STATE_CORRUPT;
      }
      queue->control_inflight--;
    } else {
      if (queue->normal_inflight == 0u) {
        queue->dispatching = 0;
        (void)pthread_mutex_unlock(&queue->mutex);
        return FTUN_E_STATE_CORRUPT;
      }
      queue->normal_inflight--;
    }
    ftun_operation_recycle(queue, operation);
    (void)pthread_mutex_unlock(&queue->mutex);
    dispatched++;
  }
  (void)pthread_mutex_lock(&queue->mutex);
  queue->dispatching = 0;
  (void)pthread_mutex_unlock(&queue->mutex);
  *out_dispatched = dispatched;
  return FTUN_OK;
}

ftun_status_t ftun_operation_queue_stop(ftun_operation_queue_t *queue)
{
  ftun_operation_t *operation;
  ftun_status_t result = FTUN_OK;
  if (queue == NULL) return FTUN_E_INVALID;
  (void)pthread_mutex_lock(&queue->mutex);
  queue->accepting = 0;
  /* Each stop attempt must revisit hooks that asked to be retried. */
  for (operation = queue->head; operation != NULL; operation = operation->next) {
    operation->stop_visited = 0;
  }
  for (;;) {
    ftun_status_t status;
    for (operation = queue->head; operation != NULL;
         operation = operation->next) {
      if (!operation->stop_visited) break;
    }
    if (operation == NULL) break;
    operation->stop_visited = 1;
    (void)pthread_mutex_unlock(&queue->mutex);
    status = ftun_operation_cancel(operation);
    if (status != FTUN_OK && status != FTUN_E_STALE && result == FTUN_OK) {
      result = status;
    }
    (void)pthread_mutex_lock(&queue->mutex);
  }
  (void)pthread_mutex_unlock(&queue->mutex);
  return result;
}

ftun_status_t ftun_operation_queue_get_usage(const ftun_operation_queue_t *queue,
                                              ftun_operation_queue_usage_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (queue == NULL || out == NULL) return FTUN_E_INVALID;
  (void)pthread_mutex_lock((pthread_mutex_t *)&queue->mutex);
  out->capacity = queue->capacity;
  out->inflight = queue->inflight;
  out->ready = atomic_load_explicit(&queue->ready_count,
                                    memory_order_acquire);
  out->control_reserve = queue->control_reserve;
  out->normal_inflight = queue->normal_inflight;
  out->control_inflight = queue->control_inflight;
  out->rejected_normal = queue->rejected_normal;
  out->rejected_control = queue->rejected_control;
  out->accepting = queue->accepting != 0;
  out->dispatching = queue->dispatching != 0;
  (void)pthread_mutex_unlock((pthread_mutex_t *)&queue->mutex);
  return FTUN_OK;
}

bool ftun_operation_queue_has_ready(const ftun_operation_queue_t *queue)
{
  return queue != NULL && atomic_load_explicit(&queue->ready_count,
                                                memory_order_acquire) != 0u;
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
  ftun_reservation_t *reservation;
  ftun_status_t status;
  if (queue == NULL) return FTUN_E_INVALID;
  owned = *queue;
  if (owned == NULL) return FTUN_OK;
  (void)pthread_mutex_lock(&owned->mutex);
  if (owned->dispatching || owned->inflight != 0u || owned->head != NULL ||
      owned->tail != NULL || owned->ready_head != NULL ||
      owned->ready_tail != NULL ||
      atomic_load_explicit(&owned->ready_count, memory_order_relaxed) != 0u) {
    (void)pthread_mutex_unlock(&owned->mutex);
    return FTUN_E_AGAIN;
  }
  reservation = owned->reservation;
  status = ftun_reservation_release(&reservation);
  if (status != FTUN_OK) {
    (void)pthread_mutex_unlock(&owned->mutex);
    return status;
  }
  owned->reservation = NULL;
  (void)pthread_mutex_unlock(&owned->mutex);
  (void)pthread_mutex_destroy(&owned->mutex);
  free(owned->storage);
  free(owned);
  *queue = NULL;
  return FTUN_OK;
}
