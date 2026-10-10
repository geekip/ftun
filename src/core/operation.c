#include "operation.h"
#include <stdlib.h>
#include <string.h>

typedef enum {
  FTUN_OPERATION_ACCEPTED = 1,
  FTUN_OPERATION_TERMINAL,
  FTUN_OPERATION_CALLBACK
} ftun_operation_state_t;

struct ftun_operation {
  ftun_operation_queue_t *queue;
  ftun_operation_t *previous;
  ftun_operation_t *next;
  ftun_completion_fn callback;
  void *user;
  ftun_operation_cancel_hook_fn cancel_hook;
  void *cancel_user;
  ftun_reservation_t *reservation;
  ftun_error_t result;
  ftun_operation_state_t state;
};

struct ftun_operation_queue {
  ftun_budget_t *budget;
  ftun_reservation_t *reservation;
  ftun_operation_t *head;
  ftun_operation_t *tail;
  size_t capacity;
  size_t inflight;
  int accepting;
  int dispatching;
};

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

ftun_status_t ftun_operation_queue_create(ftun_budget_t *budget, size_t capacity,
                                          ftun_operation_queue_t **out)
{
  ftun_operation_queue_t *queue;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (budget == NULL || out == NULL || capacity == 0u) return FTUN_E_INVALID;
  status = ftun_budget_reserve(budget, sizeof(*queue), &reservation);
  if (status != FTUN_OK) return status;
  queue = (ftun_operation_queue_t *)calloc(1u, sizeof(*queue));
  if (queue == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  queue->budget = budget;
  queue->reservation = reservation;
  queue->capacity = capacity;
  queue->accepting = 1;
  *out = queue;
  return FTUN_OK;
}

ftun_status_t ftun_operation_accept(ftun_operation_queue_t *queue,
                                    ftun_completion_fn callback, void *user,
                                    ftun_operation_t **out)
{
  ftun_operation_t *operation;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (queue == NULL || callback == NULL || out == NULL) return FTUN_E_INVALID;
  if (!queue->accepting) return FTUN_E_CANCELLED;
  if (queue->inflight >= queue->capacity) return FTUN_E_LIMIT;
  status = ftun_budget_reserve(queue->budget, sizeof(*operation), &reservation);
  if (status != FTUN_OK) return status;
  operation = (ftun_operation_t *)calloc(1u, sizeof(*operation));
  if (operation == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  operation->queue = queue;
  operation->callback = callback;
  operation->user = user;
  operation->reservation = reservation;
  operation->state = FTUN_OPERATION_ACCEPTED;
  operation->previous = queue->tail;
  if (queue->tail != NULL) queue->tail->next = operation;
  else queue->head = operation;
  queue->tail = operation;
  queue->inflight++;
  *out = operation;
  return FTUN_OK;
}

ftun_status_t ftun_operation_complete(ftun_operation_t *operation, ftun_error_t result)
{
  if (operation == NULL) return FTUN_E_INVALID;
  if (operation->state != FTUN_OPERATION_ACCEPTED) return FTUN_E_STALE;
  operation->result = result;
  operation->state = FTUN_OPERATION_TERMINAL;
  return FTUN_OK;
}

ftun_status_t ftun_operation_set_cancel_hook(
  ftun_operation_t *operation, ftun_operation_cancel_hook_fn hook, void *user)
{
  if (operation == NULL || (hook == NULL && user != NULL)) return FTUN_E_INVALID;
  if (operation->state == FTUN_OPERATION_CALLBACK) return FTUN_E_STALE;
  operation->cancel_hook = hook;
  operation->cancel_user = user;
  return FTUN_OK;
}

ftun_status_t ftun_operation_reject(ftun_operation_t **operation)
{
  ftun_operation_t *owned;
  ftun_operation_queue_t *queue;
  ftun_reservation_t *reservation;
  ftun_status_t status;
  if (operation == NULL) return FTUN_E_INVALID;
  owned = *operation;
  if (owned == NULL) return FTUN_OK;
  if (owned->state != FTUN_OPERATION_ACCEPTED || owned->queue == NULL) {
    return FTUN_E_STALE;
  }
  queue = owned->queue;
  if (queue->inflight == 0u) return FTUN_E_STATE_CORRUPT;
  reservation = owned->reservation;
  status = ftun_reservation_release(&reservation);
  if (status != FTUN_OK) return status;
  owned->reservation = NULL;
  ftun_operation_unlink(owned);
  queue->inflight--;
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *operation = NULL;
  return FTUN_OK;
}

ftun_status_t ftun_operation_cancel(ftun_operation_t *operation)
{
  ftun_status_t status;
  if (operation == NULL) return FTUN_E_INVALID;
  if (operation->state == FTUN_OPERATION_CALLBACK) return FTUN_E_STALE;
  if (operation->state == FTUN_OPERATION_TERMINAL &&
      operation->result.status == FTUN_E_CANCELLED) return FTUN_E_STALE;
  if (operation->cancel_hook != NULL) {
    status = operation->cancel_hook(operation->cancel_user);
    if (status != FTUN_OK) return status;
    operation->cancel_hook = NULL;
    operation->cancel_user = NULL;
  }
  operation->result = ftun_cancelled_error();
  operation->state = FTUN_OPERATION_TERMINAL;
  return FTUN_OK;
}

ftun_status_t ftun_operation_dispatch(ftun_operation_queue_t *queue,
                                      size_t max_callbacks, size_t *out_dispatched)
{
  size_t dispatched = 0u;
  if (out_dispatched != NULL) *out_dispatched = 0u;
  if (queue == NULL || max_callbacks == 0u || out_dispatched == NULL) return FTUN_E_INVALID;
  if (queue->dispatching) return FTUN_E_AGAIN;
  queue->dispatching = 1;
  while (dispatched < max_callbacks) {
    ftun_operation_t *operation = queue->head;
    ftun_completion_fn callback;
    void *user;
    ftun_error_t result;
    ftun_reservation_t *reservation;
    while (operation != NULL && operation->state != FTUN_OPERATION_TERMINAL) {
      operation = operation->next;
    }
    if (operation == NULL) break;
    ftun_operation_unlink(operation);
    operation->state = FTUN_OPERATION_CALLBACK;
    callback = operation->callback;
    user = operation->user;
    result = operation->result;
    operation->cancel_hook = NULL;
    operation->cancel_user = NULL;
    callback(operation, result, user);
    reservation = operation->reservation;
    operation->queue = NULL;
    operation->callback = NULL;
    operation->user = NULL;
    operation->reservation = NULL;
    free(operation);
    if (queue->inflight == 0u || ftun_reservation_release(&reservation) != FTUN_OK) {
      queue->dispatching = 0;
      return FTUN_E_STATE_CORRUPT;
    }
    queue->inflight--;
    dispatched++;
  }
  queue->dispatching = 0;
  *out_dispatched = dispatched;
  return FTUN_OK;
}

ftun_status_t ftun_operation_queue_stop(ftun_operation_queue_t *queue)
{
  ftun_operation_t *operation;
  ftun_status_t result = FTUN_OK;
  if (queue == NULL) return FTUN_E_INVALID;
  queue->accepting = 0;
  for (operation = queue->head; operation != NULL; operation = operation->next) {
    if (operation->cancel_hook != NULL) {
      ftun_status_t status = operation->cancel_hook(operation->cancel_user);
      if (status != FTUN_OK) {
        if (result == FTUN_OK) result = status;
        continue;
      }
      operation->cancel_hook = NULL;
      operation->cancel_user = NULL;
    }
    operation->result = ftun_cancelled_error();
    operation->state = FTUN_OPERATION_TERMINAL;
  }
  return result;
}

ftun_status_t ftun_operation_queue_get_usage(const ftun_operation_queue_t *queue,
                                              ftun_operation_queue_usage_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (queue == NULL || out == NULL) return FTUN_E_INVALID;
  out->capacity = queue->capacity;
  out->inflight = queue->inflight;
  out->accepting = queue->accepting != 0;
  out->dispatching = queue->dispatching != 0;
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
  if (owned->dispatching || owned->inflight != 0u || owned->head != NULL ||
      owned->tail != NULL) return FTUN_E_AGAIN;
  reservation = owned->reservation;
  status = ftun_reservation_release(&reservation);
  if (status != FTUN_OK) return status;
  owned->reservation = NULL;
  free(owned);
  *queue = NULL;
  return FTUN_OK;
}
