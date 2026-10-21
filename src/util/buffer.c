#include "buffer.h"
#include <stdlib.h>
#include <string.h>

#define FTUN_BUFFER_MIN_CLASS 256u

struct ftun_buffer {
  ftun_buffer_pool_t *pool;
  ftun_budget_t *budget;
  ftun_buffer_t *next;
  ftun_reservation_t *reservation;
  size_t capacity;
  size_t references;
  uint8_t data[];
};

typedef struct {
  size_t previous;
  size_t next;
  size_t capacity;
  ftun_buffer_ready_fn ready;
  void *user;
  uint64_t generation;
  int pending;
} ftun_buffer_waiter_t;

struct ftun_buffer_pool {
  ftun_budget_t *budget;
  ftun_reservation_t *reservation;
  ftun_buffer_t *idle;
  size_t idle_limit_bytes;
  size_t idle_limit_buffers;
  size_t idle_bytes;
  size_t idle_buffers;
  size_t active_buffers;
  size_t cache_hits;
  size_t cache_misses;
  size_t pressure_trims;
  size_t pressure_trimmed_bytes;
  size_t pressure_trimmed_buffers;
  ftun_buffer_waiter_t *waiters;
  size_t waiter_capacity;
  size_t free_waiter;
  size_t wait_head;
  size_t wait_tail;
  size_t waiting;
  size_t wake_quota;
  size_t notifications;
  size_t wake_callbacks;
  size_t cancelled_waiters;
  size_t rejected_waiters;
  uint64_t next_waiter_generation;
  ftun_buffer_pool_wakeup_fn wakeup;
  void *wakeup_user;
  int notification_pending;
  int notification_sent;
  int dispatching;
};

#define FTUN_BUFFER_WAITER_NONE SIZE_MAX

/* TASK-UTIL-002 / TEST-UTIL-002，目标 0.2.0：分档、有界闲置与所有者引用。 */
static ftun_status_t ftun_buffer_class(size_t requested, size_t *out)
{
  size_t capacity = FTUN_BUFFER_MIN_CLASS;
  if (out != NULL) *out = 0u;
  if (requested == 0u || out == NULL) return FTUN_E_INVALID;
  while (capacity < requested) {
    if (capacity > SIZE_MAX / 2u) return FTUN_E_LIMIT;
    capacity *= 2u;
  }
  if (capacity > SIZE_MAX - sizeof(ftun_buffer_t)) return FTUN_E_LIMIT;
  *out = capacity;
  return FTUN_OK;
}

static ftun_status_t ftun_buffer_allocate(ftun_budget_t *budget,
                                          ftun_buffer_pool_t *pool,
                                          size_t capacity, ftun_buffer_t **out)
{
  ftun_buffer_t *buffer;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  size_t charge = sizeof(*buffer) + capacity;

  status = ftun_budget_reserve(budget, charge, &reservation);
  if (status != FTUN_OK) return status;
  buffer = (ftun_buffer_t *)malloc(charge);
  if (buffer == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  memset(buffer, 0, sizeof(*buffer));
  buffer->pool = pool;
  buffer->budget = budget;
  buffer->reservation = reservation;
  buffer->capacity = capacity;
  buffer->references = 1u;
  *out = buffer;
  return FTUN_OK;
}

static ftun_status_t ftun_buffer_free(ftun_buffer_t *buffer)
{
  ftun_reservation_t *reservation = buffer->reservation;
  ftun_status_t status;
  buffer->reservation = NULL;
  status = ftun_reservation_release(&reservation);
  if (status != FTUN_OK) {
    buffer->reservation = reservation;
    return status;
  }
  free(buffer);
  return FTUN_OK;
}

static int ftun_buffer_pool_idle_class(const ftun_buffer_pool_t *pool,
                                       size_t capacity)
{
  const ftun_buffer_t *buffer;
  for (buffer = pool->idle; buffer != NULL; buffer = buffer->next) {
    if (buffer->capacity == capacity) return 1;
  }
  return 0;
}

static int ftun_buffer_pool_can_acquire(ftun_buffer_pool_t *pool,
                                        size_t capacity)
{
  ftun_budget_usage_t usage;
  size_t charge;
  if (ftun_buffer_pool_idle_class(pool, capacity)) return 1;
  if (capacity > SIZE_MAX - sizeof(ftun_buffer_t)) return 0;
  charge = sizeof(ftun_buffer_t) + capacity;
  return ftun_budget_get_usage(pool->budget, &usage) == FTUN_OK &&
    charge <= usage.normal_available_resources.memory_bytes;
}

static size_t ftun_buffer_pool_ready_waiter(ftun_buffer_pool_t *pool)
{
  ftun_budget_usage_t usage;
  size_t available = 0u;
  size_t slot;
  if (ftun_budget_get_usage(pool->budget, &usage) == FTUN_OK) {
    available = usage.normal_available_resources.memory_bytes;
  }
  for (slot = pool->wait_head; slot != FTUN_BUFFER_WAITER_NONE;
       slot = pool->waiters[slot].next) {
    size_t capacity = pool->waiters[slot].capacity;
    if (pool->waiters[slot].pending &&
        (ftun_buffer_pool_idle_class(pool, capacity) ||
         (capacity <= SIZE_MAX - sizeof(ftun_buffer_t) &&
          sizeof(ftun_buffer_t) + capacity <= available))) {
      return slot;
    }
  }
  return FTUN_BUFFER_WAITER_NONE;
}

static void ftun_buffer_pool_notify(ftun_buffer_pool_t *pool)
{
  ftun_buffer_pool_wakeup_fn wakeup;
  void *user;
  if (pool->waiting == 0u) {
    pool->notification_pending = 0;
    pool->notification_sent = 0;
    return;
  }
  if (pool->notification_pending && pool->notification_sent) return;
  if (pool->wait_head == FTUN_BUFFER_WAITER_NONE ||
      ftun_buffer_pool_ready_waiter(pool) == FTUN_BUFFER_WAITER_NONE) return;
  if (!pool->notification_pending) {
    pool->notification_pending = 1;
    pool->notification_sent = 0;
  }
  if (pool->notification_sent || pool->wakeup == NULL) return;
  pool->notification_sent = 1;
  if (pool->notifications != SIZE_MAX) pool->notifications++;
  wakeup = pool->wakeup;
  user = pool->wakeup_user;
  wakeup(user);
}

static void ftun_buffer_waiter_unlink(ftun_buffer_pool_t *pool, size_t slot)
{
  ftun_buffer_waiter_t *waiter = &pool->waiters[slot];
  if (waiter->previous != FTUN_BUFFER_WAITER_NONE) {
    pool->waiters[waiter->previous].next = waiter->next;
  } else {
    pool->wait_head = waiter->next;
  }
  if (waiter->next != FTUN_BUFFER_WAITER_NONE) {
    pool->waiters[waiter->next].previous = waiter->previous;
  } else {
    pool->wait_tail = waiter->previous;
  }
  waiter->previous = FTUN_BUFFER_WAITER_NONE;
  waiter->next = FTUN_BUFFER_WAITER_NONE;
}

static void ftun_buffer_waiter_recycle(ftun_buffer_pool_t *pool, size_t slot)
{
  ftun_buffer_waiter_t *waiter = &pool->waiters[slot];
  uint64_t generation = waiter->generation;
  memset(waiter, 0, sizeof(*waiter));
  waiter->generation = generation;
  waiter->previous = FTUN_BUFFER_WAITER_NONE;
  waiter->next = pool->free_waiter;
  pool->free_waiter = slot;
}

ftun_status_t ftun_buffer_acquire(ftun_budget_t *budget, size_t capacity,
                                  ftun_buffer_t **out)
{
  size_t buffer_class;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (budget == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_buffer_class(capacity, &buffer_class);
  if (status != FTUN_OK) return status;
  return ftun_buffer_allocate(budget, NULL, buffer_class, out);
}

ftun_status_t ftun_buffer_pool_create_waitable(
  ftun_budget_t *budget, size_t idle_limit_bytes, size_t idle_limit_buffers,
  size_t waiter_capacity, size_t wake_quota, ftun_buffer_pool_t **out)
{
  ftun_buffer_pool_t *pool;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  size_t charge = sizeof(*pool);
  size_t index;
  if (out != NULL) *out = NULL;
  if (budget == NULL || out == NULL ||
      (waiter_capacity == 0u && wake_quota != 0u) ||
      (waiter_capacity != 0u &&
       (wake_quota == 0u || wake_quota > waiter_capacity))) {
    return FTUN_E_INVALID;
  }
  if (waiter_capacity > (SIZE_MAX - charge) / sizeof(ftun_buffer_waiter_t)) {
    return FTUN_E_LIMIT;
  }
  charge += waiter_capacity * sizeof(ftun_buffer_waiter_t);
  status = ftun_budget_reserve(budget, charge, &reservation);
  if (status != FTUN_OK) return status;
  pool = (ftun_buffer_pool_t *)calloc(1u, sizeof(*pool));
  if (pool != NULL && waiter_capacity != 0u) {
    pool->waiters = (ftun_buffer_waiter_t *)calloc(
      waiter_capacity, sizeof(*pool->waiters));
  }
  if (pool == NULL || (waiter_capacity != 0u && pool->waiters == NULL)) {
    if (pool != NULL) free(pool->waiters);
    free(pool);
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  pool->budget = budget;
  pool->reservation = reservation;
  pool->idle_limit_bytes = idle_limit_bytes;
  pool->idle_limit_buffers = idle_limit_buffers;
  pool->waiter_capacity = waiter_capacity;
  pool->wake_quota = wake_quota;
  pool->free_waiter = waiter_capacity == 0u
    ? FTUN_BUFFER_WAITER_NONE : 0u;
  pool->wait_head = FTUN_BUFFER_WAITER_NONE;
  pool->wait_tail = FTUN_BUFFER_WAITER_NONE;
  for (index = 0u; index < waiter_capacity; index++) {
    pool->waiters[index].previous = FTUN_BUFFER_WAITER_NONE;
    pool->waiters[index].next = index + 1u < waiter_capacity
      ? index + 1u : FTUN_BUFFER_WAITER_NONE;
  }
  *out = pool;
  return FTUN_OK;
}

ftun_status_t ftun_buffer_pool_create(ftun_budget_t *budget,
                                      size_t idle_limit_bytes,
                                      size_t idle_limit_buffers,
                                      ftun_buffer_pool_t **out)
{
  return ftun_buffer_pool_create_waitable(budget, idle_limit_bytes,
                                           idle_limit_buffers, 0u, 0u, out);
}

ftun_status_t ftun_buffer_pool_set_wakeup(
  ftun_buffer_pool_t *pool, ftun_buffer_pool_wakeup_fn wakeup, void *user)
{
  if (pool == NULL || (wakeup == NULL && user != NULL)) return FTUN_E_INVALID;
  if (pool->dispatching) return FTUN_E_AGAIN;
  pool->wakeup = wakeup;
  pool->wakeup_user = user;
  ftun_buffer_pool_notify(pool);
  return FTUN_OK;
}

ftun_status_t ftun_buffer_pool_acquire(ftun_buffer_pool_t *pool, size_t capacity,
                                       ftun_buffer_t **out)
{
  ftun_buffer_t *buffer;
  ftun_buffer_t *previous = NULL;
  size_t buffer_class;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (pool == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_buffer_class(capacity, &buffer_class);
  if (status != FTUN_OK) return status;
  for (buffer = pool->idle; buffer != NULL; buffer = buffer->next) {
    if (buffer->capacity == buffer_class) break;
    previous = buffer;
  }
  if (buffer != NULL) {
    if (pool->idle_buffers == 0u || pool->idle_bytes < buffer->capacity) {
      return FTUN_E_STATE_CORRUPT;
    }
    if (previous != NULL) previous->next = buffer->next;
    else pool->idle = buffer->next;
    pool->idle_buffers--;
    pool->idle_bytes -= buffer->capacity;
    buffer->next = NULL;
    buffer->references = 1u;
    pool->active_buffers++;
    pool->cache_hits++;
    *out = buffer;
    return FTUN_OK;
  }
  pool->cache_misses++;
  status = ftun_buffer_allocate(pool->budget, pool, buffer_class, out);
  if (status == FTUN_E_LIMIT && pool->idle != NULL) {
    size_t idle_bytes = pool->idle_bytes;
    size_t idle_buffers = pool->idle_buffers;
    status = ftun_buffer_pool_trim(pool, 0u);
    if (status != FTUN_OK) return status;
    pool->pressure_trims++;
    pool->pressure_trimmed_bytes += idle_bytes - pool->idle_bytes;
    pool->pressure_trimmed_buffers += idle_buffers - pool->idle_buffers;
    status = ftun_buffer_allocate(pool->budget, pool, buffer_class, out);
  }
  if (status != FTUN_OK) return status;
  if (pool->active_buffers == SIZE_MAX) {
    buffer = *out;
    *out = NULL;
    (void)ftun_buffer_free(buffer);
    return FTUN_E_LIMIT;
  }
  pool->active_buffers++;
  return FTUN_OK;
}

ftun_status_t ftun_buffer_pool_wait(
  ftun_buffer_pool_t *pool, size_t capacity, ftun_buffer_ready_fn ready,
  void *user, ftun_buffer_wait_token_t *out)
{
  ftun_buffer_waiter_t *waiter;
  size_t buffer_class;
  size_t slot;
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (pool == NULL || ready == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_buffer_class(capacity, &buffer_class);
  if (status != FTUN_OK) return status;
  if (ftun_buffer_pool_can_acquire(pool, buffer_class)) return FTUN_E_AGAIN;
  if (pool->free_waiter == FTUN_BUFFER_WAITER_NONE) {
    if (pool->rejected_waiters != SIZE_MAX) pool->rejected_waiters++;
    return FTUN_E_LIMIT;
  }
  slot = pool->free_waiter;
  waiter = &pool->waiters[slot];
  pool->free_waiter = waiter->next;
  pool->next_waiter_generation++;
  if (pool->next_waiter_generation == 0u) pool->next_waiter_generation++;
  memset(waiter, 0, sizeof(*waiter));
  waiter->previous = pool->wait_tail;
  waiter->next = FTUN_BUFFER_WAITER_NONE;
  waiter->capacity = buffer_class;
  waiter->ready = ready;
  waiter->user = user;
  waiter->generation = pool->next_waiter_generation;
  waiter->pending = 1;
  if (pool->wait_tail != FTUN_BUFFER_WAITER_NONE) {
    pool->waiters[pool->wait_tail].next = slot;
  } else {
    pool->wait_head = slot;
  }
  pool->wait_tail = slot;
  pool->waiting++;
  out->pool = pool;
  out->slot = slot;
  out->generation = waiter->generation;
  return FTUN_OK;
}

ftun_status_t ftun_buffer_pool_wait_cancel(ftun_buffer_wait_token_t *token)
{
  ftun_buffer_pool_t *pool;
  ftun_buffer_waiter_t *waiter;
  if (token == NULL) return FTUN_E_INVALID;
  pool = token->pool;
  if (pool == NULL || token->generation == 0u ||
      token->slot >= pool->waiter_capacity) return FTUN_E_INVALID;
  waiter = &pool->waiters[token->slot];
  if (!waiter->pending || waiter->generation != token->generation) {
    return FTUN_E_STALE;
  }
  if (pool->waiting == 0u) return FTUN_E_STATE_CORRUPT;
  ftun_buffer_waiter_unlink(pool, token->slot);
  pool->waiting--;
  waiter->pending = 0;
  ftun_buffer_waiter_recycle(pool, token->slot);
  if (pool->cancelled_waiters != SIZE_MAX) pool->cancelled_waiters++;
  memset(token, 0, sizeof(*token));
  ftun_buffer_pool_notify(pool);
  return FTUN_OK;
}

ftun_status_t ftun_buffer_pool_dispatch(
  ftun_buffer_pool_t *pool, size_t max_callbacks, size_t *out_callbacks)
{
  size_t callbacks = 0u;
  size_t limit;
  if (out_callbacks != NULL) *out_callbacks = 0u;
  if (pool == NULL || max_callbacks == 0u || out_callbacks == NULL) {
    return FTUN_E_INVALID;
  }
  if (pool->dispatching) return FTUN_E_AGAIN;
  pool->dispatching = 1;
  pool->notification_pending = 0;
  pool->notification_sent = 0;
  limit = pool->wake_quota < max_callbacks ? pool->wake_quota : max_callbacks;
  while (callbacks < limit && pool->waiting != 0u) {
    ftun_buffer_waiter_t *waiter;
    ftun_buffer_ready_fn ready;
    void *user;
    size_t slot = ftun_buffer_pool_ready_waiter(pool);
    if (slot == FTUN_BUFFER_WAITER_NONE) {
      break;
    }
    waiter = &pool->waiters[slot];
    if (!waiter->pending) {
      pool->dispatching = 0;
      return FTUN_E_STATE_CORRUPT;
    }
    ready = waiter->ready;
    user = waiter->user;
    ftun_buffer_waiter_unlink(pool, slot);
    pool->waiting--;
    waiter->pending = 0;
    ftun_buffer_waiter_recycle(pool, slot);
    if (pool->wake_callbacks != SIZE_MAX) pool->wake_callbacks++;
    callbacks++;
    ready(user);
  }
  pool->dispatching = 0;
  *out_callbacks = callbacks;
  ftun_buffer_pool_notify(pool);
  return FTUN_OK;
}

ftun_status_t ftun_buffer_pool_get_usage(const ftun_buffer_pool_t *pool,
                                         ftun_buffer_pool_usage_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (pool == NULL || out == NULL) return FTUN_E_INVALID;
  out->idle_limit_bytes = pool->idle_limit_bytes;
  out->idle_limit_buffers = pool->idle_limit_buffers;
  out->idle_bytes = pool->idle_bytes;
  out->idle_buffers = pool->idle_buffers;
  out->active_buffers = pool->active_buffers;
  out->cache_hits = pool->cache_hits;
  out->cache_misses = pool->cache_misses;
  out->pressure_trims = pool->pressure_trims;
  out->pressure_trimmed_bytes = pool->pressure_trimmed_bytes;
  out->pressure_trimmed_buffers = pool->pressure_trimmed_buffers;
  out->waiter_capacity = pool->waiter_capacity;
  out->waiting = pool->waiting;
  out->wake_quota = pool->wake_quota;
  out->notifications = pool->notifications;
  out->wake_callbacks = pool->wake_callbacks;
  out->cancelled_waiters = pool->cancelled_waiters;
  out->rejected_waiters = pool->rejected_waiters;
  out->dispatching = pool->dispatching != 0;
  return FTUN_OK;
}

ftun_status_t ftun_buffer_pool_trim(ftun_buffer_pool_t *pool, size_t target_idle_bytes)
{
  if (pool == NULL) return FTUN_E_INVALID;
  while (pool->idle != NULL && pool->idle_bytes > target_idle_bytes) {
    ftun_buffer_t *buffer = pool->idle;
    ftun_status_t status;
    if (pool->idle_buffers == 0u || pool->idle_bytes < buffer->capacity) {
      return FTUN_E_STATE_CORRUPT;
    }
    pool->idle = buffer->next;
    buffer->next = NULL;
    pool->idle_buffers--;
    pool->idle_bytes -= buffer->capacity;
    status = ftun_buffer_free(buffer);
    if (status != FTUN_OK) {
      buffer->next = pool->idle;
      pool->idle = buffer;
      pool->idle_buffers++;
      pool->idle_bytes += buffer->capacity;
      return status;
    }
  }
  ftun_buffer_pool_notify(pool);
  return FTUN_OK;
}

ftun_status_t ftun_buffer_pool_destroy(ftun_buffer_pool_t **pool)
{
  ftun_buffer_pool_t *owned;
  ftun_reservation_t *reservation;
  ftun_status_t status;
  if (pool == NULL) return FTUN_E_INVALID;
  owned = *pool;
  if (owned == NULL) return FTUN_OK;
  if (owned->active_buffers != 0u || owned->waiting != 0u ||
      owned->dispatching) return FTUN_E_AGAIN;
  status = ftun_buffer_pool_trim(owned, 0u);
  if (status != FTUN_OK) return status;
  if (owned->idle != NULL || owned->idle_bytes != 0u || owned->idle_buffers != 0u) {
    return FTUN_E_STATE_CORRUPT;
  }
  reservation = owned->reservation;
  status = ftun_reservation_release(&reservation);
  if (status != FTUN_OK) return status;
  owned->reservation = NULL;
  free(owned->waiters);
  owned->waiters = NULL;
  free(owned);
  *pool = NULL;
  return FTUN_OK;
}

ftun_status_t ftun_buffer_retain(ftun_buffer_t *buffer)
{
  if (buffer == NULL) return FTUN_E_INVALID;
  if (buffer->references == 0u) return FTUN_E_STALE;
  if (buffer->references == SIZE_MAX) return FTUN_E_LIMIT;
  buffer->references++;
  return FTUN_OK;
}

ftun_status_t ftun_buffer_data(ftun_buffer_t *buffer, uint8_t **data, size_t *capacity)
{
  if (data != NULL) *data = NULL;
  if (capacity != NULL) *capacity = 0u;
  if (buffer == NULL || data == NULL || capacity == NULL || buffer->references == 0u) {
    return FTUN_E_INVALID;
  }
  *data = buffer->data;
  *capacity = buffer->capacity;
  return FTUN_OK;
}

ftun_status_t ftun_buffer_release(ftun_buffer_t **buffer)
{
  ftun_buffer_t *owned;
  ftun_buffer_pool_t *pool;
  ftun_status_t status;
  if (buffer == NULL) return FTUN_E_INVALID;
  owned = *buffer;
  if (owned == NULL) return FTUN_OK;
  if (owned->references == 0u) return FTUN_E_STATE_CORRUPT;
  owned->references--;
  *buffer = NULL;
  if (owned->references != 0u) return FTUN_OK;
  pool = owned->pool;
  if (pool == NULL) {
    status = ftun_buffer_free(owned);
    if (status != FTUN_OK) {
      owned->references = 1u;
      *buffer = owned;
    }
    return status;
  }
  if (pool->active_buffers == 0u) {
    owned->references = 1u;
    *buffer = owned;
    return FTUN_E_STATE_CORRUPT;
  }
  pool->active_buffers--;
  if (pool->idle_buffers > pool->idle_limit_buffers ||
      pool->idle_bytes > pool->idle_limit_bytes) {
    pool->active_buffers++;
    owned->references = 1u;
    *buffer = owned;
    return FTUN_E_STATE_CORRUPT;
  }
  if (pool->idle_buffers < pool->idle_limit_buffers &&
      owned->capacity <= pool->idle_limit_bytes - pool->idle_bytes) {
    owned->next = pool->idle;
    pool->idle = owned;
    pool->idle_buffers++;
    pool->idle_bytes += owned->capacity;
    ftun_buffer_pool_notify(pool);
    return FTUN_OK;
  }
  status = ftun_buffer_free(owned);
  if (status != FTUN_OK) {
    pool->active_buffers++;
    owned->references = 1u;
    *buffer = owned;
  } else {
    ftun_buffer_pool_notify(pool);
  }
  return status;
}

ftun_status_t ftun_buffer_slice(ftun_buffer_t *buffer, size_t offset, size_t length,
                                ftun_buffer_slice_t *out)
{
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (buffer == NULL || out == NULL || buffer->references == 0u ||
      offset > buffer->capacity || length > buffer->capacity - offset) {
    return FTUN_E_INVALID;
  }
  status = ftun_buffer_retain(buffer);
  if (status != FTUN_OK) return status;
  out->owner = buffer;
  out->offset = offset;
  out->length = length;
  return FTUN_OK;
}

ftun_status_t ftun_buffer_slice_clone(const ftun_buffer_slice_t *source,
                                      ftun_buffer_slice_t *out)
{
  ftun_status_t status;
  if (out != NULL && source != out) memset(out, 0, sizeof(*out));
  if (source == NULL || out == NULL || source == out || source->owner == NULL ||
      source->owner->references == 0u || source->offset > source->owner->capacity ||
      source->length > source->owner->capacity - source->offset) {
    return FTUN_E_INVALID;
  }
  status = ftun_buffer_retain(source->owner);
  if (status != FTUN_OK) return status;
  *out = *source;
  return FTUN_OK;
}

ftun_status_t ftun_buffer_slice_data(const ftun_buffer_slice_t *slice, ftun_bytes_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (slice == NULL || out == NULL || slice->owner == NULL ||
      slice->owner->references == 0u || slice->offset > slice->owner->capacity ||
      slice->length > slice->owner->capacity - slice->offset) {
    return FTUN_E_INVALID;
  }
  out->data = slice->owner->data + slice->offset;
  out->length = slice->length;
  return FTUN_OK;
}

ftun_status_t ftun_buffer_slice_budget(const ftun_buffer_slice_t *slice,
                                       ftun_budget_t **out)
{
  if (out != NULL) *out = NULL;
  if (slice == NULL || out == NULL || slice->owner == NULL ||
      slice->owner->references == 0u) return FTUN_E_INVALID;
  *out = slice->owner->budget;
  return FTUN_OK;
}

ftun_status_t ftun_buffer_slice_release(ftun_buffer_slice_t *slice)
{
  ftun_buffer_t *owner;
  if (slice == NULL) return FTUN_E_INVALID;
  owner = slice->owner;
  memset(slice, 0, sizeof(*slice));
  if (owner == NULL) return FTUN_OK;
  return ftun_buffer_release(&owner);
}
