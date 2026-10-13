#include "buffer.h"
#include <stdlib.h>
#include <string.h>

#define FTUN_BUFFER_MIN_CLASS 256u

struct ftun_buffer {
  ftun_buffer_pool_t *pool;
  ftun_buffer_t *next;
  ftun_reservation_t *reservation;
  size_t capacity;
  size_t references;
  uint8_t data[];
};

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
};

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

ftun_status_t ftun_buffer_pool_create(ftun_budget_t *budget, size_t idle_limit_bytes,
                                      size_t idle_limit_buffers,
                                      ftun_buffer_pool_t **out)
{
  ftun_buffer_pool_t *pool;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (budget == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_budget_reserve(budget, sizeof(*pool), &reservation);
  if (status != FTUN_OK) return status;
  pool = (ftun_buffer_pool_t *)calloc(1u, sizeof(*pool));
  if (pool == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  pool->budget = budget;
  pool->reservation = reservation;
  pool->idle_limit_bytes = idle_limit_bytes;
  pool->idle_limit_buffers = idle_limit_buffers;
  *out = pool;
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
  if (owned->active_buffers != 0u) return FTUN_E_AGAIN;
  status = ftun_buffer_pool_trim(owned, 0u);
  if (status != FTUN_OK) return status;
  if (owned->idle != NULL || owned->idle_bytes != 0u || owned->idle_buffers != 0u) {
    return FTUN_E_STATE_CORRUPT;
  }
  reservation = owned->reservation;
  status = ftun_reservation_release(&reservation);
  if (status != FTUN_OK) return status;
  owned->reservation = NULL;
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
    return FTUN_OK;
  }
  status = ftun_buffer_free(owned);
  if (status != FTUN_OK) {
    pool->active_buffers++;
    owned->references = 1u;
    *buffer = owned;
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

ftun_status_t ftun_buffer_slice_release(ftun_buffer_slice_t *slice)
{
  ftun_buffer_t *owner;
  if (slice == NULL) return FTUN_E_INVALID;
  owner = slice->owner;
  memset(slice, 0, sizeof(*slice));
  if (owner == NULL) return FTUN_OK;
  return ftun_buffer_release(&owner);
}
