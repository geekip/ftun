#include "libs/buffer/buffer.h"
#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define FTUN_BUFFER_MIN_CLASS 256u
#define FTUN_BUFFER_CLASS_COUNT (sizeof(size_t) * CHAR_BIT - 8u)
typedef char ftun_buffer_class_mask_fits[(FTUN_BUFFER_CLASS_COUNT <= 64u) ? 1 : -1];

struct ftun_buffer {
  ftun_buffer_pool_t *pool;
  ftun_budget_t *budget;
  ftun_buffer_t *next;
  ftun_reservation_t reservation;
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

typedef struct {
  size_t wait_head;
  size_t wait_tail;
} ftun_buffer_class_queue_t;

struct ftun_buffer_pool {
  ftun_budget_t *budget;
  ftun_reservation_t reservation;
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
  ftun_buffer_class_queue_t *classes;
  size_t waiting_classes;
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
  /* 冷诊断计数置于调度热字段之后。 */
  size_t selection_steps;
  size_t max_selection_steps;
  size_t availability_probes;
  size_t max_availability_probes;
  size_t idle_scan_steps;
  size_t max_trim_buffers;
};

#define FTUN_BUFFER_WAITER_NONE SIZE_MAX

static size_t ftun_buffer_class_index(size_t capacity)
{
#if defined(__GNUC__) || defined(__clang__)
  return (size_t)__builtin_ctzll((unsigned long long)capacity) - 8u;
#else
  size_t index = 0u;
  while (capacity > FTUN_BUFFER_MIN_CLASS) { capacity >>= 1u; index++; }
  return index;
#endif
}

static size_t ftun_buffer_first_class(uint64_t classes)
{
#if defined(__GNUC__) || defined(__clang__)
  return (size_t)__builtin_ctzll(classes);
#else
  size_t index = 0u;
  while ((classes & UINT64_C(1)) == 0u) { classes >>= 1u; index++; }
  return index;
#endif
}

static size_t ftun_buffer_count_add(size_t count, size_t amount)
{
  return amount > SIZE_MAX - count ? SIZE_MAX : count + amount;
}

static ftun_status_t ftun_buffer_pool_trim_idle(
  ftun_buffer_pool_t *pool, size_t target_idle_bytes);

/* 压力回收不递归通知；调用方完成本次资源判断/分配后再合并通知。 */
static ftun_status_t ftun_buffer_pool_pressure_trim(ftun_buffer_pool_t *pool)
{
  size_t bytes = pool->idle_bytes;
  size_t buffers = pool->idle_buffers;
  ftun_status_t status = ftun_buffer_pool_trim_idle(pool, 0u);
  if (status != FTUN_OK) return status;
  if (pool->pressure_trims != SIZE_MAX) pool->pressure_trims++;
  bytes -= pool->idle_bytes;
  buffers -= pool->idle_buffers;
  if (buffers > pool->max_trim_buffers) pool->max_trim_buffers = buffers;
  pool->pressure_trimmed_bytes = bytes > SIZE_MAX - pool->pressure_trimmed_bytes
    ? SIZE_MAX : pool->pressure_trimmed_bytes + bytes;
  pool->pressure_trimmed_buffers = buffers > SIZE_MAX - pool->pressure_trimmed_buffers
    ? SIZE_MAX : pool->pressure_trimmed_buffers + buffers;
  return FTUN_OK;
}

/* 分档、有界闲置与所有者引用。 */
static ftun_status_t ftun_buffer_class(size_t requested, size_t *out)
{
  size_t capacity = FTUN_BUFFER_MIN_CLASS;
  if (out != NULL) *out = 0u;
  if (requested == 0u || out == NULL) return FTUN_E_INVALID;
#if defined(__GNUC__) || defined(__clang__)
  if (requested > capacity) {
    unsigned int bits = (unsigned int)(sizeof(unsigned long long) * CHAR_BIT) -
      (unsigned int)__builtin_clzll((unsigned long long)(requested - 1u));
    if (bits >= sizeof(size_t) * CHAR_BIT) return FTUN_E_LIMIT;
    capacity = (size_t)1u << bits;
  }
#else
  while (capacity < requested) {
    if (capacity > SIZE_MAX / 2u) return FTUN_E_LIMIT;
    capacity *= 2u;
  }
#endif
  if (capacity > SIZE_MAX - sizeof(ftun_buffer_t)) return FTUN_E_LIMIT;
  *out = capacity;
  return FTUN_OK;
}

static ftun_status_t ftun_buffer_allocate(ftun_budget_t *budget,
                                          ftun_buffer_pool_t *pool,
                                          size_t capacity, ftun_buffer_t **out)
{
  ftun_buffer_t *buffer;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_status_t status;
  size_t charge = sizeof(*buffer) + capacity;

  status = ftun_budget_reserve(budget, charge, &reservation);
  if (status != FTUN_OK) return status;
  buffer = (ftun_buffer_t *)malloc(charge);
  if (buffer == NULL) {
    ftun_reservation_release(&reservation);
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

static void ftun_buffer_free(ftun_buffer_t *buffer)
{
  ftun_reservation_t reservation = buffer->reservation;
  buffer->reservation = (ftun_reservation_t){0};
  ftun_reservation_release(&reservation);
  free(buffer);
}

static int ftun_buffer_pool_idle_class(ftun_buffer_pool_t *pool, size_t capacity)
{
  const ftun_buffer_t *buffer;
  for (buffer = pool->idle; buffer != NULL; buffer = buffer->next) {
    pool->idle_scan_steps = ftun_buffer_count_add(pool->idle_scan_steps, 1u);
    if (buffer->capacity == capacity) return 1;
  }
  return 0;
}

static ftun_status_t ftun_buffer_pool_can_acquire(ftun_buffer_pool_t *pool,
                                                 size_t capacity, int *out)
{
  ftun_budget_usage_t usage;
  ftun_status_t status;
  size_t charge;
  *out = 0;
  if (ftun_buffer_pool_idle_class(pool, capacity)) {
    *out = 1;
    return FTUN_OK;
  }
  if (capacity > SIZE_MAX - sizeof(ftun_buffer_t)) return FTUN_E_LIMIT;
  charge = sizeof(ftun_buffer_t) + capacity;
  status = ftun_budget_get_usage(pool->budget, &usage);
  if (status != FTUN_OK) return status;
  if (charge > usage.normal_available_resources.memory_bytes && pool->idle != NULL) {
    size_t reclaimable = pool->idle_bytes;
    if (pool->idle_buffers > (SIZE_MAX - reclaimable) / sizeof(ftun_buffer_t)) {
      reclaimable = SIZE_MAX;
    } else {
      reclaimable += pool->idle_buffers * sizeof(ftun_buffer_t);
    }
    /* 这里只排除连最大回收量都不足的情况，不能把相加结果当作可用额度。
     * ancestor cleanup/保证额仍必须在实际释放后重新验证。 */
    if (charge - usage.normal_available_resources.memory_bytes <= reclaimable) {
      status = ftun_buffer_pool_pressure_trim(pool);
      if (status != FTUN_OK) return status;
      status = ftun_budget_get_usage(pool->budget, &usage);
      if (status != FTUN_OK) return status;
    }
  }
  *out = charge <= usage.normal_available_resources.memory_bytes;
  return FTUN_OK;
}

static ftun_status_t ftun_buffer_pool_ready_waiter(ftun_buffer_pool_t *pool,
                                                   size_t *out)
{
  size_t heads[FTUN_BUFFER_CLASS_COUNT];
  size_t count = 0u, index, steps = 0u, probes = 0u;
  uint64_t classes = pool->waiting_classes;
  ftun_status_t status = FTUN_OK;
  *out = FTUN_BUFFER_WAITER_NONE;
  while (classes != 0u) {
    size_t category = ftun_buffer_first_class(classes);
    classes &= classes - 1u;
    heads[count++] = pool->classes[category].wait_head;
    steps++;
  }
  /* 同类只检查队首；不同类仍按原到达顺序探测，保留压力回收的先后语义。 */
  for (index = 1u; index < count; index++) {
    size_t position = index, slot = heads[index];
    while (position != 0u) {
      steps++;
      if (pool->waiters[heads[position - 1u]].generation < pool->waiters[slot].generation) break;
      heads[position] = heads[position - 1u];
      position--;
    }
    heads[position] = slot;
  }
  for (index = 0u; index < count; index++) {
    size_t slot = heads[index];
    int available;
    steps++;
    probes++;
    if (!pool->waiters[slot].pending) { status = FTUN_E_STATE_CORRUPT; break; }
    status = ftun_buffer_pool_can_acquire(pool, pool->waiters[slot].capacity,
                                         &available);
    if (status != FTUN_OK) break;
    if (available) {
      *out = slot;
      break;
    }
  }
  pool->selection_steps = ftun_buffer_count_add(pool->selection_steps, steps);
  pool->availability_probes = ftun_buffer_count_add(pool->availability_probes, probes);
  if (steps > pool->max_selection_steps) pool->max_selection_steps = steps;
  if (probes > pool->max_availability_probes) pool->max_availability_probes = probes;
  return status;
}

static void ftun_buffer_pool_notify(ftun_buffer_pool_t *pool)
{
  ftun_buffer_pool_wakeup_fn wakeup;
  void *user;
  size_t slot;
  ftun_status_t status;
  if (pool->waiting == 0u) {
    pool->notification_pending = 0;
    pool->notification_sent = 0;
    return;
  }
  if (pool->dispatching) return;
  if (pool->notification_pending && pool->notification_sent) return;
  status = ftun_buffer_pool_ready_waiter(pool, &slot);
  /* 异常也安排 owner dispatch，由有返回值的入口报告，不静默隐藏。 */
  if (status == FTUN_OK && slot == FTUN_BUFFER_WAITER_NONE) return;
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
  size_t category = ftun_buffer_class_index(waiter->capacity);
  ftun_buffer_class_queue_t *queue = &pool->classes[category];
  if (waiter->previous != FTUN_BUFFER_WAITER_NONE) {
    pool->waiters[waiter->previous].next = waiter->next;
  } else {
    queue->wait_head = waiter->next;
  }
  if (waiter->next != FTUN_BUFFER_WAITER_NONE) {
    pool->waiters[waiter->next].previous = waiter->previous;
  } else {
    queue->wait_tail = waiter->previous;
  }
  waiter->previous = FTUN_BUFFER_WAITER_NONE;
  waiter->next = FTUN_BUFFER_WAITER_NONE;
  if (queue->wait_head == FTUN_BUFFER_WAITER_NONE) {
    pool->waiting_classes &= ~((size_t)1u << category);
  }
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

ftun_status_t ftun_buffer_pool_budget(const ftun_buffer_pool_t *pool,
  ftun_budget_t **out)
{
  if (out != NULL) *out = NULL;
  if (pool == NULL || out == NULL) return FTUN_E_INVALID;
  *out = pool->budget;
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

ftun_status_t ftun_buffer_pool_create_waitable(
  ftun_budget_t *budget, size_t idle_limit_bytes, size_t idle_limit_buffers,
  size_t waiter_capacity, size_t wake_quota, ftun_buffer_pool_t **out)
{
  ftun_buffer_pool_t *pool;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_status_t status;
  size_t charge = sizeof(*pool);
  size_t pool_bytes = sizeof(*pool);
  size_t index;
  if (out != NULL) *out = NULL;
  if (budget == NULL || out == NULL ||
      (waiter_capacity == 0u && wake_quota != 0u) ||
      (waiter_capacity != 0u &&
       (wake_quota == 0u || wake_quota > waiter_capacity))) {
    return FTUN_E_INVALID;
  }
  if (waiter_capacity != 0u) {
    pool_bytes += FTUN_BUFFER_CLASS_COUNT * sizeof(ftun_buffer_class_queue_t);
    charge = pool_bytes;
  }
  if (waiter_capacity > (SIZE_MAX - charge) / sizeof(ftun_buffer_waiter_t)) {
    return FTUN_E_LIMIT;
  }
  charge += waiter_capacity * sizeof(ftun_buffer_waiter_t);
  /* 等待节点可独立保留回调，槽位归 Pool；Flow 只持 token，不重复准入。 */
  status = ftun_budget_reserve_resources(budget,
    (ftun_budget_resources_t){charge, 0u, waiter_capacity}, &reservation);
  if (status != FTUN_OK) return status;
  pool = (ftun_buffer_pool_t *)calloc(1u, pool_bytes);
  if (pool != NULL && waiter_capacity != 0u) {
    pool->waiters = (ftun_buffer_waiter_t *)calloc(
      waiter_capacity, sizeof(*pool->waiters));
  }
  if (pool == NULL || (waiter_capacity != 0u && pool->waiters == NULL)) {
    if (pool != NULL) free(pool->waiters);
    free(pool);
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  pool->budget = budget;
  if (pool_bytes != sizeof(*pool)) {
    pool->classes = (ftun_buffer_class_queue_t *)(pool + 1u);
    for (index = 0u; index < FTUN_BUFFER_CLASS_COUNT; index++) {
      pool->classes[index].wait_head = FTUN_BUFFER_WAITER_NONE;
      pool->classes[index].wait_tail = FTUN_BUFFER_WAITER_NONE;
    }
  }
  pool->reservation = reservation;
  pool->idle_limit_bytes = idle_limit_bytes;
  pool->idle_limit_buffers = idle_limit_buffers;
  pool->waiter_capacity = waiter_capacity;
  pool->wake_quota = wake_quota;
  pool->free_waiter = waiter_capacity == 0u
    ? FTUN_BUFFER_WAITER_NONE : 0u;
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
  if (pool->wakeup != wakeup || pool->wakeup_user != user) {
    pool->notification_sent = 0;
  }
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
  int trimmed = 0;
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
    status = ftun_buffer_pool_pressure_trim(pool);
    if (status != FTUN_OK) return status;
    trimmed = 1;
    status = ftun_buffer_allocate(pool->budget, pool, buffer_class, out);
  }
  if (status != FTUN_OK) {
    if (trimmed) ftun_buffer_pool_notify(pool);
    return status;
  }
  if (pool->active_buffers == SIZE_MAX) {
    buffer = *out;
    *out = NULL;
    ftun_buffer_free(buffer);
    if (trimmed) ftun_buffer_pool_notify(pool);
    return FTUN_E_LIMIT;
  }
  pool->active_buffers++;
  if (trimmed) ftun_buffer_pool_notify(pool);
  return FTUN_OK;
}

ftun_status_t ftun_buffer_pool_wait(
  ftun_buffer_pool_t *pool, size_t capacity, ftun_buffer_ready_fn ready,
  void *user, ftun_buffer_wait_token_t *out)
{
  ftun_buffer_waiter_t *waiter;
  size_t buffer_class;
  size_t category;
  ftun_buffer_class_queue_t *queue;
  size_t slot;
  int available;
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (pool == NULL || ready == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_buffer_class(capacity, &buffer_class);
  if (status != FTUN_OK) return status;
  status = ftun_buffer_pool_can_acquire(pool, buffer_class, &available);
  if (status != FTUN_OK) return status;
  if (available) {
    ftun_buffer_pool_notify(pool);
    return FTUN_E_AGAIN;
  }
  if (pool->free_waiter == FTUN_BUFFER_WAITER_NONE ||
      pool->next_waiter_generation == UINT64_MAX) {
    if (pool->rejected_waiters != SIZE_MAX) pool->rejected_waiters++;
    ftun_buffer_pool_notify(pool);
    return FTUN_E_LIMIT;
  }
  slot = pool->free_waiter;
  category = ftun_buffer_class_index(buffer_class);
  queue = &pool->classes[category];
  waiter = &pool->waiters[slot];
  pool->free_waiter = waiter->next;
  pool->next_waiter_generation++;
  memset(waiter, 0, sizeof(*waiter));
  waiter->previous = queue->wait_tail;
  waiter->next = FTUN_BUFFER_WAITER_NONE;
  waiter->capacity = buffer_class;
  waiter->ready = ready;
  waiter->user = user;
  waiter->generation = pool->next_waiter_generation;
  waiter->pending = 1;
  if (queue->wait_tail != FTUN_BUFFER_WAITER_NONE) {
    pool->waiters[queue->wait_tail].next = slot;
  } else {
    queue->wait_head = slot;
  }
  queue->wait_tail = slot;
  pool->waiting_classes |= (size_t)1u << category;
  pool->waiting++;
  out->pool = pool;
  out->slot = slot;
  out->generation = waiter->generation;
  ftun_buffer_pool_notify(pool);
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
    size_t slot;
    ftun_status_t status = ftun_buffer_pool_ready_waiter(pool, &slot);
    if (status != FTUN_OK) {
      pool->dispatching = 0;
      *out_callbacks = callbacks;
      return status;
    }
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
  out->selection_steps = pool->selection_steps;
  out->max_selection_steps = pool->max_selection_steps;
  out->availability_probes = pool->availability_probes;
  out->max_availability_probes = pool->max_availability_probes;
  out->idle_scan_steps = pool->idle_scan_steps;
  out->max_trim_buffers = pool->max_trim_buffers;
  out->dispatching = pool->dispatching != 0;
  return FTUN_OK;
}

static ftun_status_t ftun_buffer_pool_trim_idle(
  ftun_buffer_pool_t *pool, size_t target_idle_bytes)
{
  if (pool == NULL) return FTUN_E_INVALID;
  while (pool->idle != NULL && pool->idle_bytes > target_idle_bytes) {
    ftun_buffer_t *buffer = pool->idle;
    if (pool->idle_buffers == 0u || pool->idle_bytes < buffer->capacity) {
      return FTUN_E_STATE_CORRUPT;
    }
    pool->idle = buffer->next;
    buffer->next = NULL;
    pool->idle_buffers--;
    pool->idle_bytes -= buffer->capacity;
    ftun_buffer_free(buffer);
  }
  return FTUN_OK;
}

ftun_status_t ftun_buffer_pool_trim(ftun_buffer_pool_t *pool, size_t target_idle_bytes)
{
  ftun_status_t status = ftun_buffer_pool_trim_idle(pool, target_idle_bytes);
  if (status == FTUN_OK) ftun_buffer_pool_notify(pool);
  return status;
}

ftun_status_t ftun_buffer_pool_destroy(ftun_buffer_pool_t **pool)
{
  ftun_buffer_pool_t *owned;
  ftun_reservation_t reservation;
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
  ftun_reservation_release(&reservation);
  owned->reservation = (ftun_reservation_t){0};
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

void ftun_buffer_release(ftun_buffer_t **buffer)
{
  ftun_buffer_t *owned;
  ftun_buffer_pool_t *pool;
  assert(buffer != NULL);
  owned = *buffer;
  if (owned == NULL) return;
  assert(owned->references != 0u);
  owned->references--;
  *buffer = NULL;
  if (owned->references != 0u) return;
  pool = owned->pool;
  if (pool == NULL) { ftun_buffer_free(owned); return; }
  assert(pool->active_buffers != 0u);
  assert(pool->idle_buffers <= pool->idle_limit_buffers);
  assert(pool->idle_bytes <= pool->idle_limit_bytes);
  pool->active_buffers--;
  if (pool->idle_buffers < pool->idle_limit_buffers &&
      owned->capacity <= pool->idle_limit_bytes - pool->idle_bytes) {
    owned->next = pool->idle;
    pool->idle = owned;
    pool->idle_buffers++;
    pool->idle_bytes += owned->capacity;
  } else ftun_buffer_free(owned);
  if (pool->waiting != 0u) ftun_buffer_pool_notify(pool);
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

void ftun_buffer_slice_release(ftun_buffer_slice_t *slice)
{
  ftun_buffer_t *owner;
  assert(slice != NULL);
  owner = slice->owner;
  memset(slice, 0, sizeof(*slice));
  ftun_buffer_release(&owner);
}
