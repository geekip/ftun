#include "core/event/backend.h"
#include "core/event/loop.h"
#include "platform/poller.h"
#define FTUN_EVENT_BACKEND_IO_COLLECT_QUOTA FTUN_POLLER_CAPACITY
#include "core/limits.h"
#include "platform/clock.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct ftun_event_backend_watcher ftun_event_backend_watcher_t;
typedef struct ftun_event_backend_group ftun_event_backend_group_t;

typedef struct {
  ftun_event_loop_t *front;
  ftun_poller_t poller;
  int deadline;
  uint64_t armed_deadline_ms;
  uint64_t wait_started_ms;
  uint64_t wait_ms;
  size_t collected;
  ftun_budget_t *budget;
  ftun_reservation_t reservation;
  ftun_event_backend_group_t *groups;
  ftun_event_backend_group_t *dirty;
  ftun_event_backend_group_t *ready_head;
  ftun_event_backend_group_t *ready_tail;
  ftun_status_t pending_error;
  int stopped;
} ftun_event_backend_adapter_t;

struct ftun_event_backend_watcher {
  ftun_event_backend_adapter_t *adapter;
  ftun_event_backend_group_t *group;
  ftun_event_backend_watcher_t *previous;
  ftun_event_backend_watcher_t *next;
  ftun_event_source_t *source;
  ftun_reservation_t reservation;
  uint32_t interests;
};

/* 每 FD 一个 native watcher；source 仍分别拥有兴趣、取消和前端句柄。
 * AVL 索引使新增/查找/移除不随其他 FD 线性扫描。ready 链与成员游标
 * 都嵌入已准入对象，不为重复通知分配节点，也不重启尚未完成的批次。 */
struct ftun_event_backend_group {
  ftun_event_backend_adapter_t *adapter;
  ftun_reservation_t reservation;
  ftun_event_backend_group_t *left;
  ftun_event_backend_group_t *right;
  ftun_event_backend_group_t *parent;
  ftun_event_backend_group_t *ready_previous;
  ftun_event_backend_group_t *ready_next;
  ftun_event_backend_watcher_t *watchers;
  ftun_event_backend_watcher_t *cursor;
  size_t readers;
  size_t writers;
  uint32_t events;
  uint32_t repeat_events;
  int height;
  bool queued;
  bool dirty;
  uint32_t desired_events;
  ftun_event_backend_group_t *dirty_previous, *dirty_next;
  struct { int fd; uint32_t events; } io;
  /* 大多数 FD 只有一个 source，共享组直接拥有首个成员及其额度。 */
  ftun_event_backend_watcher_t first;
};

static void ftun_event_backend_record(ftun_event_backend_adapter_t *adapter, ftun_status_t status)
{
  if (status != FTUN_OK && adapter->pending_error == FTUN_OK) {
    adapter->pending_error = status;
  }
}

static int ftun_event_backend_height(const ftun_event_backend_group_t *group)
{
  return group == NULL ? 0 : group->height;
}

static void ftun_event_backend_refresh(ftun_event_backend_group_t *group)
{
  int left = ftun_event_backend_height(group->left), right = ftun_event_backend_height(group->right);
  group->height = 1 + (left > right ? left : right);
}

static void ftun_event_backend_replace(ftun_event_backend_adapter_t *adapter,
  ftun_event_backend_group_t *old, ftun_event_backend_group_t *replacement)
{
  if (old->parent == NULL) adapter->groups = replacement;
  else if (old->parent->left == old) old->parent->left = replacement;
  else old->parent->right = replacement;
  if (replacement != NULL) replacement->parent = old->parent;
}

static ftun_event_backend_group_t *ftun_event_backend_rotate(ftun_event_backend_group_t *group, bool left)
{
  ftun_event_backend_group_t *pivot = left ? group->right : group->left;
  ftun_event_backend_replace(group->adapter, group, pivot);
  if (left) {
    group->right = pivot->left;
    if (group->right != NULL) group->right->parent = group;
    pivot->left = group;
  } else {
    group->left = pivot->right;
    if (group->left != NULL) group->left->parent = group;
    pivot->right = group;
  }
  group->parent = pivot;
  ftun_event_backend_refresh(group);
  ftun_event_backend_refresh(pivot);
  return pivot;
}

static void ftun_event_backend_rebalance(ftun_event_backend_group_t *group)
{
  while (group != NULL) {
    int balance;
    ftun_event_backend_refresh(group);
    balance = ftun_event_backend_height(group->left) - ftun_event_backend_height(group->right);
    if (balance > 1) {
      if (ftun_event_backend_height(group->left->left) < ftun_event_backend_height(group->left->right)) {
        (void)ftun_event_backend_rotate(group->left, true);
      }
      group = ftun_event_backend_rotate(group, false);
    } else if (balance < -1) {
      if (ftun_event_backend_height(group->right->right) < ftun_event_backend_height(group->right->left)) {
        (void)ftun_event_backend_rotate(group->right, false);
      }
      group = ftun_event_backend_rotate(group, true);
    }
    group = group->parent;
  }
}

static ftun_event_backend_group_t *ftun_event_backend_group_find(ftun_event_backend_adapter_t *adapter, int fd)
{
  ftun_event_backend_group_t *group = adapter->groups;
  while (group != NULL && group->io.fd != fd) group = fd < group->io.fd ? group->left : group->right;
  return group;
}

static void ftun_event_backend_group_insert(ftun_event_backend_group_t *group)
{
  ftun_event_backend_group_t **place = &group->adapter->groups, *parent = NULL;
  while (*place != NULL) {
    parent = *place;
    place = group->io.fd < parent->io.fd ? &parent->left : &parent->right;
  }
  *place = group;
  group->parent = parent;
  group->height = 1;
  ftun_event_backend_rebalance(parent);
}

static void ftun_event_backend_group_unlink(ftun_event_backend_group_t *group)
{
  ftun_event_backend_group_t *repair;
  if (group->left != NULL && group->right != NULL) {
    ftun_event_backend_group_t *successor = group->right;
    while (successor->left != NULL) successor = successor->left;
    if (successor->parent == group) repair = successor;
    else {
      repair = successor->parent;
      ftun_event_backend_replace(group->adapter, successor, successor->right);
      successor->right = group->right;
      successor->right->parent = successor;
    }
    ftun_event_backend_replace(group->adapter, group, successor);
    successor->left = group->left;
    successor->left->parent = successor;
  } else {
    repair = group->parent;
    ftun_event_backend_replace(group->adapter, group, group->left != NULL ? group->left : group->right);
  }
  ftun_event_backend_rebalance(repair);
}

static void ftun_event_backend_ready_unlink(ftun_event_backend_group_t *group)
{
  ftun_event_backend_adapter_t *adapter = group->adapter;
  if (!group->queued) return;
  if (group->ready_previous != NULL) group->ready_previous->ready_next = group->ready_next;
  else adapter->ready_head = group->ready_next;
  if (group->ready_next != NULL) group->ready_next->ready_previous = group->ready_previous;
  else adapter->ready_tail = group->ready_previous;
  group->ready_previous = group->ready_next = NULL;
  group->queued = false;
}

static void ftun_event_backend_ready_append(ftun_event_backend_group_t *group)
{
  ftun_event_backend_adapter_t *adapter = group->adapter;
  if (group->queued) return;
  group->ready_previous = adapter->ready_tail;
  if (adapter->ready_tail != NULL) adapter->ready_tail->ready_next = group;
  else adapter->ready_head = group;
  adapter->ready_tail = group;
  group->queued = true;
}

static void ftun_event_backend_batch_finish(ftun_event_backend_group_t *group)
{
  if (group->cursor != NULL) return;
  group->events = group->repeat_events;
  group->repeat_events = 0u;
  if (group->events != 0u) group->cursor = group->watchers;
  if (group->cursor == NULL) ftun_event_backend_ready_unlink(group);
}

static void ftun_event_backend_io_callback(ftun_event_backend_group_t *group, uint32_t events)
{
  group->adapter->collected++;
  if (events == 0u) return;
  /* 同方向的 level readiness 已由当前批次覆盖；只保留新出现的方向，
   * 避免把整批尚未交付的重复通知累积为第二个相同批次。 */
  if (group->queued) group->repeat_events |= events & ~group->events;
  else {
    group->events = events;
    group->cursor = group->watchers;
    ftun_event_backend_ready_append(group);
  }
}

/* 一次访问一个 source，同 FD 与不同 FD 均轮转；业务回调仍由前端派发。 */
static size_t ftun_event_backend_deliver(ftun_event_backend_adapter_t *adapter)
{
  size_t work = 0u;
  while (work < FTUN_EVENT_BACKEND_IO_COLLECT_QUOTA && adapter->ready_head != NULL) {
    ftun_event_backend_group_t *group = adapter->ready_head;
    ftun_event_backend_watcher_t *watcher = group->cursor;
    uint32_t events = group->events;
    ftun_event_backend_ready_unlink(group);
    group->cursor = watcher->next;
    ftun_event_backend_batch_finish(group);
    if (group->cursor != NULL) ftun_event_backend_ready_append(group);
    if ((watcher->interests & (FTUN_EVENT_READ | FTUN_EVENT_WRITE)) != 0u) {
      ftun_event_backend_record(adapter, ftun_event_io_ready(watcher->source, events));
    }
    work++;
  }
  return work;
}

static ftun_status_t ftun_event_backend_watcher_create(ftun_event_backend_adapter_t *adapter,
  ftun_event_backend_group_t *group, ftun_event_backend_watcher_t **out)
{
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_event_backend_watcher_t *watcher;
  ftun_status_t status;
  *out = NULL;
  if (group->first.source == NULL) {
    group->first.group = group;
    *out = &group->first;
    return FTUN_OK;
  }
  if (adapter->budget != NULL) {
    status = ftun_budget_reserve(adapter->budget, sizeof(*watcher), &reservation);
    if (status != FTUN_OK) return status;
  }
  watcher = calloc(1u, sizeof(*watcher));
  if (watcher == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  watcher->reservation = reservation;
  watcher->group = group;
  *out = watcher;
  return FTUN_OK;
}

static void ftun_event_backend_watcher_free(ftun_event_backend_watcher_t *watcher)
{
  ftun_reservation_t reservation = watcher->reservation;
  if (watcher == &watcher->group->first) {
    memset(watcher, 0, sizeof(*watcher));
    return;
  }
  free(watcher);
  (void)ftun_reservation_release(&reservation);
}

static void dirty_remove(ftun_event_backend_group_t *group)
{
  if (!group->dirty) return;
  if (group->dirty_previous) group->dirty_previous->dirty_next = group->dirty_next;
  else group->adapter->dirty = group->dirty_next;
  if (group->dirty_next) group->dirty_next->dirty_previous = group->dirty_previous;
  group->dirty_previous = group->dirty_next = NULL;
  group->dirty = false;
}
static void ftun_event_backend_group_sync(ftun_event_backend_group_t *group)
{
  group->desired_events = (group->readers ? FTUN_POLLER_READ : 0u) |
                          (group->writers ? FTUN_POLLER_WRITE : 0u);
  if (group->dirty || group->desired_events == group->io.events) return;
  group->dirty = true;
  group->dirty_next = group->adapter->dirty;
  if (group->dirty_next) group->dirty_next->dirty_previous = group;
  group->adapter->dirty = group;
}

static void ftun_event_backend_interest_remove(ftun_event_backend_group_t *group, uint32_t interests)
{
  if ((interests & FTUN_EVENT_READ) != 0u) group->readers--;
  if ((interests & FTUN_EVENT_WRITE) != 0u) group->writers--;
}

static void ftun_event_backend_interest_add(ftun_event_backend_group_t *group, uint32_t interests)
{
  if ((interests & FTUN_EVENT_READ) != 0u) group->readers++;
  if ((interests & FTUN_EVENT_WRITE) != 0u) group->writers++;
}

static void ftun_event_backend_group_free(ftun_event_backend_group_t *group)
{
  ftun_reservation_t reservation = group->reservation;
  ftun_event_backend_ready_unlink(group);
  dirty_remove(group);
  ftun_event_backend_record(group->adapter, ftun_poller_update(&group->adapter->poller,
    (ftun_native_socket_t)group->io.fd, group->io.events, 0u, group));
  ftun_event_backend_group_unlink(group);
  free(group);
  (void)ftun_reservation_release(&reservation);
}

static ftun_status_t ftun_event_backend_io_start(void *context, ftun_event_source_t *source,
  ftun_native_socket_t socket, uint32_t interests)
{
  ftun_event_backend_adapter_t *adapter = context;
  ftun_event_backend_watcher_t *watcher;
  ftun_event_backend_group_t *group;
  ftun_status_t status;
  if (socket > (ftun_native_socket_t)INT_MAX) return FTUN_E_INVALID;
  group = ftun_event_backend_group_find(adapter, (int)socket);
  if (group == NULL) {
    ftun_reservation_t reservation = (ftun_reservation_t){0};
    if (adapter->budget != NULL) {
      status = ftun_budget_reserve(adapter->budget, sizeof(*group), &reservation);
      if (status != FTUN_OK) return status;
    }
    group = calloc(1u, sizeof(*group));
    if (group == NULL) {
      (void)ftun_reservation_release(&reservation);
      return FTUN_E_LIMIT;
    }
    group->reservation = reservation;
    group->adapter = adapter;
    group->io.fd = (int)socket;
    ftun_event_backend_group_insert(group);
  }
  status = ftun_event_backend_watcher_create(adapter, group, &watcher);
  if (status != FTUN_OK) {
    if (group->watchers == NULL) ftun_event_backend_group_free(group);
    return status;
  }
  if (ftun_event_source_set_backend_data(source, watcher) != FTUN_OK) {
    ftun_event_backend_watcher_free(watcher);
    if (group->watchers == NULL) ftun_event_backend_group_free(group);
    return FTUN_E_STATE_CORRUPT;
  }
  watcher->adapter = adapter;
  watcher->source = source;
  watcher->group = group;
  watcher->interests = interests;
  /* 头插不改变当前 batch 尚未交付的 next 链，新 source 等下一次 readiness。 */
  watcher->next = group->watchers;
  if (watcher->next != NULL) watcher->next->previous = watcher;
  group->watchers = watcher;
  ftun_event_backend_interest_add(group, interests);
  ftun_event_backend_group_sync(group);
  return FTUN_OK;
}

static ftun_status_t ftun_event_backend_io_update(void *context,
  ftun_event_source_t *source, uint32_t interests)
{
  ftun_event_backend_adapter_t *adapter = context;
  ftun_event_backend_watcher_t *watcher = NULL;
  if (ftun_event_source_backend_data(source, (void **)&watcher) != FTUN_OK ||
      watcher == NULL || watcher->adapter != adapter) return FTUN_E_INVALID;
  ftun_event_backend_interest_remove(watcher->group, watcher->interests);
  watcher->interests = interests;
  ftun_event_backend_interest_add(watcher->group, interests);
  ftun_event_backend_group_sync(watcher->group);
  return FTUN_OK;
}

static ftun_status_t ftun_event_backend_timer_start(void *context,
  ftun_event_source_t *source, uint64_t deadline_ms)
{
  ftun_event_backend_adapter_t *adapter = context;
  (void)deadline_ms;
  /* 每个 timer 只占前端 source/heap 槽，所有期限共享一个 native timer。 */
  return ftun_event_source_set_backend_data(source, &adapter->deadline);
}

static ftun_status_t ftun_event_backend_source_cancel(void *context,
                                              ftun_event_source_t *source)
{
  ftun_event_backend_adapter_t *adapter = (ftun_event_backend_adapter_t *)context;
  ftun_event_backend_watcher_t *watcher = NULL;
  if (ftun_event_source_backend_data(source, (void **)&watcher) != FTUN_OK) return FTUN_E_STATE_CORRUPT;
  if ((void *)watcher == (void *)&adapter->deadline) {
    return ftun_event_source_set_backend_data(source, NULL);
  }
  if (watcher == NULL || watcher->adapter != adapter) return FTUN_E_STATE_CORRUPT;
  {
    ftun_event_backend_group_t *group = watcher->group;
    /* 先解除前端关联；失败时保留 watcher、游标和原有额度。 */
    ftun_status_t status = ftun_event_source_set_backend_data(source, NULL);
    if (status != FTUN_OK) return status;
    if (group->cursor == watcher) group->cursor = watcher->next;
    if (watcher->previous != NULL) watcher->previous->next = watcher->next;
    else group->watchers = watcher->next;
    if (watcher->next != NULL) watcher->next->previous = watcher->previous;
    ftun_event_backend_interest_remove(group, watcher->interests);
    ftun_event_backend_watcher_free(watcher);
    if (group->watchers == NULL) ftun_event_backend_group_free(group);
    else {
      ftun_event_backend_batch_finish(group);
      ftun_event_backend_group_sync(group);
    }
  }
  return FTUN_OK;
}

static void ftun_event_backend_wakeup(void *context)
{
  ftun_event_backend_adapter_t *adapter = context;
  ftun_poller_wakeup(&adapter->poller);
}

static ftun_status_t ftun_event_backend_run_once(void *context, bool block)
{
  ftun_event_backend_adapter_t *adapter = context;
  ftun_poller_event_t events[FTUN_POLLER_CAPACITY];
  uint64_t deadline = 0, now = 0, end = 0;
  size_t count = 0, index, delivered;
  bool present = false;
  int timeout = block ? -1 : 0;
  ftun_status_t status;
  if (adapter->stopped) return FTUN_E_CANCELLED;
  status = ftun_event_loop_next_deadline(adapter->front, &deadline, &present);
  if (status != FTUN_OK) return status;
  status = ftun_monotonic_now(&now);
  if (status != FTUN_OK) return status;
  if (block && present) timeout = deadline <= now ? 0 : deadline - now > INT_MAX ? INT_MAX : (int)(deadline - now);
  if (adapter->ready_head != NULL) timeout = 0;
  adapter->pending_error = FTUN_OK;
  adapter->collected = 0;
  while (adapter->dirty != NULL) {
    ftun_event_backend_group_t *group = adapter->dirty;
    dirty_remove(group);
    status = ftun_poller_update(&adapter->poller, (ftun_native_socket_t)group->io.fd,
      group->io.events, group->desired_events, group);
    if (status != FTUN_OK) return status;
    group->io.events = group->desired_events;
  }
  status = ftun_poller_wait(&adapter->poller, timeout, events, &count);
  if (status != FTUN_OK) return status;
  status = ftun_monotonic_now(&end);
  if (status != FTUN_OK) return status;
  for (index = 0; index < count; index++) ftun_event_backend_io_callback(events[index].user, events[index].events);
  delivered = ftun_event_backend_deliver(adapter);
  ftun_event_loop_backend_report(adapter->front, end - now, adapter->poller.collected + delivered,
    adapter->ready_head != NULL || adapter->poller.collected == FTUN_POLLER_CAPACITY);
  return adapter->pending_error;
}

static void ftun_event_backend_stop(void *context)
{
  ftun_event_backend_adapter_t *adapter = (ftun_event_backend_adapter_t *)context;
  adapter->stopped = 1;
  ftun_event_backend_wakeup(adapter);
}

static void ftun_event_backend_destroy(void *context)
{
  ftun_event_backend_adapter_t *adapter = (ftun_event_backend_adapter_t *)context;
  ftun_reservation_t reservation = adapter->reservation;
  while (adapter->groups != NULL) {
    ftun_event_backend_group_t *group = adapter->groups;
    while (group->watchers != NULL) {
      ftun_event_backend_watcher_t *watcher = group->watchers;
      group->watchers = watcher->next;
      ftun_event_backend_watcher_free(watcher);
    }
    ftun_event_backend_group_free(group);
  }
  ftun_poller_destroy(&adapter->poller);
  free(adapter);
  (void)ftun_reservation_release(&reservation);
}

static const ftun_event_backend_ops_t ftun_event_backend_ops = {
  ftun_event_backend_io_start,
  ftun_event_backend_io_update,
  ftun_event_backend_timer_start,
  ftun_event_backend_source_cancel,
  ftun_event_backend_wakeup,
  ftun_event_backend_run_once,
  ftun_event_backend_stop,
  ftun_event_backend_destroy,
  false
};

/* owner 的通用事件后端，系统等待由 platform/poller 实现。 */
ftun_status_t ftun_event_backend_attach(ftun_event_loop_t *loop)
{
  ftun_event_backend_adapter_t *adapter;
  ftun_budget_t *budget = NULL;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_event_loop_usage_t usage;
  ftun_status_t status;
  if (loop == NULL) return FTUN_E_INVALID;
  status = ftun_event_loop_get_usage(loop, &usage);
  if (status != FTUN_OK) return status;
  if (!usage.accepting || usage.stopped) return FTUN_E_CANCELLED;
  if (usage.backend_attached || usage.source_count != 0u || usage.deferred_count != 0u) {
    return FTUN_E_AGAIN;
  }
  status = ftun_event_loop_budget(loop, &budget);
  if (status != FTUN_OK) return status;
  if (budget != NULL) {
    /* 一个 epoll FD 与一个 eventfd，等待数组位于固定栈帧。 */
    const ftun_budget_resources_t charge = {sizeof(*adapter), 2u, 0u};
    status = ftun_budget_reserve_resources(budget, charge, &reservation);
    if (status != FTUN_OK) return status;
  }
  adapter = calloc(1u, sizeof(*adapter));
  if (adapter == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  adapter->reservation = reservation;
  adapter->budget = budget;
  adapter->front = loop;
  status = ftun_poller_create(&adapter->poller);
  if (status != FTUN_OK) goto failed;
  status = ftun_event_loop_attach_backend(loop, &ftun_event_backend_ops, adapter);
  if (status == FTUN_OK) return FTUN_OK;
  ftun_poller_destroy(&adapter->poller);
failed:
  free(adapter);
  (void)ftun_reservation_release(&reservation);
  return status;
}

ftun_status_t ftun_event_backend_get_info(ftun_event_loop_t *loop, ftun_event_backend_info_t *out)
{
  void *context = NULL;
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (loop == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_event_loop_backend_context(loop, &ftun_event_backend_ops, &context);
  if (status != FTUN_OK) return status;
  out->version_major = 1u;
  out->version_minor = 0u;
  out->backend = "epoll";
  out->async_thread_safe = true;
  return FTUN_OK;
}

ftun_status_t ftun_event_backend_detach(ftun_event_loop_t *loop)
{
  void *context = NULL;
  ftun_status_t status;
  if (loop == NULL) return FTUN_E_INVALID;
  status = ftun_event_loop_backend_context(loop, &ftun_event_backend_ops, &context);
  if (status == FTUN_E_UNSUPPORTED) return FTUN_OK;
  if (status != FTUN_OK) return status;
  (void)context;
  return ftun_event_loop_detach_backend(loop);
}
