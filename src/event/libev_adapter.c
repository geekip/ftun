#include "libev_adapter.h"
#include "event/event.h"
#include "event/libev_epoll.h"
#include "core/budget.h"
#include "util/time.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#if defined(FTUN_HAVE_LIBEV)
#include <signal.h>
#include <errno.h>
#include <sys/eventfd.h>
#include <unistd.h>
/* libev 允许调用方提供跨线程原子类型；Linux 构建使用编译器原子扩展，
 * 避免默认 volatile sig_atomic_t 在 C 内存模型下形成数据竞态。 */
#define EV_ATOMIC_T _Atomic sig_atomic_t
#include <ev.h>
#undef EV_ATOMIC_T

typedef struct ftun_libev_watcher ftun_libev_watcher_t;
typedef struct ftun_libev_group ftun_libev_group_t;

typedef struct {
  ftun_event_loop_t *front;
  struct ev_loop *loop;
  ev_io wakeup;
  ev_timer deadline;
  uint64_t armed_deadline_ms;
  uint64_t wait_started_ms;
  uint64_t wait_ms;
  size_t collected;
  int wakeup_fd;
  ftun_budget_t *budget;
  ftun_reservation_t *reservation;
  ftun_libev_group_t *groups;
  ftun_libev_group_t *ready_head;
  ftun_libev_group_t *ready_tail;
  ftun_status_t pending_error;
  int stopped;
} ftun_libev_adapter_t;

struct ftun_libev_watcher {
  ftun_libev_adapter_t *adapter;
  ftun_libev_group_t *group;
  ftun_libev_watcher_t *previous;
  ftun_libev_watcher_t *next;
  ftun_event_source_t *source;
  ftun_reservation_t *reservation;
  uint32_t interests;
};

/* 每 FD 一个 native watcher；source 仍分别拥有兴趣、取消和前端句柄。
 * AVL 索引使新增/查找/移除不随其他 FD 线性扫描。ready 链与成员游标
 * 都嵌入已准入对象，不为重复通知分配节点，也不重启尚未完成的批次。 */
struct ftun_libev_group {
  ftun_libev_adapter_t *adapter;
  ftun_reservation_t *reservation;
  ftun_libev_group_t *left;
  ftun_libev_group_t *right;
  ftun_libev_group_t *parent;
  ftun_libev_group_t *ready_previous;
  ftun_libev_group_t *ready_next;
  ftun_libev_watcher_t *watchers;
  ftun_libev_watcher_t *cursor;
  size_t readers;
  size_t writers;
  uint32_t events;
  uint32_t repeat_events;
  int height;
  bool queued;
  ev_io io;
  /* 大多数 FD 只有一个 source，共享组直接拥有首个成员及其额度。 */
  ftun_libev_watcher_t first;
};

static void ftun_libev_record(ftun_libev_adapter_t *adapter, ftun_status_t status)
{
  if (status != FTUN_OK && adapter->pending_error == FTUN_OK) {
    adapter->pending_error = status;
  }
}

static int ftun_libev_height(const ftun_libev_group_t *group)
{
  return group == NULL ? 0 : group->height;
}

static void ftun_libev_refresh(ftun_libev_group_t *group)
{
  int left = ftun_libev_height(group->left), right = ftun_libev_height(group->right);
  group->height = 1 + (left > right ? left : right);
}

static void ftun_libev_replace(ftun_libev_adapter_t *adapter,
  ftun_libev_group_t *old, ftun_libev_group_t *replacement)
{
  if (old->parent == NULL) adapter->groups = replacement;
  else if (old->parent->left == old) old->parent->left = replacement;
  else old->parent->right = replacement;
  if (replacement != NULL) replacement->parent = old->parent;
}

static ftun_libev_group_t *ftun_libev_rotate(ftun_libev_group_t *group, bool left)
{
  ftun_libev_group_t *pivot = left ? group->right : group->left;
  ftun_libev_replace(group->adapter, group, pivot);
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
  ftun_libev_refresh(group);
  ftun_libev_refresh(pivot);
  return pivot;
}

static void ftun_libev_rebalance(ftun_libev_group_t *group)
{
  while (group != NULL) {
    int balance;
    ftun_libev_refresh(group);
    balance = ftun_libev_height(group->left) - ftun_libev_height(group->right);
    if (balance > 1) {
      if (ftun_libev_height(group->left->left) < ftun_libev_height(group->left->right)) {
        (void)ftun_libev_rotate(group->left, true);
      }
      group = ftun_libev_rotate(group, false);
    } else if (balance < -1) {
      if (ftun_libev_height(group->right->right) < ftun_libev_height(group->right->left)) {
        (void)ftun_libev_rotate(group->right, false);
      }
      group = ftun_libev_rotate(group, true);
    }
    group = group->parent;
  }
}

static ftun_libev_group_t *ftun_libev_group_find(ftun_libev_adapter_t *adapter, int fd)
{
  ftun_libev_group_t *group = adapter->groups;
  while (group != NULL && group->io.fd != fd) group = fd < group->io.fd ? group->left : group->right;
  return group;
}

static void ftun_libev_group_insert(ftun_libev_group_t *group)
{
  ftun_libev_group_t **place = &group->adapter->groups, *parent = NULL;
  while (*place != NULL) {
    parent = *place;
    place = group->io.fd < parent->io.fd ? &parent->left : &parent->right;
  }
  *place = group;
  group->parent = parent;
  group->height = 1;
  ftun_libev_rebalance(parent);
}

static void ftun_libev_group_unlink(ftun_libev_group_t *group)
{
  ftun_libev_group_t *repair;
  if (group->left != NULL && group->right != NULL) {
    ftun_libev_group_t *successor = group->right;
    while (successor->left != NULL) successor = successor->left;
    if (successor->parent == group) repair = successor;
    else {
      repair = successor->parent;
      ftun_libev_replace(group->adapter, successor, successor->right);
      successor->right = group->right;
      successor->right->parent = successor;
    }
    ftun_libev_replace(group->adapter, group, successor);
    successor->left = group->left;
    successor->left->parent = successor;
  } else {
    repair = group->parent;
    ftun_libev_replace(group->adapter, group, group->left != NULL ? group->left : group->right);
  }
  ftun_libev_rebalance(repair);
}

static void ftun_libev_ready_unlink(ftun_libev_group_t *group)
{
  ftun_libev_adapter_t *adapter = group->adapter;
  if (!group->queued) return;
  if (group->ready_previous != NULL) group->ready_previous->ready_next = group->ready_next;
  else adapter->ready_head = group->ready_next;
  if (group->ready_next != NULL) group->ready_next->ready_previous = group->ready_previous;
  else adapter->ready_tail = group->ready_previous;
  group->ready_previous = group->ready_next = NULL;
  group->queued = false;
}

static void ftun_libev_ready_append(ftun_libev_group_t *group)
{
  ftun_libev_adapter_t *adapter = group->adapter;
  if (group->queued) return;
  group->ready_previous = adapter->ready_tail;
  if (adapter->ready_tail != NULL) adapter->ready_tail->ready_next = group;
  else adapter->ready_head = group;
  adapter->ready_tail = group;
  group->queued = true;
}

static void ftun_libev_batch_finish(ftun_libev_group_t *group)
{
  if (group->cursor != NULL) return;
  group->events = group->repeat_events;
  group->repeat_events = 0u;
  if (group->events != 0u) group->cursor = group->watchers;
  if (group->cursor == NULL) ftun_libev_ready_unlink(group);
}

static void ftun_libev_io_callback(EV_P_ ev_io *io, int revents)
{
  ftun_libev_group_t *group = io->data;
  uint32_t events = 0u;
  (void)loop;
  if ((revents & EV_READ) != 0) events |= FTUN_EVENT_READ;
  if ((revents & EV_WRITE) != 0) events |= FTUN_EVENT_WRITE;
  if ((revents & EV_ERROR) != 0) events |= FTUN_EVENT_ERROR;
  group->adapter->collected++;
  if (events == 0u) return;
  /* 同方向的 level readiness 已由当前批次覆盖；只保留新出现的方向，
   * 避免把整批尚未交付的重复通知累积为第二个相同批次。 */
  if (group->queued) group->repeat_events |= events & ~group->events;
  else {
    group->events = events;
    group->cursor = group->watchers;
    ftun_libev_ready_append(group);
  }
}

/* 一次访问一个 source，同 FD 与不同 FD 均轮转；业务回调仍由前端派发。 */
static size_t ftun_libev_deliver(ftun_libev_adapter_t *adapter)
{
  size_t work = 0u;
  while (work < FTUN_LIBEV_IO_COLLECT_QUOTA && adapter->ready_head != NULL) {
    ftun_libev_group_t *group = adapter->ready_head;
    ftun_libev_watcher_t *watcher = group->cursor;
    uint32_t events = group->events;
    ftun_libev_ready_unlink(group);
    group->cursor = watcher->next;
    ftun_libev_batch_finish(group);
    if (group->cursor != NULL) ftun_libev_ready_append(group);
    if ((watcher->interests & (FTUN_EVENT_READ | FTUN_EVENT_WRITE)) != 0u) {
      ftun_libev_record(adapter, ftun_event_io_ready(watcher->source, events));
    }
    work++;
  }
  return work;
}

static void ftun_libev_deadline_callback(EV_P_ ev_timer *timer, int revents)
{
  ftun_libev_adapter_t *adapter = timer->data;
  (void)loop;
  (void)revents;
  /* 到期项由前端堆按配额取出；原生层只产生一个唤醒。 */
  adapter->collected++;
}

static void ftun_libev_release(EV_P)
{
  ftun_libev_adapter_t *adapter = ev_userdata(loop);
  ftun_libev_record(adapter, ftun_monotonic_now(&adapter->wait_started_ms));
}

static void ftun_libev_acquire(EV_P)
{
  ftun_libev_adapter_t *adapter = ev_userdata(loop);
  uint64_t now_ms = 0u;
  ftun_status_t status = ftun_monotonic_now(&now_ms);
  ftun_libev_record(adapter, status);
  if (status == FTUN_OK && now_ms >= adapter->wait_started_ms) {
    adapter->wait_ms += now_ms - adapter->wait_started_ms;
  }
}

static void ftun_libev_wakeup_callback(EV_P_ ev_io *io, int revents)
{
  ftun_libev_adapter_t *adapter = io->data;
  uint64_t count;
  ssize_t result;
  (void)loop;
  adapter->collected++;
  if ((revents & EV_ERROR) != 0) {
    ftun_libev_record(adapter, FTUN_E_IO);
    return;
  }
  do { result = read(adapter->wakeup_fd, &count, sizeof(count)); }
  while (result < 0 && errno == EINTR);
  if (result != (ssize_t)sizeof(count) && !(result < 0 && errno == EAGAIN)) {
    ftun_libev_record(adapter, FTUN_E_IO);
  }
}

static ftun_status_t ftun_libev_watcher_create(ftun_libev_adapter_t *adapter,
  ftun_libev_group_t *group, ftun_libev_watcher_t **out)
{
  ftun_reservation_t *reservation = NULL;
  ftun_libev_watcher_t *watcher;
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

static void ftun_libev_watcher_free(ftun_libev_watcher_t *watcher)
{
  ftun_reservation_t *reservation = watcher->reservation;
  if (watcher == &watcher->group->first) {
    memset(watcher, 0, sizeof(*watcher));
    return;
  }
  free(watcher);
  (void)ftun_reservation_release(&reservation);
}

static void ftun_libev_group_sync(ftun_libev_group_t *group)
{
  int events = (group->readers != 0u ? EV_READ : 0) | (group->writers != 0u ? EV_WRITE : 0);
  if (events == group->io.events && (events == 0 || ev_is_active(&group->io))) return;
  ev_io_stop(group->adapter->loop, &group->io);
  if (events != 0) {
    /* FD身份未变，只更新兴趣；保留初次注册标记，不强制重复ADD。 */
    ev_io_modify(&group->io, events);
    ev_io_start(group->adapter->loop, &group->io);
  } else ev_io_modify(&group->io, EV_READ);
}

static void ftun_libev_interest_remove(ftun_libev_group_t *group, uint32_t interests)
{
  if ((interests & FTUN_EVENT_READ) != 0u) group->readers--;
  if ((interests & FTUN_EVENT_WRITE) != 0u) group->writers--;
}

static void ftun_libev_interest_add(ftun_libev_group_t *group, uint32_t interests)
{
  if ((interests & FTUN_EVENT_READ) != 0u) group->readers++;
  if ((interests & FTUN_EVENT_WRITE) != 0u) group->writers++;
}

static void ftun_libev_group_free(ftun_libev_group_t *group)
{
  ftun_reservation_t *reservation = group->reservation;
  ftun_libev_ready_unlink(group);
  ev_io_stop(group->adapter->loop, &group->io);
  ftun_libev_group_unlink(group);
  free(group);
  (void)ftun_reservation_release(&reservation);
}

static ftun_status_t ftun_libev_io_start(void *context, ftun_event_source_t *source,
  ftun_native_socket_t socket, uint32_t interests)
{
  ftun_libev_adapter_t *adapter = context;
  ftun_libev_watcher_t *watcher;
  ftun_libev_group_t *group;
  ftun_status_t status;
  if (socket > (ftun_native_socket_t)INT_MAX) return FTUN_E_INVALID;
  group = ftun_libev_group_find(adapter, (int)socket);
  if (group == NULL) {
    ftun_reservation_t *reservation = NULL;
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
    ev_io_init(&group->io, ftun_libev_io_callback, (int)socket, EV_READ);
    group->io.data = group;
    ftun_libev_group_insert(group);
  }
  status = ftun_libev_watcher_create(adapter, group, &watcher);
  if (status != FTUN_OK) {
    if (group->watchers == NULL) ftun_libev_group_free(group);
    return status;
  }
  if (ftun_event_source_set_backend_data(source, watcher) != FTUN_OK) {
    ftun_libev_watcher_free(watcher);
    if (group->watchers == NULL) ftun_libev_group_free(group);
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
  ftun_libev_interest_add(group, interests);
  ftun_libev_group_sync(group);
  return FTUN_OK;
}

static ftun_status_t ftun_libev_io_update(void *context,
  ftun_event_source_t *source, uint32_t interests)
{
  ftun_libev_adapter_t *adapter = context;
  ftun_libev_watcher_t *watcher = NULL;
  if (ftun_event_source_backend_data(source, (void **)&watcher) != FTUN_OK ||
      watcher == NULL || watcher->adapter != adapter) return FTUN_E_INVALID;
  ftun_libev_interest_remove(watcher->group, watcher->interests);
  watcher->interests = interests;
  ftun_libev_interest_add(watcher->group, interests);
  ftun_libev_group_sync(watcher->group);
  return FTUN_OK;
}

static ftun_status_t ftun_libev_timer_start(void *context,
  ftun_event_source_t *source, uint64_t deadline_ms)
{
  ftun_libev_adapter_t *adapter = context;
  (void)deadline_ms;
  /* 每个 timer 只占前端 source/heap 槽，所有期限共享一个 native timer。 */
  return ftun_event_source_set_backend_data(source, &adapter->deadline);
}

static ftun_status_t ftun_libev_source_cancel(void *context,
                                              ftun_event_source_t *source)
{
  ftun_libev_adapter_t *adapter = (ftun_libev_adapter_t *)context;
  ftun_libev_watcher_t *watcher = NULL;
  if (ftun_event_source_backend_data(source, (void **)&watcher) != FTUN_OK) return FTUN_E_STATE_CORRUPT;
  if ((void *)watcher == (void *)&adapter->deadline) {
    return ftun_event_source_set_backend_data(source, NULL);
  }
  if (watcher == NULL || watcher->adapter != adapter) return FTUN_E_STATE_CORRUPT;
  {
    ftun_libev_group_t *group = watcher->group;
    /* 先解除前端关联；失败时保留 watcher、游标和原有额度。 */
    ftun_status_t status = ftun_event_source_set_backend_data(source, NULL);
    if (status != FTUN_OK) return status;
    if (group->cursor == watcher) group->cursor = watcher->next;
    if (watcher->previous != NULL) watcher->previous->next = watcher->next;
    else group->watchers = watcher->next;
    if (watcher->next != NULL) watcher->next->previous = watcher->previous;
    ftun_libev_interest_remove(group, watcher->interests);
    ftun_libev_watcher_free(watcher);
    if (group->watchers == NULL) ftun_libev_group_free(group);
    else {
      ftun_libev_batch_finish(group);
      ftun_libev_group_sync(group);
    }
  }
  return FTUN_OK;
}

static void ftun_libev_wakeup(void *context)
{
  ftun_libev_adapter_t *adapter = (ftun_libev_adapter_t *)context;
  const uint64_t one = 1u;
  ssize_t result;
  /* 非阻塞 eventfd 满时已有未读通知；静默前 FD 始终由 adapter 保留。 */
  do { result = write(adapter->wakeup_fd, &one, sizeof(one)); }
  while (result < 0 && errno == EINTR);
}

static ftun_status_t ftun_libev_run_once(void *context, bool block)
{
  ftun_libev_adapter_t *adapter = (ftun_libev_adapter_t *)context;
  if (adapter->stopped) return FTUN_E_CANCELLED;
  uint64_t deadline_ms = 0u, now_ms = 0u;
  bool present = false;
  ftun_status_t status = ftun_event_loop_next_deadline(adapter->front, &deadline_ms, &present);
  if (status != FTUN_OK) return status;
  if (!present) ev_timer_stop(adapter->loop, &adapter->deadline);
  else if (!ev_is_active(&adapter->deadline) || deadline_ms != adapter->armed_deadline_ms) {
    status = ftun_monotonic_now(&now_ms);
    if (status != FTUN_OK) return status;
    ev_now_update(adapter->loop);
    ev_timer_stop(adapter->loop, &adapter->deadline);
    ev_timer_set(&adapter->deadline,
      deadline_ms > now_ms ? (ev_tstamp)(deadline_ms - now_ms) / 1000.0 : 0.0, 0.0);
    adapter->armed_deadline_ms = deadline_ms;
    ev_timer_start(adapter->loop, &adapter->deadline);
  }
  adapter->pending_error = FTUN_OK;
  adapter->wait_ms = 0u;
  adapter->collected = 0u;
  if (adapter->ready_head != NULL) block = false;
  (void)ev_run(adapter->loop, block ? EVRUN_ONCE : EVRUN_NOWAIT);
  {
    size_t delivered = ftun_libev_deliver(adapter);
    ftun_event_loop_backend_report(adapter->front, adapter->wait_ms,
      adapter->collected + delivered, adapter->ready_head != NULL ||
      adapter->collected >= FTUN_LIBEV_IO_COLLECT_QUOTA);
  }
  return adapter->pending_error;
}

static void ftun_libev_stop(void *context)
{
  ftun_libev_adapter_t *adapter = (ftun_libev_adapter_t *)context;
  adapter->stopped = 1;
  ev_break(adapter->loop, EVBREAK_ALL);
  ftun_libev_wakeup(adapter);
}

static void ftun_libev_destroy(void *context)
{
  ftun_libev_adapter_t *adapter = (ftun_libev_adapter_t *)context;
  ftun_reservation_t *reservation = adapter->reservation;
  while (adapter->groups != NULL) {
    ftun_libev_group_t *group = adapter->groups;
    while (group->watchers != NULL) {
      ftun_libev_watcher_t *watcher = group->watchers;
      group->watchers = watcher->next;
      ftun_libev_watcher_free(watcher);
    }
    ftun_libev_group_free(group);
  }
  ev_timer_stop(adapter->loop, &adapter->deadline);
  ev_io_stop(adapter->loop, &adapter->wakeup);
  ev_loop_destroy(adapter->loop);
  (void)close(adapter->wakeup_fd);
  adapter->front = NULL;
  adapter->loop = NULL;
  free(adapter);
  (void)ftun_reservation_release(&reservation);
}

static const ftun_event_backend_ops_t ftun_libev_ops = {
  ftun_libev_io_start,
  ftun_libev_io_update,
  ftun_libev_timer_start,
  ftun_libev_source_cancel,
  ftun_libev_wakeup,
  ftun_libev_run_once,
  ftun_libev_stop,
  ftun_libev_destroy,
  false
};

/* 完整 libev 4.33 epoll 适配。 */
ftun_status_t ftun_libev_attach(ftun_event_loop_t *loop)
{
  ftun_libev_adapter_t *adapter;
  ftun_budget_t *budget = NULL;
  ftun_reservation_t *reservation = NULL;
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
    /* 一个 epoll FD 与一个自有 eventfd；不启用 libev 的隐式 async pipe。
     * libev 原生数组/allocator 开销不包含在第一方对象的精确字节中。 */
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
  adapter->wakeup_fd = eventfd(0u, EFD_NONBLOCK | EFD_CLOEXEC);
  if (adapter->wakeup_fd < 0) {
    status = (errno == EMFILE || errno == ENFILE || errno == ENOMEM) ? FTUN_E_LIMIT : FTUN_E_IO;
    goto failed;
  }
  adapter->loop = ev_loop_new(EVFLAG_NOENV | EVBACKEND_EPOLL);
  if (adapter->loop == NULL || ev_backend(adapter->loop) != EVBACKEND_EPOLL) {
    status = adapter->loop == NULL && (errno == EMFILE || errno == ENFILE || errno == ENOMEM)
      ? FTUN_E_LIMIT : FTUN_E_UNSUPPORTED;
    goto failed;
  }
  ev_set_userdata(adapter->loop, adapter);
  ev_set_loop_release_cb(adapter->loop, ftun_libev_release, ftun_libev_acquire);
  ev_timer_init(&adapter->deadline, ftun_libev_deadline_callback, 0.0, 0.0);
  adapter->deadline.data = adapter;
  ev_io_init(&adapter->wakeup, ftun_libev_wakeup_callback, adapter->wakeup_fd, EV_READ);
  adapter->wakeup.data = adapter;
  ev_io_start(adapter->loop, &adapter->wakeup);
  status = ftun_event_loop_attach_backend(loop, &ftun_libev_ops, adapter);
  if (status == FTUN_OK) return FTUN_OK;
  ev_io_stop(adapter->loop, &adapter->wakeup);
failed:
  if (adapter->loop != NULL) ev_loop_destroy(adapter->loop);
  if (adapter->wakeup_fd >= 0) (void)close(adapter->wakeup_fd);
  free(adapter);
  (void)ftun_reservation_release(&reservation);
  return status;
}

ftun_status_t ftun_libev_get_info(ftun_event_loop_t *loop, ftun_libev_info_t *out)
{
  void *context = NULL;
  ftun_status_t status;
  int version_major;
  int version_minor;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (loop == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_event_loop_backend_context(loop, &ftun_libev_ops, &context);
  if (status != FTUN_OK) return status;
  version_major = ev_version_major();
  version_minor = ev_version_minor();
  if (version_major < 0 || version_minor < 0) return FTUN_E_STATE_CORRUPT;
  out->version_major = (unsigned int)version_major;
  out->version_minor = (unsigned int)version_minor;
  out->backend = "epoll";
  out->async_thread_safe = true;
  return FTUN_OK;
}

ftun_status_t ftun_libev_detach(ftun_event_loop_t *loop)
{
  void *context = NULL;
  ftun_status_t status;
  if (loop == NULL) return FTUN_E_INVALID;
  status = ftun_event_loop_backend_context(loop, &ftun_libev_ops, &context);
  if (status == FTUN_E_UNSUPPORTED) return FTUN_OK;
  if (status != FTUN_OK) return status;
  (void)context;
  return ftun_event_loop_detach_backend(loop);
}

#else

ftun_status_t ftun_libev_attach(ftun_event_loop_t *loop)
{
  return loop == NULL ? FTUN_E_INVALID : FTUN_E_UNSUPPORTED;
}

ftun_status_t ftun_libev_get_info(ftun_event_loop_t *loop, ftun_libev_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  return loop == NULL || out == NULL ? FTUN_E_INVALID : FTUN_E_UNSUPPORTED;
}

ftun_status_t ftun_libev_detach(ftun_event_loop_t *loop)
{
  return loop == NULL ? FTUN_E_INVALID : FTUN_OK;
}

#endif
