#include "platform/poller.h"
#include "platform/socket.h"
#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>

/* 固定上游单文件仅在本编译单元内使用；分配入口注入宿主预算，不改子模块。
 * 除wakeup外的wepoll调用均由owner串行执行；线程局部绑定隔离不同后端。 */
static __thread const ftun_poller_memory_t *active_memory;
static void *wepoll_allocate(size_t bytes);
static void wepoll_release(void *memory);
#define WEPOLL_EXPORT static __attribute__((unused))
#define malloc wepoll_allocate
#define free wepoll_release
#include <wepoll.c>
#undef malloc
#undef free
#undef WEPOLL_EXPORT

/* 上游1.5.8的port与poll_group分别拥有一个IOCP/AFD句柄；sock只有内存。
 * epoll_wait固定64项，低于上游256项栈容量，不经过动态完成数组分支。 */
typedef char allocation_sizes_distinct[(sizeof(port_state_t) != sizeof(poll_group_t) &&
  sizeof(port_state_t) != sizeof(sock_state_t) && sizeof(poll_group_t) != sizeof(sock_state_t)) ? 1 : -1];
static void *wepoll_allocate(size_t bytes)
{
  size_t descriptors = bytes == sizeof(port_state_t) || bytes == sizeof(poll_group_t) ? 1u : 0u;
  return active_memory->allocate(active_memory->context, bytes, descriptors);
}
static void wepoll_release(void *memory)
{
  active_memory->release(active_memory->context, memory);
}

typedef struct wait_registration wait_registration_t;
typedef struct {
  HANDLE port;
  ftun_handle_t wakeup[2];
  ftun_poller_memory_t memory;
  wait_registration_t *wait_head, *wait_tail, *wait_cursor;
  size_t wait_count;
} native_poller_t;
typedef char native_fits[(sizeof(native_poller_t) <= sizeof(((ftun_poller_t *)0)->native)) ? 1 : -1];
static INIT_ONCE global_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK initialize(PINIT_ONCE once, void *parameter, void **context)
{
  (void)once; (void)parameter; (void)context;
  /* 发布上游全局初始化，避免多个owner首次创建时竞争其非原子init__done。 */
  return init() == 0;
}
static ftun_status_t error_status(void)
{
  DWORD error = GetLastError();
  return error == ERROR_NOT_ENOUGH_MEMORY || error == ERROR_NO_SYSTEM_RESOURCES ||
    error == ERROR_TOO_MANY_OPEN_FILES ? FTUN_E_LIMIT : FTUN_E_IO;
}
ftun_status_t ftun_poller_create(ftun_poller_t *poller, ftun_poller_memory_t memory)
{
  native_poller_t *native = (void *)&poller->native;
  native->port = NULL;
  native->wakeup[0] = native->wakeup[1] = -1;
  native->memory = memory;
  native->wait_head = native->wait_tail = native->wait_cursor = NULL;
  native->wait_count = 0u;
  /* 固定额度覆盖TCP对构造峰值3和上游进程级keyed event的保守份额1。
   * IOCP/AFD句柄额度随对应动态分配单独准入，实际释放后归还。 */
  if (!InitOnceExecuteOnce(&global_once, initialize, NULL, NULL)) return error_status();
  ftun_status_t status = ftun_socket_pair(native->wakeup);
  if (status != FTUN_OK) return status;
  active_memory = &native->memory;
  native->port = epoll_create1(0);
  if (native->port == NULL) status = error_status();
  else {
    struct epoll_event wake = {.events = EPOLLIN, .data.ptr = NULL};
    if (epoll_ctl(native->port, EPOLL_CTL_ADD, (SOCKET)native->wakeup[0], &wake) != 0) status = error_status();
  }
  active_memory = NULL;
  if (status != FTUN_OK) ftun_poller_destroy(poller);
  return status;
}
/* Wintun交付自动复位的等待事件；回调只记录就绪并唤醒owner，不读写设备。 */
struct wait_registration {
  wait_registration_t *previous, *next;
  ftun_poller_t *poller;
  ftun_poller_io_t *io;
  void *user;
  PTP_WAIT wait;
  volatile LONG pending, armed;
};
static void CALLBACK wait_ready(PTP_CALLBACK_INSTANCE instance, void *context, PTP_WAIT wait, TP_WAIT_RESULT result)
{
  wait_registration_t *node = context;
  (void)instance; (void)wait; (void)result;
  InterlockedExchange(&node->pending, 1);
  InterlockedExchange(&node->armed, 0);
  ftun_poller_wakeup(node->poller);
}
static ftun_status_t wait_update(ftun_poller_t *poller, ftun_poller_io_t *io, uint32_t interests, void *user)
{
  native_poller_t *native = (void *)&poller->native;
  wait_registration_t *node = io->registration;
  if (interests & FTUN_POLLER_WRITE) return FTUN_E_UNSUPPORTED;
  if (interests == 0u) {
    if (node == NULL) return FTUN_OK;
    SetThreadpoolWait(node->wait, NULL, NULL);
    WaitForThreadpoolWaitCallbacks(node->wait, TRUE);
    CloseThreadpoolWait(node->wait);
    if (node->previous != NULL) node->previous->next = node->next;
    else native->wait_head = node->next;
    if (node->next != NULL) node->next->previous = node->previous;
    else native->wait_tail = node->previous;
    if (native->wait_cursor == node) native->wait_cursor = node->next;
    native->wait_count--;
    native->memory.release(native->memory.context, node);
    io->registration = NULL;
    return FTUN_OK;
  }
  if (node == NULL) {
    node = native->memory.allocate(native->memory.context, sizeof(*node), 1u);
    if (node == NULL) return FTUN_E_LIMIT;
    memset(node, 0, sizeof(*node));
    node->poller = poller; node->io = io; node->user = user;
    node->wait = CreateThreadpoolWait(wait_ready, node, NULL);
    if (node->wait == NULL) {
      native->memory.release(native->memory.context, node);
      return FTUN_E_LIMIT;
    }
    node->previous = native->wait_tail;
    if (native->wait_tail != NULL) native->wait_tail->next = node;
    else native->wait_head = node;
    native->wait_tail = node;
    native->wait_count++;
    io->registration = node;
  }
  if ((interests & FTUN_POLLER_READ) == 0u) {
    SetThreadpoolWait(node->wait, NULL, NULL);
    WaitForThreadpoolWaitCallbacks(node->wait, TRUE);
    InterlockedExchange(&node->pending, 0);
    InterlockedExchange(&node->armed, 0);
  }
  return FTUN_OK;
}
ftun_status_t ftun_poller_update(ftun_poller_t *poller, ftun_poller_io_t *io,
  uint32_t interests, void *user)
{
  native_poller_t *native = (void *)&poller->native;
  if (io->events == interests) return FTUN_OK;
  if (io->kind == FTUN_POLLER_WAITABLE) return wait_update(poller, io, interests, user);
  struct epoll_event event = {.data.ptr = user};
  if (interests & FTUN_POLLER_READ) event.events |= EPOLLIN;
  if (interests & FTUN_POLLER_WRITE) event.events |= EPOLLOUT;
  int operation = interests == 0u ? EPOLL_CTL_DEL : io->events == 0u ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
  active_memory = &native->memory;
  int result = epoll_ctl(native->port, operation, (SOCKET)io->socket, &event);
  ftun_status_t status = result == 0 ? FTUN_OK : error_status();
  active_memory = NULL;
  return status;
}
ftun_status_t ftun_poller_wait(ftun_poller_t *poller, int timeout_ms,
  ftun_poller_event_t events[FTUN_POLLER_CAPACITY], size_t *count)
{
  native_poller_t *native = (void *)&poller->native;
  struct epoll_event ready[FTUN_POLLER_CAPACITY];
  bool signaled = false;
  for (wait_registration_t *node = native->wait_head; node != NULL; node = node->next) {
    if ((node->io->events & FTUN_POLLER_READ) == 0u) continue;
    DWORD result = WaitForSingleObject((HANDLE)node->io->socket, 0u);
    if (result == WAIT_FAILED) return FTUN_E_IO;
    if (result == WAIT_OBJECT_0) InterlockedExchange(&node->pending, 1);
    if (InterlockedCompareExchange(&node->pending, 0, 0) != 0) signaled = true;
    else if (InterlockedCompareExchange(&node->armed, 1, 0) == 0)
      SetThreadpoolWait(node->wait, (HANDLE)node->io->socket, NULL);
  }
  size_t reserved = native->wait_count > FTUN_POLLER_CAPACITY / 2u ? FTUN_POLLER_CAPACITY / 2u : native->wait_count;
  active_memory = &native->memory;
  int length = epoll_wait(native->port, ready, (int)(FTUN_POLLER_CAPACITY - reserved), signaled ? 0 : timeout_ms);
  ftun_status_t status = length < 0 ? error_status() : FTUN_OK;
  active_memory = NULL;
  *count = 0u;
  poller->collected = length > 0 ? (size_t)length : 0u;
  if (status != FTUN_OK) return status;
  for (int i = 0; i < length; i++) {
    uint32_t flags = ready[i].events;
    if (ready[i].data.ptr == NULL) {
      char bytes[256];
      int result = recv((SOCKET)native->wakeup[0], bytes, sizeof(bytes), 0);
      if (result <= 0 && WSAGetLastError() != WSAEWOULDBLOCK) return FTUN_E_IO;
      continue;
    }
    events[*count].user = ready[i].data.ptr;
    events[*count].events = ((flags & (EPOLLIN | EPOLLHUP | EPOLLERR)) ? FTUN_POLLER_READ : 0u) |
      ((flags & (EPOLLOUT | EPOLLHUP | EPOLLERR)) ? FTUN_POLLER_WRITE : 0u);
    (*count)++;
  }
  wait_registration_t *node = native->wait_cursor != NULL ? native->wait_cursor : native->wait_head;
  for (size_t visited = 0u, collected = 0u; visited < native->wait_count && collected < reserved; visited++) {
    wait_registration_t *next = node->next != NULL ? node->next : native->wait_head;
    if ((node->io->events & FTUN_POLLER_READ) != 0u && InterlockedExchange(&node->pending, 0) != 0) {
      events[*count] = (ftun_poller_event_t){node->user, FTUN_POLLER_READ};
      (*count)++; collected++; poller->collected++;
    }
    node = next;
  }
  native->wait_cursor = node;
  return FTUN_OK;
}
void ftun_poller_wakeup(ftun_poller_t *poller)
{
  native_poller_t *native = (void *)&poller->native;
  const char byte = 1;
  (void)send((SOCKET)native->wakeup[1], &byte, 1, 0);
}
void ftun_poller_destroy(ftun_poller_t *poller)
{
  native_poller_t *native = (void *)&poller->native;
  while (native->wait_head != NULL) {
    wait_registration_t *node = native->wait_head;
    if (wait_update(poller, node->io, 0u, NULL) != FTUN_OK) abort();
  }
  if (native->port != NULL) {
    active_memory = &native->memory;
    if (epoll_close(native->port) != 0) abort();
    active_memory = NULL;
    native->port = NULL;
  }
  if (native->wakeup[0] >= 0) (void)ftun_socket_close((ftun_native_socket_t)native->wakeup[0]);
  if (native->wakeup[1] >= 0) (void)ftun_socket_close((ftun_native_socket_t)native->wakeup[1]);
  native->wakeup[0] = native->wakeup[1] = -1;
}
