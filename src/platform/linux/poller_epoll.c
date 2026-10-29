#include "platform/poller.h"
#include <errno.h>
#include <limits.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

static ftun_status_t error_status(void)
{
  return errno == EMFILE || errno == ENFILE || errno == ENOMEM ? FTUN_E_LIMIT : FTUN_E_IO;
}
ftun_status_t ftun_poller_create(ftun_poller_t *poller)
{
  struct epoll_event event = {0};
  poller->wakeup = -1;
  poller->descriptor = epoll_create1(EPOLL_CLOEXEC);
  if (poller->descriptor < 0) return error_status();
  poller->wakeup = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
  event.events = EPOLLIN;
  if (poller->wakeup < 0 || epoll_ctl(poller->descriptor, EPOLL_CTL_ADD, poller->wakeup, &event) < 0) {
    ftun_status_t status = error_status();
    ftun_poller_destroy(poller);
    return status;
  }
  return FTUN_OK;
}
ftun_status_t ftun_poller_update(ftun_poller_t *poller, ftun_native_socket_t fd,
  uint32_t previous, uint32_t interests, void *user)
{
  struct epoll_event event = {0};
  int operation;
  if (fd > INT_MAX) return FTUN_E_INVALID;
  if (previous == interests) return FTUN_OK;
  event.data.ptr = user;
  if (interests & FTUN_POLLER_READ) event.events |= EPOLLIN;
  if (interests & FTUN_POLLER_WRITE) event.events |= EPOLLOUT;
  operation = interests == 0 ? EPOLL_CTL_DEL : previous == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
  if (epoll_ctl(poller->descriptor, operation, (int)fd, &event) == 0) return FTUN_OK;
  return error_status();
}
ftun_status_t ftun_poller_wait(ftun_poller_t *poller, int timeout_ms,
  ftun_poller_event_t events[FTUN_POLLER_CAPACITY], size_t *count)
{
  struct epoll_event ready[FTUN_POLLER_CAPACITY];
  int index, length = epoll_wait(poller->descriptor, ready, FTUN_POLLER_CAPACITY, timeout_ms);
  *count = 0;
  poller->collected = length > 0 ? (size_t)length : 0;
  if (length < 0) return errno == EINTR ? FTUN_OK : error_status();
  for (index = 0; index < length; index++) {
    uint32_t flags = ready[index].events;
    if (ready[index].data.ptr == NULL) {
      uint64_t value;
      ssize_t result;
      do { result = read(poller->wakeup, &value, sizeof(value)); } while (result < 0 && errno == EINTR);
      if (result != sizeof(value) && !(result < 0 && errno == EAGAIN)) return FTUN_E_IO;
      continue;
    }
    events[*count].user = ready[index].data.ptr;
    events[*count].events = ((flags & (EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR)) ? FTUN_POLLER_READ : 0u) |
      ((flags & (EPOLLOUT | EPOLLHUP | EPOLLERR)) ? FTUN_POLLER_WRITE : 0u);
    (*count)++;
  }
  return FTUN_OK;
}
void ftun_poller_wakeup(ftun_poller_t *poller)
{
  const uint64_t one = 1;
  ssize_t result;
  do { result = write(poller->wakeup, &one, sizeof(one)); } while (result < 0 && errno == EINTR);
  /* EAGAIN 表示已有未消费唤醒，FD 的寿命由 owner 保证。 */
}
void ftun_poller_destroy(ftun_poller_t *poller)
{
  if (poller->wakeup >= 0) close(poller->wakeup);
  if (poller->descriptor >= 0) close(poller->descriptor);
  poller->descriptor = poller->wakeup = -1;
}
