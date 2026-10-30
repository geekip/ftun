#include "platform/poller.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/event.h>
#include <unistd.h>

typedef struct { int descriptor; } native_poller_t;
static ftun_status_t error_status(void)
{
  return errno == EMFILE || errno == ENFILE || errno == ENOMEM ? FTUN_E_LIMIT : FTUN_E_IO;
}
ftun_status_t ftun_poller_create(ftun_poller_t *poller, ftun_poller_memory_t memory)
{
  (void)memory;
  native_poller_t *native = (void *)&poller->native;
  struct kevent event;
  native->descriptor = kqueue();
  if (native->descriptor < 0) return error_status();
  if (fcntl(native->descriptor, F_SETFD, FD_CLOEXEC) != 0) {
    ftun_status_t status = error_status();
    ftun_poller_destroy(poller);
    return status;
  }
  EV_SET(&event, 1u, EVFILT_USER, EV_ADD | EV_CLEAR, 0u, 0, NULL);
  if (kevent(native->descriptor, &event, 1, NULL, 0, NULL) == 0) return FTUN_OK;
  ftun_status_t status = error_status();
  ftun_poller_destroy(poller);
  return status;
}
ftun_status_t ftun_poller_update(ftun_poller_t *poller, ftun_poller_io_t *io,
  uint32_t interests, void *user)
{
  if (io->kind == FTUN_POLLER_WAITABLE) return FTUN_E_UNSUPPORTED;
  native_poller_t *native = (void *)&poller->native;
  ftun_native_socket_t fd = io->socket;
  uint32_t previous = io->events;
  struct kevent changes[2];
  int count = 0;
  const uint32_t bits[] = {FTUN_POLLER_READ, FTUN_POLLER_WRITE};
  const short filters[] = {EVFILT_READ, EVFILT_WRITE};
  for (size_t i = 0u; i < 2u; i++) {
    if ((previous & bits[i]) == (interests & bits[i])) continue;
    EV_SET(&changes[count], fd, filters[i],
      (interests & bits[i]) != 0u ? EV_ADD : EV_DELETE, 0u, 0, user);
    count++;
  }
  for (int i = 0; i < count; i++) {
    if (kevent(native->descriptor, &changes[i], 1, NULL, 0, NULL) == 0) continue;
    ftun_status_t status = error_status();
    /* 两个filter不是原子批次；第二项失败时撤销第一项，避免悬空udata。 */
    if (i != 0) {
      changes[0].flags = (changes[0].flags & EV_ADD) != 0 ? EV_DELETE : EV_ADD;
      if (kevent(native->descriptor, changes, 1, NULL, 0, NULL) != 0) abort();
    }
    return status;
  }
  return FTUN_OK;
}
ftun_status_t ftun_poller_wait(ftun_poller_t *poller, int timeout_ms,
  ftun_poller_event_t events[FTUN_POLLER_CAPACITY], size_t *count)
{
  native_poller_t *native = (void *)&poller->native;
  struct kevent ready[FTUN_POLLER_CAPACITY];
  struct timespec timeout = {timeout_ms < 0 ? 0 : timeout_ms / 1000,
    timeout_ms < 0 ? 0 : (timeout_ms % 1000) * 1000000L};
  int length = kevent(native->descriptor, NULL, 0, ready, FTUN_POLLER_CAPACITY,
    timeout_ms < 0 ? NULL : &timeout);
  *count = 0u;
  poller->collected = length > 0 ? (size_t)length : 0u;
  if (length < 0) return errno == EINTR ? FTUN_OK : error_status();
  for (int i = 0; i < length; i++) {
    if (ready[i].filter == EVFILT_USER) continue;
    events[*count].user = ready[i].udata;
    events[*count].events = (ready[i].filter == EVFILT_READ ? FTUN_POLLER_READ : FTUN_POLLER_WRITE);
    if ((ready[i].flags & (EV_EOF | EV_ERROR)) != 0u)
      events[*count].events |= FTUN_POLLER_READ | FTUN_POLLER_WRITE;
    (*count)++;
  }
  return FTUN_OK;
}
void ftun_poller_wakeup(ftun_poller_t *poller)
{
  native_poller_t *native = (void *)&poller->native;
  struct kevent event;
  EV_SET(&event, 1u, EVFILT_USER, 0u, NOTE_TRIGGER, 0, NULL);
  (void)kevent(native->descriptor, &event, 1, NULL, 0, NULL);
}
void ftun_poller_destroy(ftun_poller_t *poller)
{
  native_poller_t *native = (void *)&poller->native;
  if (native->descriptor >= 0) close(native->descriptor);
  native->descriptor = -1;
}
