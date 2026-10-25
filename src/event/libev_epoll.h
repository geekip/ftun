#ifndef FTUN_EVENT_LIBEV_EPOLL_H
#define FTUN_EVENT_LIBEV_EPOLL_H

#define FTUN_LIBEV_IO_COLLECT_QUOTA 64

/* 仅在编译完整 libev 时强制包含。保留上游源码与 epoll 轮转，限制每次
 * 内核返回的 FD 数；剩余 level-triggered readiness 留到下一轮。 */
#if defined(FTUN_LIBEV_EPOLL_HOOK)
#include <sys/epoll.h>
static inline int ftun_libev_epoll_wait(int fd, struct epoll_event *events,
  int maximum, int timeout)
{
  if (maximum > FTUN_LIBEV_IO_COLLECT_QUOTA) maximum = FTUN_LIBEV_IO_COLLECT_QUOTA;
  return epoll_wait(fd, events, maximum, timeout);
}
#define epoll_wait ftun_libev_epoll_wait
#endif
#endif
