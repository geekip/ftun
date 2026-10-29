#include "platform/poller.h"

/* kqueue 的编译替换边界。新平台运行能力尚未实现，构造必须明确拒绝，
 * 不能向 Core 交付一个看似可用的后端；Linux 产品继续使用 epoll。 */
ftun_status_t ftun_poller_create(ftun_poller_t *poller)
{
  poller->descriptor = poller->wakeup = -1;
  poller->collected = 0u;
  return FTUN_E_UNSUPPORTED;
}
ftun_status_t ftun_poller_update(ftun_poller_t *poller, ftun_native_socket_t socket,
  uint32_t previous, uint32_t interests, void *user)
{
  (void)poller; (void)socket; (void)previous; (void)interests; (void)user;
  return FTUN_E_UNSUPPORTED;
}
ftun_status_t ftun_poller_wait(ftun_poller_t *poller, int timeout_ms,
  ftun_poller_event_t events[FTUN_POLLER_CAPACITY], size_t *count)
{
  (void)poller; (void)timeout_ms; (void)events;
  *count = 0u;
  return FTUN_E_UNSUPPORTED;
}
void ftun_poller_wakeup(ftun_poller_t *poller) { (void)poller; }
void ftun_poller_destroy(ftun_poller_t *poller) { (void)poller; }
