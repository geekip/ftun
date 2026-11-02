#include "libs/transport/netmon.h"
#include <string.h>

/* 在真实owner路径注入有界批次，不修改宿主接口、路由或网络命名空间。 */
ftun_status_t __wrap_ftun_netmon_take(ftun_netmon_t *netmon, uint64_t now,
  ftun_network_change_t *out)
{
  static unsigned batches;
  (void)netmon; (void)now;
  if (batches > 100u) return FTUN_E_AGAIN;
  memset(out, 0, sizeof(*out));
  out->events = 1u;
  out->mask = FTUN_NETWORK_CHANGE_OVERFLOW;
  out->storm = batches++ < 100u;
  return FTUN_OK;
}
