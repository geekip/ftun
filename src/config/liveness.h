#ifndef FTUN_CONFIG_LIVENESS_H
#define FTUN_CONFIG_LIVENESS_H
#include "config/model.h"
#include "network/socket_policy.h"

/* 把 base.timeouts 转成套接字存活策略；各业务据此给自己创建/接纳的 TCP socket 设置。 */
static inline ftun_socket_liveness_t ftun_config_socket_liveness(
  const ftun_config_t *config)
{
  ftun_socket_liveness_t liveness = {0};
  if (config == NULL) return liveness;
  liveness.keepalive_enabled = config->base.timeouts.keepalive.enabled;
  liveness.idle_s = config->base.timeouts.keepalive.idle_s;
  liveness.interval_s = config->base.timeouts.keepalive.interval_s;
  liveness.count = config->base.timeouts.keepalive.count;
  liveness.user_timeout_ms = config->base.timeouts.write_progress_ms;
  return liveness;
}
#endif
