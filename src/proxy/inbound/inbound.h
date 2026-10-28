#ifndef FTUN_PROXY_INBOUND_INBOUND_H
#define FTUN_PROXY_INBOUND_INBOUND_H

#include "core/budget.h"
#include "tun/device.h"

typedef enum {
  FTUN_INBOUND_MIXED = 1,
  FTUN_INBOUND_SOCKS5,
  FTUN_INBOUND_TUN
} ftun_inbound_kind_t;

typedef struct {
  ftun_bytes_t username;
  ftun_bytes_t password;
} ftun_inbound_user_t;

struct ftun_inbound_spec {
  ftun_budget_t *budget;
  ftun_inbound_kind_t kind;
  uint64_t generation;
  uint32_t id;
  ftun_string_t name;
  uint32_t fixed_outbound_id;
  bool tcp;
  bool udp;
  ftun_endpoint_t listen;
  const ftun_inbound_user_t *users; /* prepare 期间同步借用。 */
  size_t user_count;
  ftun_tun_spec_t tun;
};

#endif
