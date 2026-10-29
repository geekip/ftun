#ifndef FTUN_PROXY_FAKEIP_STORE_INTERNAL_H
#define FTUN_PROXY_FAKEIP_STORE_INTERNAL_H

#include "proxy/fakeip/store.h"

ftun_status_t ftun_fakeip_store_snapshot_state(
  ftun_fakeip_store_t *store, const char **path, ftun_budget_t **budget,
  ftun_fakeip_store_info_t *info);
ftun_status_t ftun_fakeip_store_submit_snapshot(
  ftun_fakeip_store_t *store, ftun_bytes_t contents, uint64_t sequence,
  ftun_operation_t **out);

#endif
