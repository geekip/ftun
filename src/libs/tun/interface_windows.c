#include "libs/tun/interface_backend.h"
#include "platform/tun_config.h"
#include "core/limits.h"
#include <stdlib.h>

typedef struct {
  ftun_reservation_t reservation;
} interface_state_t;
static ftun_status_t restore(void *context, const ftun_interface_spec_t *spec, void **out)
{
  interface_state_t *state;
  ftun_reservation_t reservation = {0};
  ftun_status_t status;
  if (spec == NULL || out == NULL || *out != NULL) return FTUN_E_INVALID;
  size_t bytes = sizeof(*state) + ftun_platform_tun_config_size();
  status = spec->budget == NULL ? FTUN_OK : ftun_budget_reserve(spec->budget, bytes, &reservation);
  if (status != FTUN_OK) return status;
  state = calloc(1u, bytes);
  if (state == NULL) { ftun_reservation_release(&reservation); return FTUN_E_LIMIT; }
  state->reservation = reservation;
  *out = state; /* 部分安装失败仍由 owner 持有并撤销。 */
  return ftun_platform_tun_configure(state + 1, context, spec->name, spec->mtu,
    spec->addresses, spec->address_count);
}
static ftun_status_t withdraw(void *context, void **out)
{
  interface_state_t *state = *out;
  ftun_status_t status;
  if (state == NULL) return FTUN_OK;
  status = ftun_platform_tun_unconfigure(state + 1, context);
  if (status != FTUN_OK) return status;
  ftun_reservation_release(&state->reservation);
  free(state);
  *out = NULL;
  return FTUN_OK;
}
const ftun_interface_ops_t ftun_interface_default_ops = {restore, withdraw, NULL, {0}, true};
