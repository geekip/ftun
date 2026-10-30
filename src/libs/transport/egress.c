#include "libs/transport/egress.h"
#include "libs/transport/socket_path.h"

#include <assert.h>
#include <string.h>

static const char ftun_egress_direct_name[] = "DIRECT";

static void ftun_egress_direct_info(uint64_t generation, ftun_egress_info_t *out)
{
  out->id = FTUN_EGRESS_DIRECT;
  out->capabilities = FTUN_EGRESS_CAP_STREAM | FTUN_EGRESS_CAP_DATAGRAM;
  out->state = FTUN_EGRESS_STATE_AVAILABLE;
  out->configuration_generation = generation;
  out->provider_kind = "direct";
}

static ftun_status_t ftun_egress_direct_resolve(const void *context,
  const ftun_config_t *config, ftun_string_t name, ftun_egress_info_t *out)
{
  (void)context;
  (void)config;
  memset(out, 0, sizeof(*out));
  if (name.length != sizeof(ftun_egress_direct_name) - 1u ||
      memcmp(name.data, ftun_egress_direct_name, name.length) != 0) {
    return FTUN_E_REJECTED;
  }
  ftun_egress_direct_info(0u, out);
  return FTUN_OK;
}

static ftun_status_t ftun_egress_direct_query(const void *context,
  ftun_egress_id_t egress, uint64_t configuration_generation,
  ftun_egress_info_t *out)
{
  (void)context;
  memset(out, 0, sizeof(*out));
  if (egress != FTUN_EGRESS_DIRECT) return FTUN_E_REJECTED;
  ftun_egress_direct_info(configuration_generation, out);
  return FTUN_OK;
}

static ftun_status_t ftun_egress_direct_open(void *context, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *result_spec,
  ftun_operation_t **out)
{
  (void)context;
  *out = NULL;
  if (request->egress != FTUN_EGRESS_DIRECT) return FTUN_E_REJECTED;
  return ftun_socket_path_open(NULL, core, request, result_spec, out);
}

static ftun_status_t direct_validate(const void *context, uint32_t root,
  uint32_t leaf, uint64_t generation)
{
  (void)context; (void)generation;
  return root == FTUN_EGRESS_DIRECT && leaf == root ? FTUN_OK : FTUN_E_REJECTED;
}

static const ftun_egress_provider_t ftun_egress_direct = {
  ftun_egress_direct_resolve,
  ftun_egress_direct_query,
  ftun_egress_direct_open,
  NULL, NULL, NULL, direct_validate
};

void ftun_egress_retain(const ftun_egress_provider_t *provider)
{
  if (provider != NULL && provider->retain != NULL) provider->retain(provider->context);
}

void ftun_egress_release(const ftun_egress_provider_t **provider)
{
  const ftun_egress_provider_t *owned = *provider;
  *provider = NULL;
  if (owned != NULL && owned->release != NULL) owned->release(owned->context);
}

const ftun_egress_provider_t *ftun_egress_direct_provider(void)
{
  return &ftun_egress_direct;
}

ftun_status_t ftun_egress_path_open(void *context, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *result_spec,
  ftun_operation_t **out)
{
  const ftun_egress_provider_t *provider = (const ftun_egress_provider_t *)context;
  assert(provider != NULL && provider->open != NULL);
  return provider->open(provider->context, core, request, result_spec, out);
}

bool ftun_egress_supports(const ftun_egress_info_t *info,
                          ftun_dial_transport_t transport)
{
  uint32_t need = transport == FTUN_DIAL_TCP
    ? FTUN_EGRESS_CAP_STREAM : FTUN_EGRESS_CAP_DATAGRAM;
  return (info->capabilities & need) != 0u &&
         info->state != FTUN_EGRESS_STATE_UNAVAILABLE;
}
