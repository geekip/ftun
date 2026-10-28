#include "outbound.h"

#include <string.h>

static int ftun_outbound_endpoint_equal(const ftun_endpoint_t *left,
                                        const ftun_endpoint_t *right)
{
  if (left->kind != right->kind || left->port != right->port) return 0;
  if (left->kind == FTUN_ADDRESS_IPV4) {
    return memcmp(left->address, right->address, 4u) == 0;
  }
  if (left->kind == FTUN_ADDRESS_DOMAIN) {
    return left->domain.data != NULL && right->domain.data != NULL &&
           left->domain.length == right->domain.length &&
           memcmp(left->domain.data, right->domain.data,
                  left->domain.length) == 0;
  }
  return 0;
}

static ftun_status_t ftun_outbound_validate(
  const ftun_outbound_request_t *request)
{
  size_t index;
  if (request == NULL || request->route == NULL || request->target == NULL ||
      request->leaf == NULL || request->route->kind != FTUN_ROUTE_READY ||
      request->route->generation == 0u || request->target->generation == 0u ||
      request->leaf->generation == 0u ||
      (request->transport != FTUN_DIAL_TCP &&
       request->transport != FTUN_DIAL_UDP) ||
      (request->route->allowed_count != 0u &&
       request->route->allowed == NULL) ||
      (request->target->allowed_count != 0u &&
       request->target->allowed == NULL)) return FTUN_E_INVALID;
  if (request->route->generation != request->target->generation ||
      request->route->generation != request->leaf->generation) {
    return FTUN_E_STALE;
  }
  if (request->route->outbound_id != request->leaf->id) {
    return FTUN_E_STALE;
  }
  if (request->route->allowed_count != request->target->allowed_count) {
    return FTUN_E_REJECTED;
  }
  for (index = 0u; index < request->route->allowed_count; index++) {
    if (!ftun_outbound_endpoint_equal(&request->route->allowed[index],
                                      &request->target->allowed[index])) {
      return FTUN_E_REJECTED;
    }
  }
  if ((request->transport == FTUN_DIAL_TCP &&
       !request->leaf->supports_tcp) ||
      (request->transport == FTUN_DIAL_UDP &&
       !request->leaf->supports_udp)) return FTUN_E_UNSUPPORTED;
  if (request->leaf->kind < FTUN_OUTBOUND_LEAF_DIRECT ||
      request->leaf->kind > FTUN_OUTBOUND_LEAF_GROUP) return FTUN_E_INVALID;
  if (request->leaf->kind == FTUN_OUTBOUND_LEAF_GROUP) {
    return FTUN_E_UNSUPPORTED;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_outbound_direct_open(
  void *context, ftun_core_t *core, const void *request, ftun_operation_t **out)
{
  (void)context;
  return ftun_direct_open(core, (const ftun_direct_request_t *)request, out);
}

static ftun_status_t ftun_outbound_socks5_open(
  void *context, ftun_core_t *core, const void *request, ftun_operation_t **out)
{
  (void)context;
  return ftun_socks5_connect(core, (const ftun_socks5_connect_request_t *)request,
                             out);
}

static const ftun_connector_registry_t ftun_outbound_registry = {
  {
    {"direct", FTUN_CONNECTOR_TCP | FTUN_CONNECTOR_UDP,
     ftun_outbound_direct_open, NULL},
    {"socks5", FTUN_CONNECTOR_TCP | FTUN_CONNECTOR_UDP | FTUN_CONNECTOR_DOMAIN_TARGET,
     ftun_outbound_socks5_open, NULL}
  },
  2u
};

const ftun_connector_registry_t *ftun_outbound_default_registry(void)
{
  return &ftun_outbound_registry;
}

/* 叶子类型对应的 Connector 名字；REJECT 与组不是 Connector。 */
static const char *ftun_outbound_connector_kind(ftun_outbound_leaf_kind_t kind)
{
  return kind == FTUN_OUTBOUND_LEAF_DIRECT ? "direct" :
         kind == FTUN_OUTBOUND_LEAF_SOCKS5 ? "socks5" : NULL;
}

/* 固定叶子分派。 */
ftun_status_t ftun_outbound_open_with_registry(
  ftun_core_t *core, const ftun_outbound_request_t *request,
  const ftun_connector_registry_t *registry,
  ftun_reject_result_t *reject_result, ftun_operation_t **out)
{
  const ftun_connector_ops_t *connector;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (reject_result != NULL) memset(reject_result, 0, sizeof(*reject_result));
  if (out == NULL || reject_result == NULL || registry == NULL) {
    return FTUN_E_INVALID;
  }
  status = ftun_outbound_validate(request);
  if (status != FTUN_OK) return status;
  if (request->leaf->kind == FTUN_OUTBOUND_LEAF_REJECT) {
    if (request->direct != NULL || request->socks5 != NULL ||
        request->metadata == NULL ||
        request->metadata->generation != request->route->generation) {
      return request->metadata != NULL &&
             request->metadata->generation != request->route->generation ?
             FTUN_E_STALE : FTUN_E_INVALID;
    }
    if ((request->metadata->known_fields & FTUN_META_NETWORK) == 0u ||
        request->metadata->network !=
          (request->transport == FTUN_DIAL_TCP ? 1u : 2u)) {
      return FTUN_E_INVALID;
    }
    status = ftun_reject_classify(request->metadata, false, reject_result);
    return status != FTUN_OK ? status : FTUN_E_REJECTED;
  }
  connector = ftun_connector_lookup(registry,
    ftun_outbound_connector_kind(request->leaf->kind));
  if (connector == NULL ||
      (request->transport == FTUN_DIAL_TCP &&
       (connector->capabilities & FTUN_CONNECTOR_TCP) == 0u) ||
      (request->transport == FTUN_DIAL_UDP &&
       (connector->capabilities & FTUN_CONNECTOR_UDP) == 0u)) {
    return FTUN_E_UNSUPPORTED;
  }
  if (request->leaf->kind == FTUN_OUTBOUND_LEAF_DIRECT) {
    ftun_direct_request_t direct;
    if (request->direct == NULL || request->socks5 != NULL ||
        request->metadata != NULL) return FTUN_E_INVALID;
    direct = *request->direct;
    direct.target = request->target;
    direct.transport = request->transport;
    return connector->open(connector->context, core, &direct, out);
  } else {
    ftun_socks5_connect_request_t socks5;
    if (request->socks5 == NULL || request->direct != NULL ||
        request->metadata != NULL) return FTUN_E_INVALID;
    socks5 = *request->socks5;
    socks5.target = request->target;
    socks5.transport = request->transport;
    return connector->open(connector->context, core, &socks5, out);
  }
}

ftun_status_t ftun_outbound_open(ftun_core_t *core,
                                  const ftun_outbound_request_t *request,
                                  ftun_reject_result_t *reject_result,
                                  ftun_operation_t **out)
{
  return ftun_outbound_open_with_registry(core, request,
    ftun_outbound_default_registry(), reject_result, out);
}
