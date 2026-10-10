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

static int ftun_outbound_backend_valid(const ftun_outbound_backend_t *backend)
{
  return backend != NULL && backend->direct_open != NULL &&
         backend->socks5_open != NULL && backend->reject_classify != NULL;
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
  void *context, ftun_core_t *core, const ftun_direct_request_t *request,
  ftun_operation_t **out)
{
  (void)context;
  return ftun_direct_open(core, request, out);
}

static ftun_status_t ftun_outbound_socks5_open(
  void *context, ftun_core_t *core,
  const ftun_socks5_connect_request_t *request, ftun_operation_t **out)
{
  (void)context;
  return ftun_socks5_connect(core, request, out);
}

static ftun_status_t ftun_outbound_reject_classify(
  void *context, const ftun_metadata_t *metadata, bool dns_query,
  ftun_reject_result_t *out)
{
  (void)context;
  return ftun_reject_classify(metadata, dns_query, out);
}

static const ftun_outbound_backend_t ftun_outbound_default_backend = {
  ftun_outbound_direct_open,
  ftun_outbound_socks5_open,
  ftun_outbound_reject_classify,
  NULL
};

/* TASK-OUTBOUND-001 / TEST-OUTBOUND-001，目标 0.2.0：固定叶子分派。 */
ftun_status_t ftun_outbound_open_with_backend(
  ftun_core_t *core, const ftun_outbound_request_t *request,
  const ftun_outbound_backend_t *backend,
  ftun_reject_result_t *reject_result, ftun_operation_t **out)
{
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (reject_result != NULL) memset(reject_result, 0, sizeof(*reject_result));
  if (out == NULL || reject_result == NULL ||
      !ftun_outbound_backend_valid(backend)) return FTUN_E_INVALID;
  status = ftun_outbound_validate(request);
  if (status != FTUN_OK) return status;
  if (request->leaf->kind == FTUN_OUTBOUND_LEAF_DIRECT) {
    ftun_direct_request_t direct;
    if (request->direct == NULL || request->socks5 != NULL ||
        request->metadata != NULL) return FTUN_E_INVALID;
    direct = *request->direct;
    direct.target = request->target;
    direct.transport = request->transport;
    return backend->direct_open(backend->context, core, &direct, out);
  }
  if (request->leaf->kind == FTUN_OUTBOUND_LEAF_SOCKS5) {
    ftun_socks5_connect_request_t socks5;
    if (request->socks5 == NULL || request->direct != NULL ||
        request->metadata != NULL) return FTUN_E_INVALID;
    socks5 = *request->socks5;
    socks5.target = request->target;
    socks5.transport = request->transport;
    return backend->socks5_open(backend->context, core, &socks5, out);
  }
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
  status = backend->reject_classify(backend->context, request->metadata,
                                    false, reject_result);
  if (status != FTUN_OK) return status;
  if (reject_result->terminal_status != FTUN_E_REJECTED ||
      (reject_result->action != FTUN_REJECT_TCP_REFUSE &&
       reject_result->action != FTUN_REJECT_UDP_DROP)) {
    memset(reject_result, 0, sizeof(*reject_result));
    return FTUN_E_STATE_CORRUPT;
  }
  return FTUN_E_REJECTED;
}

ftun_status_t ftun_outbound_open(ftun_core_t *core,
                                  const ftun_outbound_request_t *request,
                                  ftun_reject_result_t *reject_result,
                                  ftun_operation_t **out)
{
  return ftun_outbound_open_with_backend(core, request,
                                         &ftun_outbound_default_backend,
                                         reject_result, out);
}
