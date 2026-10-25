#include "proxy/dns/resolver_adapter.h"

#if defined(FTUN_HAVE_MODULE_DNS)
#include "dns/dispatcher.h"
#endif

#include <string.h>

static int ftun_resolver_backend_valid(const ftun_resolver_backend_t *backend)
{
  return backend != NULL && backend->system_resolve != NULL &&
         backend->bootstrap_resolve != NULL && backend->server_resolve != NULL;
}

static int ftun_resolver_string_equal(ftun_string_t left,
                                      ftun_string_t right)
{
  return left.data != NULL && right.data != NULL &&
         left.length == right.length &&
         memcmp(left.data, right.data, left.length) == 0;
}

static int ftun_resolver_name_valid(ftun_string_t name)
{
  size_t index;
  if (name.length == 0u) return 1;
  if (name.data == NULL || name.length > 255u ||
      memchr(name.data, '\0', name.length) != NULL) return 0;
  for (index = 0u; index < name.length; index++) {
    unsigned char byte = (unsigned char)name.data[index];
    if (byte == (unsigned char)',' || byte <= 0x1fu || byte == 0x7fu) {
      return 0;
    }
  }
  return 1;
}

static int ftun_resolver_domain_valid(ftun_string_t domain)
{
  size_t effective;
  size_t start = 0u;
  size_t index;
  size_t dots = 0u;
  int only_digits_and_dots = 1;
  if (domain.data == NULL || domain.length == 0u ||
      domain.length > FTUN_SYSTEM_RESOLVER_MAX_DOMAIN_BYTES ||
      memchr(domain.data, '\0', domain.length) != NULL) return 0;
  effective = domain.length;
  if (domain.data[effective - 1u] == '.') effective--;
  if (effective == 0u || effective > 253u) return 0;
  for (index = 0u; index < effective; index++) {
    unsigned char byte = (unsigned char)domain.data[index];
    if (byte == '.') dots++;
    else if (byte < (unsigned char)'0' || byte > (unsigned char)'9') {
      only_digits_and_dots = 0;
    }
  }
  if (only_digits_and_dots && dots == 3u) return 0;
  for (index = 0u; index <= effective; index++) {
    if (index == effective || domain.data[index] == '.') {
      size_t label_length = index - start;
      size_t label_index;
      if (label_length == 0u || label_length > 63u ||
          domain.data[start] == '-' || domain.data[index - 1u] == '-') return 0;
      for (label_index = start; label_index < index; label_index++) {
        unsigned char byte = (unsigned char)domain.data[label_index];
        if (!((byte >= (unsigned char)'A' && byte <= (unsigned char)'Z') ||
              (byte >= (unsigned char)'a' && byte <= (unsigned char)'z') ||
              (byte >= (unsigned char)'0' && byte <= (unsigned char)'9') ||
              byte == (unsigned char)'-')) return 0;
      }
      start = index + 1u;
    }
  }
  return 1;
}

static ftun_status_t ftun_resolver_validate(
  const ftun_resolve_request_t *request)
{
  const ftun_metadata_t *metadata = NULL;
  ftun_session_info_t info;
  ftun_string_t identity;
  ftun_status_t status;
  if (request == NULL || request->session == NULL ||
      request->query.budget == NULL || request->query.completion == NULL ||
      !ftun_resolver_domain_valid(request->query.domain) ||
      !ftun_resolver_name_valid(request->default_server)) {
    return FTUN_E_INVALID;
  }
  status = ftun_session_get_info(request->session, &info);
  if (status != FTUN_OK) return status;
  if (info.state != FTUN_SESSION_ROUTING || info.route_pinned ||
      info.has_pending_operation) return FTUN_E_STALE;
  status = ftun_session_get_metadata(request->session, &metadata);
  if (status != FTUN_OK) return status;
  if (metadata->resolved_count != 0u ||
      (metadata->original_target.kind == FTUN_ADDRESS_IPV4 &&
       !metadata->original_is_fake)) return FTUN_E_STALE;
  memset(&identity, 0, sizeof(identity));
  if ((metadata->known_fields & FTUN_META_DOMAIN) != 0u) {
    identity = metadata->domain;
  } else if (metadata->original_target.kind == FTUN_ADDRESS_DOMAIN) {
    identity = metadata->original_target.domain;
  }
  if (!ftun_resolver_string_equal(identity, request->query.domain)) {
    return FTUN_E_INVALID;
  }
  return FTUN_OK;
}

/* TASK-DNS-005 / TEST-DNS-005，目标 0.2.0：路由前 REAL 来源选择。 */
ftun_status_t ftun_resolve_real_with_backend(
  ftun_core_t *core, const ftun_resolve_request_t *request,
  const ftun_resolver_backend_t *backend, ftun_operation_t **out)
{
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (out == NULL || !ftun_resolver_backend_valid(backend)) {
    return FTUN_E_INVALID;
  }
  status = ftun_resolver_validate(request);
  if (status != FTUN_OK) return status;
  if (!request->dns_enabled) {
    ftun_system_resolve_request_t system;
    memset(&system, 0, sizeof(system));
    system.worker = request->query.worker;
    system.budget = request->query.budget;
    system.domain = request->query.domain;
    system.protection = request->query.protection;
    system.deadline_ms = request->query.deadline_ms;
    system.check_path = request->query.check_system_path;
    system.path_user = request->query.system_path_user;
    system.completion = request->query.completion;
    system.user = request->query.user;
    return backend->system_resolve(backend->context, core, &system, out);
  }
  if (request->default_server.length == 0u) {
    return backend->bootstrap_resolve(backend->context, core,
                                      &request->query, out);
  }
  return backend->server_resolve(backend->context, core,
                                  request->default_server,
                                  &request->query, out);
}

ftun_status_t ftun_proxy_dns_resolve_with_provider(
  ftun_core_t *core, ftun_resolver_scope_t *scope, bool dns_enabled,
  ftun_string_t default_server, const ftun_bootstrap_request_t *query,
  ftun_dial_purpose_t purpose, ftun_operation_t **out)
{
  ftun_resolver_provider_request_t request = {0};
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (core == NULL || scope == NULL || query == NULL || out == NULL ||
      !ftun_resolver_name_valid(default_server)) return FTUN_E_INVALID;
  status = ftun_resolver_scope_generation(scope, &request.generation);
  if (status != FTUN_OK) return status;
  request.system.worker = query->worker;
  request.system.budget = query->budget;
  request.system.domain = query->domain;
  request.system.protection = query->protection;
  request.system.deadline_ms = query->deadline_ms;
  request.system.check_path = query->check_system_path;
  request.system.path_user = query->system_path_user;
  request.system.completion = query->completion;
  request.system.user = query->user;
  request.purpose = purpose;
  request.requested_domain = FTUN_DIAL_DOMAIN_UNDERLAY;
  request.loop = query->loop;
  request.operations = query->operations;
  request.network_view = query->network_view;
  request.network_generation = query->network_generation;
  request.query_id = query->query_id;
  if (!dns_enabled) request.source = FTUN_RESOLVER_SYSTEM;
  else if (default_server.length != 0u) {
    request.source = FTUN_RESOLVER_NAMED;
    request.resolver_name = default_server;
  } else {
    request.source = FTUN_RESOLVER_BOOTSTRAP;
    request.servers = query->servers;
    request.server_count = query->server_count;
  }
  return ftun_resolver_scope_start(scope, core, &request, out);
}

ftun_status_t ftun_resolve_real_with_provider(ftun_core_t *core,
  const ftun_resolve_request_t *request, ftun_resolver_scope_t *scope,
  ftun_operation_t **out)
{
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (out == NULL) return FTUN_E_INVALID;
  status = ftun_resolver_validate(request);
  return status == FTUN_OK ? ftun_proxy_dns_resolve_with_provider(core, scope,
    request->dns_enabled, request->default_server, &request->query,
    FTUN_DIAL_PURPOSE_BUSINESS, out) : status;
}
