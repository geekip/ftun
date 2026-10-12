#include "resolver.h"

#if defined(FTUN_HAVE_MODULE_DNS)
#include "dns/dns.h"
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

static ftun_status_t ftun_resolver_system(
  void *context, ftun_core_t *core,
  const ftun_system_resolve_request_t *request, ftun_operation_t **out)
{
  (void)context;
  return ftun_system_resolve(core, request, out);
}

static ftun_status_t ftun_resolver_bootstrap(
  void *context, ftun_core_t *core,
  const ftun_bootstrap_request_t *request, ftun_operation_t **out)
{
  (void)context;
#if defined(FTUN_HAVE_MODULE_DNS)
  return ftun_bootstrap_resolve(core, request, out);
#else
  (void)core;
  (void)request;
  if (out != NULL) *out = NULL;
  return FTUN_E_UNSUPPORTED;
#endif
}

static ftun_status_t ftun_resolver_server(
  void *context, ftun_core_t *core, ftun_string_t server,
  const ftun_bootstrap_request_t *request, ftun_operation_t **out)
{
  (void)context;
#if defined(FTUN_HAVE_MODULE_DNS)
  return ftun_dns_resolve_named(core, server, request, out);
#else
  (void)core;
  (void)server;
  (void)request;
  if (out != NULL) *out = NULL;
  return FTUN_E_UNSUPPORTED;
#endif
}

static const ftun_resolver_backend_t ftun_resolver_default_backend = {
  ftun_resolver_system,
  ftun_resolver_bootstrap,
  ftun_resolver_server,
  NULL
};

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

ftun_status_t ftun_resolve_real(ftun_core_t *core,
                                const ftun_resolve_request_t *request,
                                ftun_operation_t **out)
{
  return ftun_resolve_real_with_backend(core, request,
                                         &ftun_resolver_default_backend, out);
}
