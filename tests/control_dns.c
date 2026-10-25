#define _POSIX_C_SOURCE 200809L
#include "proxy/http_fetch.h"
#include "transport/socket_path.h"
#include "util/time.h"

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned int system_calls, path_calls, resolver_calls;

int __real_getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **);
int __wrap_getaddrinfo(const char *node, const char *service,
  const struct addrinfo *hints, struct addrinfo **out)
{
  system_calls++;
  return __real_getaddrinfo(node, service, hints, out);
}

static ftun_status_t test_path_open(void *context, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *spec,
  ftun_operation_t **out)
{
  path_calls++;
  if (spec->configuration_generation != 7u ||
      spec->purpose != FTUN_DIAL_PURPOSE_FRS_UPDATE ||
      request->dial.endpoint.kind != FTUN_ADDRESS_IPV4 ||
      memcmp(request->dial.endpoint.address, "\177\0\0\1", 4u) != 0) return FTUN_E_REJECTED;
  fprintf(stderr, "path generation=7 purpose=%u transport=%u port=%u\n",
    (unsigned)spec->purpose, (unsigned)request->dial.transport,
    (unsigned)request->dial.endpoint.port);
  return ftun_socket_path_open(context, core, request, spec, out);
}

ftun_status_t __real_ftun_resolver_provider_start(ftun_resolver_provider_t *,
  ftun_core_t *, const ftun_resolver_provider_request_t *, ftun_operation_t **);
ftun_status_t __wrap_ftun_resolver_provider_start(ftun_resolver_provider_t *provider,
  ftun_core_t *core, const ftun_resolver_provider_request_t *request, ftun_operation_t **out)
{
  resolver_calls++;
  if (request->generation != 7u || request->purpose != FTUN_DIAL_PURPOSE_FRS_UPDATE) return FTUN_E_INVALID;
  fprintf(stderr, "resolver generation=7 source=%u\n", (unsigned)request->source);
  return __real_ftun_resolver_provider_start(provider, core, request, out);
}

int main(int argc, char **argv)
{
  ftun_budget_t *budget = NULL;
  ftun_http_fetch_spec_t spec = {0};
  ftun_http_fetch_result_t result;
  ftun_budget_usage_t before, after;
  char bootstrap[2048], domain[FTUN_CONTROL_ENDPOINT_TEXT_BYTES];
  char *entry;
  uint64_t now;
  ftun_status_t status;
  if ((argc != 8 && argc != 9) || strlen(argv[3]) >= sizeof(spec.resolver.upstream) ||
      strlen(argv[4]) >= sizeof(spec.resolver.proxy) || strlen(argv[5]) >= sizeof(bootstrap)) return 2;
  if (ftun_budget_create(NULL, 8u * 1024u * 1024u, 128u, &budget) != FTUN_OK ||
      ftun_budget_get_usage(budget, &before) != FTUN_OK || ftun_monotonic_now(&now) != FTUN_OK) return 3;
  spec.budget = budget;
  spec.allow_system_resolver = argc == 8 || atoi(argv[8]) != 0;
  spec.path.open = test_path_open;
  spec.url = (ftun_string_t){argv[1], strlen(argv[1])};
  spec.maximum_bytes = 4096u;
  spec.deadline_ms = now + strtoull(argv[7], NULL, 10);
  spec.generation = 7u;
  spec.purpose = FTUN_DIAL_PURPOSE_FRS_UPDATE;
  memcpy(spec.resolver.name, "test", 5u);
  spec.resolver.named = strcmp(argv[2], "tcp") == 0 || strcmp(argv[2], "udp") == 0;
  spec.resolver.tcp = strcmp(argv[2], "tcp") == 0;
  memcpy(spec.resolver.upstream, argv[3], strlen(argv[3]) + 1u);
  memcpy(spec.resolver.proxy, argv[4], strlen(argv[4]) + 1u);
  spec.resolver.use_proxy = argv[4][0] != '\0';
  if (atoi(argv[6]) != 0) {
    memcpy(spec.resolver.proxy_username, "user", 5u);
    memcpy(spec.resolver.proxy_password, "pass", 5u);
  }
  memcpy(bootstrap, argv[5], strlen(argv[5]) + 1u);
  for (entry = strtok(bootstrap, ","); entry != NULL; entry = strtok(NULL, ",")) {
    size_t index = spec.resolver.bootstrap_count;
    if (index >= FTUN_BOOTSTRAP_MAX_SERVERS ||
        ftun_control_parse_endpoint(entry, 53u, &spec.resolver.bootstrap[index], domain) != FTUN_OK ||
        spec.resolver.bootstrap[index].kind != FTUN_ADDRESS_IPV4) return 4;
    spec.resolver.bootstrap_count++;
  }
  status = ftun_http_fetch(&spec, &result);
  printf("status=%s http=%u paths=%u system=%u resolvers=%u length=%zu\n", ftun_status_name(status),
    (unsigned)result.status, path_calls, system_calls, resolver_calls, result.length);
  if (result.length != 0u) (void)fwrite(result.data, 1u, result.length, stdout);
  ftun_http_fetch_release(&result);
  if (strcmp(argv[2], "system") != 0 && system_calls != 0u) return 5;
  if (ftun_budget_get_usage(budget, &after) != FTUN_OK || after.used != before.used ||
      after.metadata_bytes != before.metadata_bytes || after.used_resources.descriptors != 0u ||
      ftun_budget_destroy(&budget) != FTUN_OK) return 6;
  return 0;
}
