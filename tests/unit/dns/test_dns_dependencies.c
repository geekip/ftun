/* 使用真实 loopback Bootstrap 记录 prepare 实际解析集合。 */
#include "proxy/protocol/socks5.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include "app/config/parser.h"
#include "app/config/model.h"
#include "dns/service.c"
#include "libs/transport/socket_path.h"
#include "app/config/compile.h"
#include "app/config/validate.h"
#include "core/context.h"
#include "core/event/backend.h"

#include <dirent.h>
#include <pthread.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "DNS dependencies failed at line %d: %s\n", __LINE__, #x); \
  return 1; } } while (0)
#define MAX_QUERIES 64u

typedef struct {
  int fd;
  uint16_t port;
  pthread_t thread;
  pthread_mutex_t mutex;
  bool stopping;
  bool failed;
  char failure[254];
  char queries[MAX_QUERIES][254];
  size_t count;
} bootstrap_t;

typedef struct {
  ftun_budget_t *budget;
  ftun_operation_queue_t *operations;
  ftun_core_t *core;
  ftun_event_loop_t *loop;
  ftun_budget_usage_t baseline;
  size_t fds;
} fixture_t;

static size_t fail_count, fail_size;
static unsigned int allocation_failures;
static ftun_config_t *destroy_target;
static unsigned int destroy_failures;
void *__real_calloc(size_t count, size_t size);
ftun_status_t __real_ftun_config_destroy(ftun_config_t **config);

void *__wrap_calloc(size_t count, size_t size)
{
  if (allocation_failures != 0u && count == fail_count && size == fail_size) {
    allocation_failures--;
    return NULL;
  }
  return __real_calloc(count, size);
}

ftun_status_t __wrap_ftun_config_destroy(ftun_config_t **config)
{
  if (destroy_failures != 0u && config != NULL && *config == destroy_target) {
    destroy_failures--;
    return FTUN_E_AGAIN;
  }
  return __real_ftun_config_destroy(config);
}

static size_t fd_count(void)
{
  DIR *directory = opendir("/proc/self/fd");
  struct dirent *entry;
  size_t count = 0u;
  if (directory == NULL) return SIZE_MAX;
  while ((entry = readdir(directory)) != NULL) {
    if (entry->d_name[0] != '.') count++;
  }
  (void)closedir(directory);
  return count;
}

static void *bootstrap_run(void *user)
{
  bootstrap_t *server = user;
  for (;;) {
    struct sockaddr_in peer;
    socklen_t peer_length = sizeof(peer);
    uint8_t wire[512];
    char name[254];
    ssize_t length = recvfrom(server->fd, wire, sizeof(wire) - 16u, 0,
      (struct sockaddr *)&peer, &peer_length);
    size_t cursor = 12u, output = 0u;
    bool failure, valid = length >= 17;
    (void)pthread_mutex_lock(&server->mutex);
    if (server->stopping) {
      (void)pthread_mutex_unlock(&server->mutex);
      return NULL;
    }
    while (valid && cursor < (size_t)length && wire[cursor] != 0u) {
      size_t label = wire[cursor++];
      if (label > 63u || label > (size_t)length - cursor ||
          label + output + 1u >= sizeof(name)) { valid = false; break; }
      if (output != 0u) name[output++] = '.';
      memcpy(name + output, wire + cursor, label);
      output += label;
      cursor += label;
    }
    name[output] = '\0';
    if (!valid || cursor + 5u != (size_t)length ||
        server->count == MAX_QUERIES) {
      server->failed = true;
      (void)pthread_mutex_unlock(&server->mutex);
      continue;
    }
    memcpy(server->queries[server->count++], name, output + 1u);
    failure = strcmp(name, server->failure) == 0;
    (void)pthread_mutex_unlock(&server->mutex);
    wire[2] = 0x81u;
    wire[3] = failure ? 0x83u : 0x80u;
    wire[6] = 0u;
    wire[7] = (uint8_t)(failure ? 0u : 1u);
    if (!failure) {
      static const uint8_t answer[] = {
        0xc0u, 0x0cu, 0u, 1u, 0u, 1u, 0u, 0u, 0u, 60u,
        0u, 4u, 127u, 0u, 0u, 7u
      };
      memcpy(wire + length, answer, sizeof(answer));
      length += (ssize_t)sizeof(answer);
    }
    if (sendto(server->fd, wire, (size_t)length, 0,
        (struct sockaddr *)&peer, peer_length) != length) {
      (void)pthread_mutex_lock(&server->mutex);
      server->failed = true;
      (void)pthread_mutex_unlock(&server->mutex);
    }
  }
}

static int bootstrap_start(bootstrap_t *server)
{
  struct sockaddr_in address;
  socklen_t length = sizeof(address);
  memset(server, 0, sizeof(*server));
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  CHECK(pthread_mutex_init(&server->mutex, NULL) == 0);
  server->fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  CHECK(server->fd >= 0);
  CHECK(bind(server->fd, (struct sockaddr *)&address, length) == 0);
  CHECK(getsockname(server->fd, (struct sockaddr *)&address, &length) == 0);
  server->port = ntohs(address.sin_port);
  CHECK(pthread_create(&server->thread, NULL, bootstrap_run, server) == 0);
  return 0;
}

static int bootstrap_stop(bootstrap_t *server)
{
  struct sockaddr_in address;
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons(server->port);
  (void)pthread_mutex_lock(&server->mutex);
  server->stopping = true;
  (void)pthread_mutex_unlock(&server->mutex);
  CHECK(sendto(server->fd, "x", 1u, 0, (struct sockaddr *)&address,
               sizeof(address)) == 1);
  CHECK(pthread_join(server->thread, NULL) == 0);
  CHECK(!server->failed);
  CHECK(close(server->fd) == 0);
  CHECK(pthread_mutex_destroy(&server->mutex) == 0);
  return 0;
}

static void bootstrap_reset(bootstrap_t *server, const char *failure)
{
  (void)pthread_mutex_lock(&server->mutex);
  server->count = 0u;
  (void)snprintf(server->failure, sizeof(server->failure), "%s", failure);
  (void)pthread_mutex_unlock(&server->mutex);
}

static size_t queries(bootstrap_t *server, const char *name)
{
  size_t count = 0u, index;
  (void)pthread_mutex_lock(&server->mutex);
  for (index = 0u; index < server->count; index++) {
    if (name == NULL || strcmp(name, server->queries[index]) == 0) count++;
  }
  if (server->failed) count = SIZE_MAX;
  (void)pthread_mutex_unlock(&server->mutex);
  return count;
}

static int fixture_start(fixture_t *fixture)
{
  memset(fixture, 0, sizeof(*fixture));
  fixture->fds = fd_count();
  CHECK(fixture->fds != SIZE_MAX);
  CHECK(ftun_budget_create(NULL, 16u * 1024u * 1024u, 1024u,
                           &fixture->budget) == FTUN_OK);
  CHECK(ftun_operation_queue_create(fixture->budget, 64u,
                                    &fixture->operations) == FTUN_OK);
  CHECK(ftun_core_context_create(fixture->budget, &fixture->core) == FTUN_OK);
  CHECK(ftun_event_loop_create_with_capacity(fixture->core, 128u,
                                            &fixture->loop) == FTUN_OK);
  CHECK(ftun_event_backend_attach(fixture->loop) == FTUN_OK);
  CHECK(ftun_budget_get_usage(fixture->budget, &fixture->baseline) == FTUN_OK);
  return 0;
}

static int fixture_finish(fixture_t *fixture)
{
  ftun_budget_usage_t usage;
  ftun_event_loop_usage_t events;
  ftun_operation_queue_usage_t operations;
  CHECK(ftun_budget_get_usage(fixture->budget, &usage) == FTUN_OK);
  CHECK(usage.used_resources.memory_bytes == fixture->baseline.used_resources.memory_bytes &&
        usage.metadata_bytes == fixture->baseline.metadata_bytes &&
        usage.used_resources.descriptors == fixture->baseline.used_resources.descriptors &&
        usage.used_resources.queue_slots == fixture->baseline.used_resources.queue_slots);
  CHECK(ftun_event_loop_get_usage(fixture->loop, &events) == FTUN_OK &&
        events.source_count == 0u && events.ready_count == 0u);
  CHECK(ftun_operation_queue_get_usage(fixture->operations, &operations) == FTUN_OK &&
        operations.inflight == 0u && operations.ready == 0u);
  CHECK(ftun_event_loop_stop(fixture->loop) == FTUN_OK);
  CHECK(ftun_event_backend_detach(fixture->loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&fixture->loop) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&fixture->core) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(fixture->operations) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&fixture->operations) == FTUN_OK);
  CHECK(ftun_budget_destroy(&fixture->budget) == FTUN_OK);
  CHECK(fd_count() == fixture->fds);
  return 0;
}

static ftun_status_t config_make(bootstrap_t *server, const char *outbounds,
  const char *servers, const char *extra, bool enabled, bool cache,
  ftun_config_t **out)
{
  char json[8192];
  int length = snprintf(json, sizeof(json),
    "{\"log\":{\"level\":\"silent\"},\"dns\":{\"enable\":%s,\"cache\":%s,"
    "\"bootstrap\":[\"127.0.0.1:%u\",\"127.0.0.1:9\"]%s},"
    "\"outbounds\":%s%s}", enabled ? "true" : "false", cache ? "true" : "false",
    (unsigned int)server->port, servers, outbounds, extra);
  ftun_status_t status;
  *out = NULL;
  if (length <= 0 || (size_t)length >= sizeof(json)) return FTUN_E_LIMIT;
  status = ftun_config_parse((ftun_bytes_t){(const uint8_t *)json, (size_t)length}, out);
  if (status == FTUN_OK) status = ftun_config_validate(*out, NULL);
  if (status == FTUN_OK) status = ftun_config_compile(*out, &(*out)->plan);
  return status;
}

static const char direct_server[] =
  ",\"default-server\":\"s\",\"servers\":[{\"name\":\"s\",\"type\":\"udp\","
  "\"address\":[\"127.0.0.1:9\"],\"outbound\":\"DIRECT\"}]";

static ftun_status_t prepare(fixture_t *fixture, ftun_config_t *config,
  bool planned, ftun_dns_runtime_t **out, ftun_dns_runtime_plan_t **plan)
{
  ftun_status_t status = FTUN_OK;
  if (planned) status = ftun_dns_runtime_plan_prepare(fixture->budget, config, 0u, plan);
  if (status != FTUN_OK) return status;
  if (planned) return ftun_dns_runtime_prepare_reload_planned(NULL,
    fixture->core, fixture->budget, fixture->operations, fixture->loop,
    config, NULL,
    &(ftun_dns_runtime_network_t){.protocol = &ftun_socks5_protocol, .generation = 2u, .socket_mark = 0u,
      .path = {.open = ftun_socket_path_open}}, *plan, out);
  return ftun_dns_runtime_prepare(fixture->core, fixture->budget,
    fixture->operations, fixture->loop, config, NULL,
    &(ftun_dns_runtime_network_t){.protocol = &ftun_socks5_protocol, .generation = 1u, .socket_mark = 0u,
      .path = {.open = ftun_socket_path_open}}, out);
}

static int prepare_case(bootstrap_t *server, const char *label,
  const char *outbounds, const char *servers, const char *extra,
  bool enabled, const char *failure, ftun_status_t expected,
  const char *const *resolved, size_t resolved_count)
{
  unsigned int planned, cache;
  for (planned = 0u; planned < 2u; planned++) {
    for (cache = 0u; cache < 2u; cache++) {
      fixture_t fixture;
      ftun_config_t *config = NULL;
      ftun_dns_runtime_t *dns = NULL;
      ftun_dns_runtime_plan_t *plan = NULL;
      size_t index;
      CHECK(fixture_start(&fixture) == 0);
      CHECK(config_make(server, outbounds, servers, extra, enabled,
                        cache != 0u, &config) == FTUN_OK);
      bootstrap_reset(server, failure);
      CHECK(prepare(&fixture, config, planned != 0u, &dns, &plan) == expected);
      CHECK(queries(server, NULL) == resolved_count);
      for (index = 0u; index < resolved_count; index++) {
        CHECK(queries(server, resolved[index]) == 1u);
      }
      if (expected == FTUN_OK && enabled) {
        CHECK(dns != NULL);
        for (index = 0u; index < config->outbound_count; index++) {
          char domain[254];
          const char *colon;
          size_t length;
          if (config->outbounds[index].kind != FTUN_CONFIG_OUTBOUND_SOCKS5) continue;
          colon = strrchr(config->outbounds[index].server, ':');
          length = colon == NULL ? strlen(config->outbounds[index].server) :
            (size_t)(colon - config->outbounds[index].server);
          CHECK(length < sizeof(domain));
          memcpy(domain, config->outbounds[index].server, length);
          domain[length] = '\0';
          CHECK((dns->proxy_endpoint_valid[index] != 0u) ==
                (queries(server, domain) == 1u));
          if (dns->proxy_endpoint_valid[index] != 0u) {
            CHECK(dns->proxy_endpoints[index].kind == FTUN_ADDRESS_IPV4);
            CHECK(dns->proxy_endpoints[index].address[0] == 127u &&
                  dns->proxy_endpoints[index].address[3] == 7u);
            CHECK(colon != NULL && dns->proxy_endpoints[index].port ==
                  (uint16_t)strtoul(colon + 1u, NULL, 10));
          }
        }
        CHECK(ftun_dns_runtime_activate(dns) == FTUN_OK);
      } else if (!enabled) CHECK(dns == NULL);
      CHECK(ftun_dns_runtime_destroy(&dns) == FTUN_OK);
      CHECK(ftun_dns_runtime_plan_destroy(&plan) == FTUN_OK);
      CHECK(config->document.reference_count == 1u);
      CHECK(ftun_config_destroy(&config) == FTUN_OK);
      CHECK(fixture_finish(&fixture) == 0);
      printf("dependencies %s planned=%u cache=%u passed\n", label, planned, cache);
    }
  }
  return 0;
}

static int basic_cases(bootstrap_t *server)
{
  const char *both[] = {"dns.example", "unused.example"};
  static const char reject_server[] =
    ",\"servers\":[{\"name\":\"s\",\"type\":\"udp\",\"address\":[\"127.0.0.1:9\"],"
    "\"outbound\":\"REJECT\"}]";
  CHECK(prepare_case(server, "direct", "[]", direct_server, "", true,
    "unused.example", FTUN_OK, NULL, 0u) == 0);
#if defined(FTUN_TEST_PROXY)
  CHECK(prepare_case(server, "reject", "[]", reject_server, "", true,
    "", FTUN_OK, NULL, 0u) == 0);
#else
  {
    ftun_config_t *config = NULL;
    bootstrap_reset(server, "");
    CHECK(config_make(server, "[]", reject_server, "", true,
                      false, &config) == FTUN_E_UNSUPPORTED);
    CHECK(queries(server, NULL) == 0u);
    CHECK(ftun_config_destroy(&config) == FTUN_OK);
  }
#endif
  CHECK(prepare_case(server, "implicit-bootstrap", "[]", "", "", true,
    "", FTUN_OK, NULL, 0u) == 0);
  CHECK(prepare_case(server, "disabled", "[]", "", "", false,
    "", FTUN_OK, NULL, 0u) == 0);
  /* 多地址服务器的每个地址都要解析（配置顺序即优先级）。 */
  CHECK(prepare_case(server, "all-address-bootstrap", "[]",
    ",\"servers\":[{\"name\":\"s\",\"type\":\"udp\","
    "\"address\":[\"dns.example:53\",\"unused.example:53\"],\"outbound\":\"DIRECT\"}]",
    "", true, "", FTUN_OK, both, 2u) == 0);
  return 0;
}

#if defined(FTUN_TEST_PROXY)
#define LEAVES "{\"name\":\"A\",\"type\":\"socks5\",\"server\":\"a.example:1080\"}," \
  "{\"name\":\"B\",\"type\":\"socks5\",\"server\":\"b.example:1081\"}"
#define GROUP "{\"name\":\"G\",\"type\":\"select\",\"outbounds\":[\"A\",\"B\"],\"default\":\"A\"}"
#define GROUP_SERVER ",\"servers\":[{\"name\":\"s\",\"type\":\"udp\",\"address\":[\"127.0.0.1:9\"],\"outbound\":\"G\"}]"

static int closure_cases(bootstrap_t *server)
{
  const char *both[] = {"a.example", "b.example"};
  const char *a[] = {"a.example"};
  CHECK(prepare_case(server, "unreferenced", "[" LEAVES "]", direct_server,
    "", true, "a.example", FTUN_OK, NULL, 0u) == 0);
  CHECK(prepare_case(server, "route-only", "[" LEAVES "]", direct_server,
    ",\"inbounds\":[{\"name\":\"i\",\"type\":\"mixed\",\"listen\":\"127.0.0.1:9\","
    "\"outbound\":\"A\"}]", true, "a.example", FTUN_OK, NULL, 0u) == 0);
  CHECK(prepare_case(server, "nondefault-failure", "[" LEAVES "," GROUP "]",
    GROUP_SERVER, "", true, "b.example", FTUN_E_PROTOCOL, both, 2u) == 0);
  CHECK(prepare_case(server, "nested-failure", "[" LEAVES "," GROUP ","
    "{\"name\":\"N\",\"type\":\"select\",\"outbounds\":[\"G\"],\"default\":\"G\"}]",
    ",\"servers\":[{\"name\":\"s\",\"type\":\"udp\",\"address\":[\"127.0.0.1:9\"],"
    "\"outbound\":\"N\"}]", "", true, "b.example", FTUN_E_PROTOCOL, both, 2u) == 0);
  CHECK(prepare_case(server, "urltest-failure", "[" LEAVES ","
    "{\"name\":\"G\",\"type\":\"url-test\",\"outbounds\":[\"A\",\"B\"],"
    "\"default\":\"A\",\"url\":\"http://127.0.0.1/x\"}]", GROUP_SERVER,
    "", true, "b.example", FTUN_E_PROTOCOL, both, 2u) == 0);
  CHECK(prepare_case(server, "all-server-roots", "[" LEAVES "," GROUP "]",
    ",\"default-server\":\"d\",\"servers\":[{\"name\":\"d\",\"type\":\"udp\","
    "\"address\":[\"127.0.0.1:9\"],\"outbound\":\"DIRECT\"},{\"name\":\"hidden\","
    "\"type\":\"tcp\",\"address\":[\"127.0.0.1:9\"],\"outbound\":\"G\"}]", "",
    true, "b.example", FTUN_E_PROTOCOL, both, 2u) == 0);
  CHECK(prepare_case(server, "shared-leaf", "[" LEAVES ","
    "{\"name\":\"H\",\"type\":\"select\",\"outbounds\":[\"A\",\"DIRECT\",\"REJECT\"],\"default\":\"A\"},"
    "{\"name\":\"G\",\"type\":\"select\",\"outbounds\":[\"H\",\"A\"],\"default\":\"H\"}]",
    ",\"servers\":[{\"name\":\"s\",\"type\":\"udp\",\"address\":[\"127.0.0.1:9\"],\"outbound\":\"G\"},"
    "{\"name\":\"t\",\"type\":\"udp\",\"address\":[\"127.0.0.1:9\"],\"outbound\":\"H\"}]",
    "", true, "b.example", FTUN_OK, a, 1u) == 0);
  CHECK(prepare_case(server, "members-ready", "[" LEAVES "," GROUP "]",
    GROUP_SERVER, "", true, "", FTUN_OK, both, 2u) == 0);
  CHECK(prepare_case(server, "disabled-proxies", "[" LEAVES "]", "", "",
    false, "a.example", FTUN_OK, NULL, 0u) == 0);
  CHECK(prepare_case(server, "implicit-proxies", "[" LEAVES "]", "", "",
    true, "a.example", FTUN_OK, NULL, 0u) == 0);
  return 0;
}

static int invalid_config_cases(bootstrap_t *server)
{
  const char *invalid[] = {
    "[{\"name\":\"P\",\"type\":\"socks5\",\"server\":\"bad_domain:1\"}]",
    "[{\"name\":\"G\",\"type\":\"select\",\"outbounds\":[\"missing\"],\"default\":\"missing\"}]",
    "[{\"name\":\"G\",\"type\":\"select\",\"outbounds\":[\"H\"],\"default\":\"H\"},"
      "{\"name\":\"H\",\"type\":\"select\",\"outbounds\":[\"G\"],\"default\":\"G\"}]",
    "[{\"name\":\"P\",\"type\":\"socks5\",\"server\":\"127.0.0.1:1\"},"
      "{\"name\":\"P\",\"type\":\"socks5\",\"server\":\"127.0.0.1:2\"}]"
  };
  size_t index;
  bootstrap_reset(server, "");
  for (index = 0u; index < sizeof(invalid) / sizeof(invalid[0]); index++) {
    ftun_config_t *config = NULL;
    CHECK(config_make(server, invalid[index], direct_server, "", true,
                      false, &config) == FTUN_E_INVALID);
    CHECK(ftun_config_destroy(&config) == FTUN_OK);
  }
  CHECK(queries(server, NULL) == 0u);
  return 0;
}
#endif

static int plan_pairing(bootstrap_t *server)
{
  fixture_t fixture;
  ftun_config_t *config = NULL, *different = NULL, *owned;
  ftun_dns_runtime_plan_t *plan = NULL, *saved;
  ftun_dns_runtime_t *dns = NULL, *second = NULL;
  CHECK(fixture_start(&fixture) == 0);
  CHECK(config_make(server, "[]", direct_server, "", true, false, &config) == FTUN_OK);
  CHECK(config_make(server, "[]",
    ",\"default-server\":\"s\",\"servers\":[{\"name\":\"s\",\"type\":\"udp\","
    "\"address\":[\"127.0.0.1:10\"],\"outbound\":\"DIRECT\"}]",
    "", true, false, &different) == FTUN_OK);
  bootstrap_reset(server, "");
  CHECK(ftun_dns_runtime_plan_prepare(fixture.budget, config, 0u, &plan) == FTUN_OK);
  CHECK(config->document.reference_count == 2u);
  saved = plan;
  CHECK(ftun_dns_runtime_plan_prepare(fixture.budget, config, 0u, &plan) == FTUN_E_AGAIN && plan == saved);
  CHECK(ftun_dns_runtime_prepare_reload_planned(NULL, fixture.core, fixture.budget,
    fixture.operations, fixture.loop, different, NULL,
    &(ftun_dns_runtime_network_t){.protocol = &ftun_socks5_protocol, .generation = 2u, .socket_mark = 0u,
      .path = {.open = ftun_socket_path_open}}, plan, &dns) == FTUN_E_STALE);
  CHECK(dns == NULL && different->document.reference_count == 1u && queries(server, NULL) == 0u);
  CHECK(ftun_dns_runtime_prepare_reload_planned(NULL, fixture.core, fixture.budget,
    fixture.operations, fixture.loop, config, NULL,
    &(ftun_dns_runtime_network_t){.protocol = &ftun_socks5_protocol, .generation = 2u, .socket_mark = 0u,
      .path = {.open = ftun_socket_path_open}}, plan, &dns) == FTUN_OK);
  CHECK(ftun_dns_runtime_prepare_reload_planned(NULL, fixture.core, fixture.budget,
    fixture.operations, fixture.loop, config, NULL,
    &(ftun_dns_runtime_network_t){.protocol = &ftun_socks5_protocol, .generation = 2u, .socket_mark = 0u,
      .path = {.open = ftun_socket_path_open}}, plan, &second) == FTUN_OK);
  CHECK(config->document.reference_count == 4u);
  CHECK(ftun_dns_runtime_destroy(&second) == FTUN_OK && config->document.reference_count == 3u);
  owned = config;
  CHECK(ftun_config_destroy(&config) == FTUN_OK && config == NULL);
  CHECK(plan->config == owned && owned->document.reference_count == 2u && dns->config == owned);
  CHECK(ftun_dns_runtime_plan_destroy(&plan) == FTUN_OK && owned->document.reference_count == 1u);
  CHECK(ftun_dns_runtime_activate(dns) == FTUN_OK);
  CHECK(ftun_dns_runtime_destroy(&dns) == FTUN_OK);
  CHECK(ftun_config_destroy(&different) == FTUN_OK);
  CHECK(fixture_finish(&fixture) == 0);
  puts("dependencies plan pairing and config lifetime passed");
  return 0;
}

static int retain_failure(bootstrap_t *server)
{
  fixture_t fixture;
  ftun_config_t *config = NULL;
  ftun_dns_runtime_plan_t *plan = NULL;
  ftun_dns_runtime_t *dns = NULL;
  CHECK(fixture_start(&fixture) == 0);
  CHECK(config_make(server, "[]", direct_server, "", true, false, &config) == FTUN_OK);
  bootstrap_reset(server, "");
  config->document.reference_count = SIZE_MAX;
  CHECK(ftun_dns_runtime_plan_prepare(fixture.budget, config, 0u, &plan) == FTUN_E_LIMIT);
  CHECK(plan == NULL && config->document.reference_count == SIZE_MAX);
  CHECK(prepare(&fixture, config, false, &dns, &plan) == FTUN_E_LIMIT);
  CHECK(dns == NULL && config->document.reference_count == SIZE_MAX && queries(server, NULL) == 0u);
  config->document.reference_count = 1u;
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(fixture_finish(&fixture) == 0);
  puts("dependencies retain overflow passed");
  return 0;
}

#if defined(FTUN_TEST_PROXY)
static int allocation_and_cleanup(bootstrap_t *server)
{
  unsigned int planned, fault;
  for (planned = 0u; planned < 2u; planned++) {
    for (fault = 0u; fault < 3u; fault++) {
      fixture_t fixture;
      ftun_config_t *config = NULL;
      ftun_dns_runtime_plan_t *plan = NULL;
      ftun_dns_runtime_t *dns = NULL;
      CHECK(fixture_start(&fixture) == 0);
      CHECK(config_make(server, "[" LEAVES "," GROUP "]", GROUP_SERVER,
                        "", true, true, &config) == FTUN_OK);
      bootstrap_reset(server, "");
      fail_count = fault == 0u ? 1u : config->outbound_count;
      fail_size = fault == 0u ? (planned != 0u ? sizeof(ftun_dns_runtime_plan_t) :
        sizeof(ftun_dns_runtime_t)) : (fault == 1u ? sizeof(ftun_endpoint_t) : 1u);
      allocation_failures = 1u;
      CHECK(prepare(&fixture, config, planned != 0u, &dns, &plan) == FTUN_E_LIMIT);
      CHECK(allocation_failures == 0u && queries(server, NULL) == 0u);
      CHECK(ftun_dns_runtime_destroy(&dns) == FTUN_OK);
      CHECK(ftun_dns_runtime_plan_destroy(&plan) == FTUN_OK);
      CHECK(config->document.reference_count == 1u);
      CHECK(ftun_config_destroy(&config) == FTUN_OK);
      CHECK(fixture_finish(&fixture) == 0);
    }
  }
  {
    fixture_t fixture;
    ftun_config_t *config = NULL;
    ftun_dns_runtime_plan_t *plan = NULL;
    ftun_dns_runtime_t *dns = NULL;
    CHECK(fixture_start(&fixture) == 0);
    CHECK(config_make(server, "[" LEAVES "," GROUP "]", GROUP_SERVER,
                      "", true, false, &config) == FTUN_OK);
    bootstrap_reset(server, "b.example");
    destroy_target = config;
    destroy_failures = 1u;
    CHECK(ftun_dns_runtime_plan_prepare(fixture.budget, config, 0u, &plan) == FTUN_E_PROTOCOL);
    CHECK(plan != NULL && plan->config == config && config->document.reference_count == 2u);
    CHECK(destroy_failures == 0u && queries(server, "b.example") == 1u);
    CHECK(ftun_dns_runtime_plan_destroy(&plan) == FTUN_OK && plan == NULL);
    CHECK(config->document.reference_count == 1u);
    bootstrap_reset(server, "b.example");
    destroy_failures = 1u;
    CHECK(prepare(&fixture, config, false, &dns, &plan) == FTUN_E_PROTOCOL);
    CHECK(dns != NULL && dns->cleanup_only && config->document.reference_count == 2u);
    CHECK(destroy_failures == 0u);
    CHECK(ftun_dns_runtime_destroy(&dns) == FTUN_OK && config->document.reference_count == 1u);
    destroy_target = NULL;
    CHECK(ftun_config_destroy(&config) == FTUN_OK);
    CHECK(fixture_finish(&fixture) == 0);
  }
  puts("dependencies allocation failures and retained cleanup passed");
  return 0;
}
#endif

static int plan_budget(bootstrap_t *server)
{
  fixture_t fixture;
  ftun_config_t *config = NULL;
  ftun_dns_runtime_plan_t *first = NULL, *second = NULL;
  ftun_budget_t *child = NULL;
  ftun_budget_usage_t baseline, usage;
  size_t charge;
  CHECK(fixture_start(&fixture) == 0);
#if defined(FTUN_TEST_PROXY)
  CHECK(config_make(server, "[" LEAVES "," GROUP "]", direct_server,
    "", true, false, &config) == FTUN_OK);
#else
  CHECK(config_make(server, "[]", direct_server, "", true, false, &config) == FTUN_OK);
#endif
  charge = sizeof(*first) + config->outbound_count *
    (sizeof(*first->proxies) + sizeof(*first->proxy_valid));
  CHECK(ftun_budget_create(fixture.budget, charge - 1u, 0u, &child) == FTUN_OK);
  CHECK(ftun_budget_get_usage(fixture.budget, &baseline) == FTUN_OK);
  bootstrap_reset(server, "");
  CHECK(ftun_dns_runtime_plan_prepare(child, config, 0u, &first) == FTUN_E_LIMIT);
  CHECK(first == NULL && config->document.reference_count == 1u && queries(server, NULL) == 0u);
  CHECK(ftun_budget_get_usage(fixture.budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == baseline.used_resources.memory_bytes);
  CHECK(ftun_budget_destroy(&child) == FTUN_OK);
  CHECK(ftun_dns_runtime_plan_prepare(fixture.budget, config, 0u, &first) == FTUN_OK);
  CHECK(ftun_budget_get_usage(fixture.budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == baseline.used_resources.memory_bytes + charge);
  CHECK(ftun_dns_runtime_plan_prepare(fixture.budget, config, 0u, &second) == FTUN_OK);
  CHECK(ftun_budget_get_usage(fixture.budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == baseline.used_resources.memory_bytes + 2u * charge);
  destroy_target = config;
  destroy_failures = 1u;
  CHECK(ftun_dns_runtime_plan_destroy(&first) == FTUN_E_AGAIN && first != NULL);
  CHECK(ftun_budget_get_usage(fixture.budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == baseline.used_resources.memory_bytes + 2u * charge);
  CHECK(ftun_dns_runtime_plan_destroy(&first) == FTUN_OK);
  CHECK(ftun_budget_get_usage(fixture.budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == baseline.used_resources.memory_bytes + charge);
  CHECK(ftun_dns_runtime_plan_destroy(&second) == FTUN_OK && config->document.reference_count == 1u);
  CHECK(ftun_budget_get_usage(fixture.budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == baseline.used_resources.memory_bytes);
  destroy_target = NULL;
  config->dns.enable = false;
  CHECK(ftun_dns_runtime_plan_prepare(fixture.budget, config, 0u, &first) == FTUN_OK);
  CHECK(ftun_budget_get_usage(fixture.budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == baseline.used_resources.memory_bytes + sizeof(*first));
  CHECK(ftun_dns_runtime_plan_destroy(&first) == FTUN_OK);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  CHECK(fixture_finish(&fixture) == 0);
  return 0;
}

int main(void)
{
  bootstrap_t bootstrap;
  size_t initial_fds = fd_count();
  CHECK(initial_fds != SIZE_MAX);
  CHECK(bootstrap_start(&bootstrap) == 0);
  CHECK(plan_budget(&bootstrap) == 0);
  CHECK(basic_cases(&bootstrap) == 0);
  CHECK(plan_pairing(&bootstrap) == 0);
  CHECK(retain_failure(&bootstrap) == 0);
#if defined(FTUN_TEST_PROXY)
  CHECK(closure_cases(&bootstrap) == 0);
  CHECK(invalid_config_cases(&bootstrap) == 0);
  CHECK(allocation_and_cleanup(&bootstrap) == 0);
#endif
  CHECK(bootstrap_stop(&bootstrap) == 0);
  CHECK(fd_count() == initial_fds);
  puts("DNS dependency contracts passed");
  return 0;
}
