#define _GNU_SOURCE 1
#define FTUN_TEST_PROXY 1
#include "../../support/egress_fixture.h"
#include "proxy/egress_internal.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <poll.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "app/config/parser.h"
#include "app/config/model.h"
#include "dns/module.h"
#include "app/composition/bridges.h"
/* 真实 Runtime、组适配器和本机 SOCKS5 UDP/TCP 路径验证查询固定出口。 */
#include "dns/service.c"
#include "libs/transport/socket_path.h"
#include "app/config/compile.h"
#include "app/config/validate.h"
#include "core/event/backend.h"
#include "proxy/dns/runtime_adapter.h"
#include "proxy/runtime_state.h"

#include <netinet/tcp.h>
#include <dirent.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "DNS query binding failed: %s:%d: %s\n", __FILE__, __LINE__, #x); \
  return 1; } } while (0)

typedef struct {
  int fd;
  unsigned int stage;
  uint8_t bytes[512];
  size_t used;
} peer_t;

typedef struct {
  int listener;
  int udp;
  uint16_t port;
  uint16_t udp_port;
  const char *credential;
  peer_t peers[16];
  uint8_t datagram[512];
  size_t datagram_length;
  struct sockaddr_in client;
  socklen_t client_length;
  unsigned int udp_queries;
  unsigned int tcp_queries;
  unsigned int authentications;
  bool release_tc;
  bool withhold_tcp;
} proxy_t;

typedef struct {
  ftun_proxy_dns_runtime_adapter_t proxy;
  size_t calls;
  bool force;
  uint32_t forced_member;
} selector_t;

typedef struct {
  size_t calls;
  ftun_status_t status;
  size_t length;
} completion_t;

typedef struct {
  ftun_budget_t *budget;
  ftun_operation_queue_t *operations;
  ftun_core_t *core;
  ftun_event_loop_t *loop;
  ftun_dns_runtime_t *dns;
  ftun_dns_runtime_t *retired;
  ftun_dns_service_slot_t slot;
  ftun_dns_runtime_adapter_t adapter;
  ftun_config_t *config;
  selector_t selector;
  proxy_t proxies[3];
  size_t fd_baseline;
} fixture_t;

static uint64_t test_now(void)
{
  uint64_t now;
  if (ftun_dns_runtime_now(NULL, &now) != FTUN_OK) abort();
  return now;
}

static size_t open_fd_count(void)
{
  DIR *directory = opendir("/proc/self/fd");
  struct dirent *entry;
  size_t count = 0u;
  if (directory == NULL) return SIZE_MAX;
  while ((entry = readdir(directory)) != NULL) {
    if (entry->d_name[0] != '.') count++;
  }
  if (closedir(directory) != 0) return SIZE_MAX;
  return count;
}

static int bind_socket(int type, uint16_t *port)
{
  struct sockaddr_in address;
  socklen_t length = (socklen_t)sizeof(address);
  int fd = socket(AF_INET, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0) return -1;
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(fd, (const struct sockaddr *)&address, length) != 0 ||
      getsockname(fd, (struct sockaddr *)&address, &length) != 0 ||
      (type == SOCK_STREAM && listen(fd, 16) != 0)) {
    (void)close(fd);
    return -1;
  }
  *port = ntohs(address.sin_port);
  return fd;
}

static int proxy_init(proxy_t *proxy, const char *credential)
{
  size_t index;
  memset(proxy, 0, sizeof(*proxy));
  proxy->credential = credential;
  for (index = 0u; index < 16u; index++) proxy->peers[index].fd = -1;
  proxy->listener = bind_socket(SOCK_STREAM, &proxy->port);
  proxy->udp = bind_socket(SOCK_DGRAM, &proxy->udp_port);
  CHECK(proxy->listener >= 0 && proxy->udp >= 0);
  return 0;
}

static int write_bytes(int fd, const uint8_t *bytes, size_t length)
{
  CHECK(send(fd, bytes, length, MSG_NOSIGNAL) == (ssize_t)length);
  return 0;
}

static int proxy_peer_step(proxy_t *proxy, peer_t *peer)
{
  ssize_t count;
  size_t needed;
  uint8_t reply[512];
  if (peer->fd < 0) return 0;
  count = recv(peer->fd, peer->bytes + peer->used,
               sizeof(peer->bytes) - peer->used, 0);
  if (count == 0) {
    CHECK(close(peer->fd) == 0);
    peer->fd = -1;
    return 0;
  }
  if (count < 0) {
    CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
    return 0;
  }
  peer->used += (size_t)count;
  if (peer->stage == 0u) {
    if (peer->used < 3u) return 0;
    CHECK(peer->used == 3u && peer->bytes[0] == 5u &&
          peer->bytes[1] == 1u && peer->bytes[2] == 2u);
    reply[0] = 5u; reply[1] = 2u;
    CHECK(write_bytes(peer->fd, reply, 2u) == 0);
    peer->stage = 1u;
  } else if (peer->stage == 1u) {
    size_t length = strlen(proxy->credential);
    if (peer->used < length * 2u + 3u) return 0;
    CHECK(peer->used == length * 2u + 3u && peer->bytes[0] == 1u &&
          peer->bytes[1] == length && peer->bytes[length + 2u] == length);
    CHECK(memcmp(peer->bytes + 2u, proxy->credential, length) == 0);
    CHECK(memcmp(peer->bytes + length + 3u, proxy->credential, length) == 0);
    proxy->authentications++;
    reply[0] = 1u; reply[1] = 0u;
    CHECK(write_bytes(peer->fd, reply, 2u) == 0);
    peer->stage = 2u;
  } else if (peer->stage == 2u) {
    if (peer->used < 10u) return 0;
    CHECK(peer->used == 10u && peer->bytes[0] == 5u && peer->bytes[3] == 1u);
    CHECK(peer->bytes[1] == 1u || peer->bytes[1] == 3u);
    memset(reply, 0, 10u);
    reply[0] = 5u; reply[3] = 1u; reply[4] = 127u; reply[7] = 1u;
    reply[8] = (uint8_t)(proxy->udp_port >> 8u);
    reply[9] = (uint8_t)proxy->udp_port;
    CHECK(write_bytes(peer->fd, reply, 10u) == 0);
    peer->stage = peer->bytes[1] == 1u ? 3u : 4u;
  } else if (peer->stage == 3u) {
    if (peer->used < 2u) return 0;
    needed = ((size_t)peer->bytes[0] << 8u) | peer->bytes[1];
    CHECK(needed >= 12u && needed + 2u <= sizeof(reply));
    if (peer->used < needed + 2u) return 0;
    CHECK(peer->used == needed + 2u);
    memcpy(reply, peer->bytes, peer->used);
    reply[4] = 0x81u; reply[5] = 0x80u;
    if (!proxy->withhold_tcp) CHECK(write_bytes(peer->fd, reply, peer->used) == 0);
    proxy->tcp_queries++;
    peer->stage = 5u;
  } else CHECK(false);
  peer->used = 0u;
  return 0;
}

static int proxy_step(proxy_t *proxy)
{
  size_t index;
  int fd;
  for (;;) {
    fd = accept4(proxy->listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0) {
      CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
      break;
    }
    for (index = 0u; index < 16u && proxy->peers[index].fd >= 0; index++) {}
    CHECK(index < 16u);
    memset(&proxy->peers[index], 0, sizeof(proxy->peers[index]));
    proxy->peers[index].fd = fd;
    {
      int one = 1;
      CHECK(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0);
    }
  }
  for (index = 0u; index < 16u; index++) {
    CHECK(proxy_peer_step(proxy, &proxy->peers[index]) == 0);
  }
  if (proxy->datagram_length == 0u) {
    ssize_t count;
    proxy->client_length = (socklen_t)sizeof(proxy->client);
    count = recvfrom(proxy->udp, proxy->datagram, sizeof(proxy->datagram), 0,
      (struct sockaddr *)&proxy->client, &proxy->client_length);
    if (count >= 0) {
      CHECK(count >= 22 && proxy->datagram[3] == 1u);
      proxy->datagram_length = (size_t)count;
      proxy->udp_queries++;
    } else CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
  }
  if (proxy->datagram_length != 0u && proxy->release_tc) {
    proxy->datagram[12] = 0x83u;
    proxy->datagram[13] = 0x80u;
    CHECK(sendto(proxy->udp, proxy->datagram, proxy->datagram_length, 0,
      (const struct sockaddr *)&proxy->client, proxy->client_length) ==
        (ssize_t)proxy->datagram_length);
    proxy->datagram_length = 0u;
  }
  return 0;
}

static ftun_status_t select_member(void *user,
  uint64_t generation, uint32_t group, uint32_t *member)
{
  selector_t *selector = (selector_t *)user;
  selector->calls++;
  if (selector->force) {
    *member = selector->forced_member;
    return FTUN_OK;
  }
  ftun_runtime_t *runtime = NULL;
  ftun_runtime_info_t info;
  bool is_group, degraded;
  ftun_string_t resolver;
  ftun_status_t status = ftun_runtime_active_acquire(selector->proxy.core, &runtime);
  if (status == FTUN_OK) status = ftun_runtime_get_info(runtime, &info);
  if (status == FTUN_OK && info.generation != generation) status = FTUN_E_STALE;
  if (status == FTUN_OK) status = ftun_runtime_group_selected(runtime, group,
    member, &is_group, &degraded, &resolver);
  (void)ftun_runtime_release(&runtime);
  return status;
}

static ftun_config_t *configuration(fixture_t *fixture, int variant)
{
  char json[4096];
  char a[256];
  char b[256];
  char nodes[2048];
  const char *group;
  int length;
  ftun_config_t *config = NULL;
  ftun_feature_plan_t *plan = NULL;
  proxy_t *pa = &fixture->proxies[variant == 2 ? 2u : 0u];
  proxy_t *pb = &fixture->proxies[1];
  (void)snprintf(a, sizeof(a), "{\"name\":\"A\",\"type\":\"socks5\","
    "\"server\":\"127.0.0.1:%u\",\"username\":\"%s\",\"password\":\"%s\"}",
    (unsigned int)pa->port, pa->credential, pa->credential);
  (void)snprintf(b, sizeof(b), "{\"name\":\"B\",\"type\":\"socks5\","
    "\"server\":\"127.0.0.1:%u\",\"username\":\"%s\",\"password\":\"%s\"}",
    (unsigned int)pb->port, pb->credential, pb->credential);
  group = variant == 3 || variant == 4 ?
    "{\"name\":\"G\",\"type\":\"select\",\"outbounds\":[\"B\"],\"default\":\"B\"}" :
    variant == 5 ?
    "{\"name\":\"G\",\"type\":\"select\",\"outbounds\":[\"A\",\"B\"],\"default\":\"A\"}" :
    variant == 6 ?
    "{\"name\":\"G\",\"type\":\"select\",\"outbounds\":[\"H\"],\"default\":\"H\"},"
    "{\"name\":\"H\",\"type\":\"url-test\",\"outbounds\":[\"A\",\"B\"],"
    "\"default\":\"A\",\"url\":\"http://127.0.0.1:9/probe\"}" :
    "{\"name\":\"G\",\"type\":\"select\",\"outbounds\":[\"A\"],\"default\":\"A\"}";
  if (variant == 1) (void)snprintf(nodes, sizeof(nodes), "%s,%s,%s", group, b, a);
  else if (variant == 3) (void)snprintf(nodes, sizeof(nodes), "%s,%s", group, b);
  else (void)snprintf(nodes, sizeof(nodes), "%s,%s,%s", group, a, b);
  length = snprintf(json, sizeof(json),
    "{\"dns\":{\"enable\":true,\"cache\":false,\"default-server\":\"real\","
    "\"servers\":[{\"name\":\"real\",\"type\":\"udp\","
    "\"address\":[\"127.0.0.1:9\"],\"outbound\":\"G\"}]},"
    "\"outbounds\":[%s],\"rules\":[\"MATCH,G\"]}", nodes);
  if (length < 0 || (size_t)length >= sizeof(json) ||
      ftun_config_parse((ftun_bytes_t){(const uint8_t *)json,(size_t)length}, &config) != FTUN_OK ||
      ftun_config_validate(config, NULL) != FTUN_OK ||
      ftun_config_compile(config, &plan) != FTUN_OK) {
    (void)ftun_config_destroy(&config);
    return NULL;
  }
  ftun_config_bind_plan(config, plan);
  return config;
}

static int fixture_init(fixture_t *fixture, int variant)
{
  ftun_runtime_t *candidate = NULL;
  size_t index;
  memset(fixture, 0, sizeof(*fixture));
  fixture->fd_baseline = open_fd_count();
  CHECK(fixture->fd_baseline != SIZE_MAX);
  CHECK(proxy_init(&fixture->proxies[0], "old") == 0);
  CHECK(proxy_init(&fixture->proxies[1], "other") == 0);
  CHECK(proxy_init(&fixture->proxies[2], "fresh") == 0);
  CHECK(ftun_budget_create(NULL, 16u * 1024u * 1024u, 1024u, &fixture->budget) == FTUN_OK);
  CHECK(ftun_operation_queue_create(fixture->budget, 64u, &fixture->operations) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(fixture->budget, 4u, &fixture->core) == FTUN_OK);
  CHECK(ftun_event_loop_create_with_capacity(fixture->core, 128u, &fixture->loop) == FTUN_OK);
  CHECK(ftun_event_backend_attach(fixture->loop) == FTUN_OK);
  fixture->config = configuration(fixture, variant);
  CHECK(fixture->config != NULL);
  CHECK(ftun_runtime_prepare(fixture->core, fixture->config, &candidate) == FTUN_OK);
  CHECK(ftun_runtime_commit(fixture->core, &candidate) == FTUN_OK);
  fixture->selector.proxy.core = fixture->core;
  ftun_app_dns_bridge_init(&fixture->selector.proxy);
  fixture->selector.proxy.slot = &fixture->slot;
  fixture->adapter.user = &fixture->selector;
  const ftun_egress_provider_t *egress = NULL;
  CHECK(ftun_test_egress(fixture->budget, fixture->config, 1u, select_member, &fixture->selector, &egress) == FTUN_OK);
  CHECK(ftun_dns_runtime_prepare(fixture->core, fixture->budget, fixture->operations,
    fixture->loop, fixture->config, &fixture->adapter,
    &(ftun_dns_runtime_network_t){.generation = 1u, .socket_mark = 0u, .egress = egress,
      .path = {.open = ftun_socket_path_open}}, &fixture->dns) == FTUN_OK);
  ftun_egress_release(&egress);
  CHECK(ftun_dns_runtime_activate(fixture->dns) == FTUN_OK);
  for (index = 0u; index < 3u; index++) CHECK(fixture->proxies[index].udp_queries == 0u);
  return 0;
}

static int pump(fixture_t *fixture)
{
  size_t count;
  size_t index;
  for (index = 0u; index < 3u; index++) CHECK(proxy_step(&fixture->proxies[index]) == 0);
  CHECK(ftun_event_loop_run_once(fixture->loop, false, 64u, &count) == FTUN_OK);
  CHECK(ftun_dns_runtime_run_once(fixture->dns, 64u, &count) == FTUN_OK);
  if (fixture->retired != NULL) CHECK(ftun_dns_runtime_run_once(fixture->retired, 64u, &count) == FTUN_OK);
  CHECK(ftun_operation_dispatch(fixture->operations, 64u, &count) == FTUN_OK);
  return 0;
}

static void completed(ftun_operation_t *operation, ftun_error_t error,
                       ftun_bytes_t response, void *user)
{
  completion_t *completion = (completion_t *)user;
  (void)operation;
  completion->calls++;
  completion->status = error.status;
  completion->length = response.length;
}

static int query_start_until(fixture_t *fixture, uint16_t id,
  completion_t *completion, ftun_operation_t **operation, uint64_t deadline)
{
  static const uint8_t name[] = {1u,'a',7u,'e','x','a','m','p','l','e',0u};
  uint8_t wire[27];
  ftun_dns_query_t query;
  memset(wire, 0, sizeof(wire));
  wire[0] = (uint8_t)(id >> 8u); wire[1] = (uint8_t)id;
  wire[2] = 1u; wire[5] = 1u;
  memcpy(wire + 12u, name, sizeof(name));
  wire[24] = 1u; wire[26] = 1u;
  memset(&query, 0, sizeof(query));
  query.id = id; query.flags = 0x100u;
  query.question.name = (ftun_dns_name_t){wire + 12u, sizeof(name)};
  query.question.type = 1u; query.question.class_code = 1u;
  query.wire = (ftun_bytes_t){wire, sizeof(wire)};
  query.deadline_ms = deadline;
  query.resolution_mode = 1u; query.policy_fingerprint = 55u;
  query.outbound_id = 2u; query.server_fingerprint = 1u;
  query.completion = completed; query.completion_user = completion;
  CHECK(ftun_dns_exchange(fixture->core, fixture->dns->servers[0], &query, operation) == FTUN_OK);
  return 0;
}

static int query_start(fixture_t *fixture, uint16_t id,
  completion_t *completion, ftun_operation_t **operation)
{
  return query_start_until(fixture, id, completion, operation,
                            test_now() + 3000u);
}

static int wait_udp(fixture_t *fixture, size_t proxy, unsigned int count)
{
  uint64_t deadline = test_now() + 2000u;
  while (fixture->proxies[proxy].udp_queries < count && test_now() < deadline) {
    CHECK(pump(fixture) == 0);
  }
  CHECK(fixture->proxies[proxy].udp_queries == count);
  return 0;
}

static int wait_completion(fixture_t *fixture, completion_t *completion)
{
  uint64_t deadline = test_now() + 3000u;
  while (completion->calls == 0u && test_now() < deadline) CHECK(pump(fixture) == 0);
  CHECK(completion->calls == 1u && completion->status == FTUN_OK && completion->length == 27u);
  return 0;
}

static int reload(fixture_t *fixture, int variant)
{
  ftun_config_t *config = configuration(fixture, variant);
  ftun_runtime_t *candidate = NULL;
  ftun_dns_runtime_t *prepared = NULL;
  ftun_dns_runtime_plan_t *plan = NULL;
  CHECK(config != NULL);
  CHECK(ftun_runtime_prepare(fixture->core, config, &candidate) == FTUN_OK);
  CHECK(ftun_dns_runtime_plan_prepare(fixture->budget, config, 0u, &plan) == FTUN_OK);
  const ftun_egress_provider_t *egress = NULL;
  CHECK(ftun_test_egress(fixture->budget, config, 2u, select_member, &fixture->selector, &egress) == FTUN_OK);
  CHECK(ftun_dns_runtime_prepare_reload_planned(fixture->dns, fixture->core,
    fixture->budget, fixture->operations, fixture->loop, config, &fixture->adapter,
    &(ftun_dns_runtime_network_t){.generation = 2u, .socket_mark = 0u, .egress = egress,
      .path = {.open = ftun_socket_path_open}}, plan, &prepared) == FTUN_OK);
  ftun_egress_release(&egress);
  CHECK(ftun_dns_runtime_commit_reload(&fixture->dns, &prepared, &fixture->retired) == FTUN_OK);
  CHECK(ftun_runtime_commit(fixture->core, &candidate) == FTUN_OK);
  CHECK(ftun_config_destroy(&fixture->config) == FTUN_OK);
  fixture->config = config;
  CHECK(ftun_dns_runtime_plan_destroy(&plan) == FTUN_OK);
  return 0;
}

static int fixture_destroy(fixture_t *fixture)
{
  ftun_event_loop_usage_t events;
  size_t index;
  size_t peer;
  CHECK(ftun_dns_runtime_reap(&fixture->retired) == FTUN_OK);
  CHECK(ftun_dns_runtime_destroy(&fixture->dns) == FTUN_OK);
  CHECK(ftun_config_destroy(&fixture->config) == FTUN_OK);
  CHECK(ftun_event_loop_get_usage(fixture->loop, &events) == FTUN_OK && events.source_count == 0u);
  CHECK(ftun_event_loop_stop(fixture->loop) == FTUN_OK);
  CHECK(ftun_event_backend_detach(fixture->loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&fixture->loop) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&fixture->core) == FTUN_OK);
  CHECK(ftun_operation_queue_stop(fixture->operations) == FTUN_OK);
  CHECK(ftun_operation_queue_destroy(&fixture->operations) == FTUN_OK);
  CHECK(ftun_budget_destroy(&fixture->budget) == FTUN_OK);
  for (index = 0u; index < 3u; index++) {
    CHECK(close(fixture->proxies[index].listener) == 0);
    CHECK(close(fixture->proxies[index].udp) == 0);
    for (peer = 0u; peer < 16u; peer++) {
      if (fixture->proxies[index].peers[peer].fd >= 0) CHECK(close(fixture->proxies[index].peers[peer].fd) == 0);
    }
  }
  CHECK(open_fd_count() == fixture->fd_baseline);
  return 0;
}

static int generation_case(int variant)
{
  fixture_t fixture;
  completion_t first = {0u, FTUN_OK, 0u};
  completion_t second = {0u, FTUN_OK, 0u};
  ftun_operation_t *operation = NULL;
  ftun_dns_runtime_t *old;
  uint64_t original_deadline;
  size_t expected = variant == 2 ? 2u : (variant >= 3 ? 1u : 0u);
  size_t first_selects = variant == 6 ? 2u : 1u;
  size_t index;
  CHECK(fixture_init(&fixture, variant >= 5 ? variant : 0) == 0);
  old = fixture.dns;
  CHECK(query_start(&fixture, 11u, &first, &operation) == 0);
  CHECK(wait_udp(&fixture, 0u, 1u) == 0);
  CHECK(fixture.selector.calls == first_selects);
  CHECK(old->request_count == 1u && ((ftun_proxy_egress_t *)old->egress->context)->nodes[old->request_head->egress_id - 2u].endpoint.port == fixture.proxies[0].port);
  original_deadline = old->request_head->waiter_head->deadline_ms;
  if (variant < 5) {
    CHECK(reload(&fixture, variant) == 0);
    CHECK(ftun_dns_runtime_reap(&fixture.retired) == FTUN_E_AGAIN);
    {
      ftun_egress_info_t info = {0};
      CHECK(fixture.dns->egress->query(fixture.dns->egress->context,
        2u, old->generation, &info) == FTUN_E_STALE);
    }
  } else if (variant == 5) {
    CHECK(ftun_runtime_select_names(fixture.core, (ftun_string_t){"G",1u},
      (ftun_string_t){"B",1u}) == FTUN_OK);
  } else {
    ftun_group_choice_t choice;
    memset(&choice, 0, sizeof(choice));
    choice.generation = 1u; choice.leaf_id = 5u;
    CHECK(ftun_runtime_group_publish(fixture.core, 3u, &choice) == FTUN_OK);
  }
  fixture.proxies[0].release_tc = true;
  {
    uint64_t deadline = test_now() + 2000u;
    ftun_dns_runtime_transport_request_t *tcp = NULL;
    while (tcp == NULL && test_now() < deadline) {
      ftun_dns_runtime_transport_request_t *request;
      for (request = old->request_head; request != NULL; request = request->next) {
        if (request->transport == FTUN_DNS_TRANSPORT_TCP && request->waiter_head != NULL) {
          tcp = request;
          break;
        }
      }
      if (tcp == NULL) CHECK(pump(&fixture) == 0);
    }
    CHECK(tcp != NULL);
    CHECK(((ftun_proxy_egress_t *)old->egress->context)->nodes[tcp->egress_id - 2u].endpoint.port == fixture.proxies[0].port);
    CHECK(tcp->waiter_head->deadline_ms == original_deadline);
    CHECK(memcmp(((ftun_proxy_egress_t *)old->egress->context)->nodes[tcp->egress_id - 2u].username, "old", 3u) == 0);
    CHECK(fixture.selector.calls == first_selects);
  }
  CHECK(wait_completion(&fixture, &first) == 0);
  CHECK(fixture.proxies[0].tcp_queries == 1u && fixture.proxies[0].authentications == 2u);
  CHECK(fixture.proxies[1].tcp_queries == 0u && fixture.proxies[2].tcp_queries == 0u);
  CHECK(ftun_dns_runtime_reap(&fixture.retired) == FTUN_OK && fixture.retired == NULL);
  for (index = 0u; index < 3u; index++) fixture.proxies[index].release_tc = true;
  CHECK(query_start(&fixture, 12u, &second, &operation) == 0);
  CHECK(wait_completion(&fixture, &second) == 0);
  CHECK(fixture.selector.calls == first_selects * 2u);
  CHECK(fixture.proxies[expected].tcp_queries == (expected == 0u ? 2u : 1u));
  CHECK(fixture_destroy(&fixture) == 0);
  printf("query binding real SOCKS5 UDP/TC/TCP variant=%d passed\n", variant);
  return 0;
}

static void unexpected_completion(void *user, ftun_status_t status,
  ftun_dns_transport_t transport, const ftun_endpoint_t *source, ftun_bytes_t response)
{
  (void)user; (void)status; (void)transport; (void)source; (void)response;
  abort();
}

static int invalid_binding_case(void)
{
  fixture_t fixture;
  ftun_dns_transport_binding_t binding;
  ftun_dns_transport_binding_t changed;
  const uint32_t denied[] = {0u, 4u, 2u, UINT32_MAX};
  uint8_t wire[12] = {0u};
  ftun_endpoint_t upstream;
  size_t index;
  CHECK(fixture_init(&fixture, 0) == 0);
  CHECK(ftun_dns_runtime_transport_select(fixture.dns, 2u, &binding) == FTUN_OK);
  CHECK(binding.scope == fixture.dns && binding.root_id == 2u && binding.leaf_id == 3u);
  memset(&upstream, 0, sizeof(upstream));
  upstream.kind = FTUN_ADDRESS_IPV4; upstream.address[0] = 127u; upstream.address[3] = 1u; upstream.port = 9u;
  for (index = 0u; index < 6u; index++) {
    void *request = (void *)&fixture;
    changed = binding;
    if (index < 4u) changed.leaf_id = denied[index];
    else if (index == 4u) changed.scope = &fixture;
    else changed.root_id = 4u;
    CHECK(ftun_dns_runtime_transport_submit(fixture.dns, &changed, 1u, 1u,
      &upstream, FTUN_DNS_TRANSPORT_UDP, (ftun_bytes_t){wire,sizeof(wire)},
      test_now() + 1000u, unexpected_completion, NULL, &request) ==
      (index == 4u ? FTUN_E_STALE : FTUN_E_REJECTED));
    CHECK(request == NULL && fixture.dns->request_count == 0u);
    CHECK(((ftun_proxy_egress_t *)fixture.dns->egress->context)->nodes[1].resolved);
  }
  fixture.selector.force = true;
  for (index = 0u; index < 4u; index++) {
    fixture.selector.forced_member = denied[index];
    CHECK(ftun_dns_runtime_transport_select(fixture.dns, 2u, &changed) == FTUN_E_REJECTED);
    CHECK(changed.scope == NULL && changed.root_id == 0u && changed.leaf_id == 0u);
  }
  CHECK(fixture_destroy(&fixture) == 0);
  puts("query binding invalid scope/root/leaf and unauthorized choices passed");
  return 0;
}

static int coalescing_case(bool reload_generation)
{
  fixture_t fixture;
  completion_t completions[3] = {{0u, FTUN_OK, 0u}};
  ftun_operation_t *operations[3] = {NULL, NULL, NULL};
  size_t count;
  CHECK(fixture_init(&fixture, reload_generation ? 0 : 5) == 0);
  CHECK(query_start(&fixture, 21u, &completions[0], &operations[0]) == 0);
  CHECK(wait_udp(&fixture, 0u, 1u) == 0);
  if (reload_generation) {
    CHECK(reload(&fixture, 1) == 0);
    CHECK(query_start(&fixture, 22u, &completions[1], &operations[1]) == 0);
    CHECK(fixture.dns->request_count == 1u && fixture.retired->request_count == 1u);
    CHECK(ftun_dns_runtime_reap(&fixture.retired) == FTUN_E_AGAIN);
    fixture.proxies[0].release_tc = true;
    CHECK(wait_completion(&fixture, &completions[0]) == 0);
    CHECK(wait_completion(&fixture, &completions[1]) == 0);
    CHECK(fixture.proxies[0].udp_queries == 2u && fixture.proxies[0].tcp_queries == 2u);
    CHECK(fixture.selector.calls == 2u);
  } else {
    CHECK(query_start(&fixture, 22u, &completions[1], &operations[1]) == 0);
    CHECK(fixture.dns->request_count == 1u && fixture.dns->waiter_count == 2u);
    CHECK(ftun_operation_cancel(operations[0]) == FTUN_OK);
    CHECK(ftun_operation_dispatch(fixture.operations, 8u, &count) == FTUN_OK && count == 1u);
    CHECK(completions[0].calls == 1u && completions[0].status == FTUN_E_CANCELLED);
    CHECK(fixture.dns->request_count == 1u && fixture.dns->waiter_count == 1u);
    CHECK(ftun_runtime_select_names(fixture.core, (ftun_string_t){"G",1u},
      (ftun_string_t){"B",1u}) == FTUN_OK);
    CHECK(query_start(&fixture, 23u, &completions[2], &operations[2]) == 0);
    CHECK(wait_udp(&fixture, 1u, 1u) == 0);
    CHECK(fixture.dns->request_count == 2u && fixture.dns->waiter_count == 2u);
    fixture.proxies[0].release_tc = true;
    fixture.proxies[1].release_tc = true;
    CHECK(wait_completion(&fixture, &completions[1]) == 0);
    CHECK(wait_completion(&fixture, &completions[2]) == 0);
    CHECK(completions[0].calls == 1u && fixture.selector.calls == 3u);
    CHECK(fixture.proxies[0].udp_queries == 1u && fixture.proxies[0].tcp_queries == 1u);
    CHECK(fixture.proxies[1].udp_queries == 1u && fixture.proxies[1].tcp_queries == 1u);
  }
  CHECK(fixture_destroy(&fixture) == 0);
  printf("query coalescing reload_generation=%u passed\n", reload_generation);
  return 0;
}

static int retired_termination_case(bool timeout)
{
  fixture_t fixture;
  completion_t completion = {0u, FTUN_OK, 0u};
  ftun_operation_t *operation = NULL;
  uint64_t deadline;
  size_t count;
  CHECK(fixture_init(&fixture, 0) == 0);
  fixture.proxies[0].withhold_tcp = true;
  deadline = test_now() + 1000u;
  CHECK(query_start_until(&fixture, 31u, &completion, &operation, deadline) == 0);
  CHECK(wait_udp(&fixture, 0u, 1u) == 0);
  CHECK(reload(&fixture, 1) == 0);
  CHECK(ftun_dns_runtime_reap(&fixture.retired) == FTUN_E_AGAIN);
  fixture.proxies[0].release_tc = true;
  while (fixture.proxies[0].tcp_queries == 0u &&
         test_now() < deadline) CHECK(pump(&fixture) == 0);
  CHECK(fixture.proxies[0].tcp_queries == 1u && completion.calls == 0u);
  {
    ftun_dns_runtime_transport_request_t *request = fixture.retired->request_head;
    while (request != NULL && request->transport != FTUN_DNS_TRANSPORT_TCP) {
      request = request->next;
    }
    CHECK(request != NULL && request->waiter_head != NULL &&
      request->waiter_head->deadline_ms == deadline);
  }
  CHECK(ftun_dns_runtime_reap(&fixture.retired) == FTUN_E_AGAIN);
  if (timeout) {
    while (completion.calls == 0u && test_now() < deadline + 1000u) {
      CHECK(pump(&fixture) == 0);
      CHECK(poll(NULL, 0u, 1) == 0);
    }
  } else {
    CHECK(ftun_operation_cancel(operation) == FTUN_OK);
    CHECK(ftun_dns_runtime_reap(&fixture.retired) == FTUN_E_AGAIN);
    CHECK(ftun_operation_dispatch(fixture.operations, 8u, &count) == FTUN_OK && count == 1u);
  }
  CHECK(completion.calls == 1u && completion.length == 0u &&
        completion.status == (timeout ? FTUN_E_TIMEOUT : FTUN_E_CANCELLED));
  CHECK(fixture.selector.calls == 1u && fixture.proxies[0].authentications == 2u);
  CHECK(ftun_dns_runtime_reap(&fixture.retired) == FTUN_OK && fixture.retired == NULL);
  CHECK(pump(&fixture) == 0);
  CHECK(completion.calls == 1u && fixture.proxies[1].tcp_queries == 0u);
  CHECK(fixture_destroy(&fixture) == 0);
  printf("query retired TCP termination timeout=%u passed\n", timeout);
  return 0;
}

int main(void)
{
  int variant;
  for (variant = 1; variant <= 6; variant++) CHECK(generation_case(variant) == 0);
  CHECK(invalid_binding_case() == 0);
  CHECK(coalescing_case(false) == 0);
  CHECK(coalescing_case(true) == 0);
  CHECK(retired_termination_case(false) == 0);
  CHECK(retired_termination_case(true) == 0);
  puts("DNS query binding: 11 scenarios passed; FD baseline restored for every fixture");
  return 0;
}
