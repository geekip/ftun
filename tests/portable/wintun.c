#include "platform/windows/tun.h"
#include "platform/windows/tun_config.h"
#include "platform/clock.h"
#include "core/event/backend.h"
#include "core/event/loop.h"
#include "libs/tun/port.h"
#include "libs/tun/service.h"
#include "libs/tun/interface_backend.h"
#include "libs/tun/owner.h"
#include "app/config/model.h"
#include "core/context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "Wintun contract: %d: %s\n", __LINE__, #x); exit(1); } } while (0)

typedef struct {
  HANDLE event;
  WCHAR name[16];
  BYTE packet[2048], sent[2048];
  DWORD packet_size, send_size;
  size_t rx_remaining, released, tx_attempts, sent_count, creates, closes, ends;
  int fail;
  bool active, existing, blocked;
} fixture_t;
static fixture_t fixture;
static WINTUN_ADAPTER_HANDLE WINAPI create_adapter(LPCWSTR name, LPCWSTR type, const GUID *guid)
{
  (void)guid;
  CHECK(wcscmp(type, L"FTUN") == 0);
  fixture.creates++;
  if (fixture.fail == 1) { SetLastError(ERROR_ACCESS_DENIED); return NULL; }
  fixture.active = true;
  wcscpy(fixture.name, name);
  return (WINTUN_ADAPTER_HANDLE)&fixture;
}
static void WINAPI close_adapter(WINTUN_ADAPTER_HANDLE adapter)
{ CHECK(adapter == (WINTUN_ADAPTER_HANDLE)&fixture && fixture.active); fixture.active = false; fixture.closes++; }
static void WINAPI get_luid(WINTUN_ADAPTER_HANDLE adapter, NET_LUID *luid)
{ CHECK(adapter == (WINTUN_ADAPTER_HANDLE)&fixture); luid->Value = 1234u; }
static WINTUN_SESSION_HANDLE WINAPI start_session(WINTUN_ADAPTER_HANDLE adapter, DWORD capacity)
{
  CHECK(adapter == (WINTUN_ADAPTER_HANDLE)&fixture && capacity == 1024u * 1024u);
  if (fixture.fail == 2) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
  fixture.event = CreateEventW(NULL, FALSE, FALSE, NULL);
  CHECK(fixture.event != NULL);
  return (WINTUN_SESSION_HANDLE)&fixture;
}
static void WINAPI end_session(WINTUN_SESSION_HANDLE session)
{ CHECK(session == (WINTUN_SESSION_HANDLE)&fixture); CHECK(CloseHandle(fixture.event)); fixture.event = NULL; fixture.ends++; }
static HANDLE WINAPI read_event(WINTUN_SESSION_HANDLE session)
{ CHECK(session == (WINTUN_SESSION_HANDLE)&fixture); return fixture.fail == 3 ? NULL : fixture.event; }
static BYTE *WINAPI receive_packet(WINTUN_SESSION_HANDLE session, DWORD *size)
{
  CHECK(session == (WINTUN_SESSION_HANDLE)&fixture);
  if (fixture.fail == 4) { SetLastError(ERROR_INVALID_DATA); return NULL; }
  if (fixture.rx_remaining == 0u) { SetLastError(ERROR_NO_MORE_ITEMS); return NULL; }
  fixture.rx_remaining--; *size = fixture.packet_size;
  return fixture.packet;
}
static void WINAPI release_packet(WINTUN_SESSION_HANDLE session, const BYTE *packet)
{ CHECK(session == (WINTUN_SESSION_HANDLE)&fixture && packet == fixture.packet); fixture.released++; }
static BYTE *WINAPI allocate_send(WINTUN_SESSION_HANDLE session, DWORD size)
{
  CHECK(session == (WINTUN_SESSION_HANDLE)&fixture && size <= sizeof(fixture.sent));
  fixture.tx_attempts++;
  if (fixture.blocked) { SetLastError(ERROR_BUFFER_OVERFLOW); return NULL; }
  fixture.send_size = size;
  return fixture.sent;
}
static void WINAPI send_packet(WINTUN_SESSION_HANDLE session, const BYTE *packet)
{ CHECK(session == (WINTUN_SESSION_HANDLE)&fixture && packet == fixture.sent); fixture.sent_count++; }
static NETIO_STATUS WINAPI alias_to_luid(PCWSTR alias, PNET_LUID luid)
{
  CHECK(alias != NULL);
  if (fixture.active || fixture.existing) { luid->Value = 1234u; return NO_ERROR; }
  return ERROR_INVALID_PARAMETER; /* Windows 对未找到的别名也使用此错误。 */
}
static NETIO_STATUS WINAPI luid_to_alias(const NET_LUID *luid, PWSTR alias, SIZE_T size)
{
  CHECK(luid->Value == 1234u && size >= 16u);
  wcscpy(alias, fixture.fail == 5 ? L"ftun-renamed" : fixture.name);
  return NO_ERROR;
}
static const ftun_platform_tun_io_t fake_io = {
  create_adapter, close_adapter, get_luid, start_session, end_session,
  read_event, receive_packet, release_packet, allocate_send, send_packet, alias_to_luid, luid_to_alias
};
static ftun_budget_t *budget(size_t bytes, size_t handles)
{
  ftun_budget_t *result = NULL;
  ftun_budget_options_t options = {{bytes, handles, 4096u}, {0}, {0}};
  CHECK(ftun_budget_create_resources(NULL, &options, &result) == FTUN_OK);
  return result;
}
static void empty_budget(ftun_budget_t **root)
{
  ftun_budget_usage_t usage;
  CHECK(ftun_budget_get_usage(*root, &usage) == FTUN_OK);
  CHECK(usage.used_resources.memory_bytes == 0u && usage.used_resources.descriptors == 0u && usage.used_resources.queue_slots == 0u);
  CHECK(ftun_budget_destroy(root) == FTUN_OK);
}
static ftun_tun_spec_t spec(void)
{ return (ftun_tun_spec_t){{"ftun-test", 9u}, 1500u}; }
static void port_contract(void)
{
  ftun_tun_spec_t device = spec();
  ftun_packet_port_t *port = NULL;
  ftun_budget_t *root;
  ftun_tun_port_info_t info;
  BYTE buffer[2048]; size_t size;
  ftun_budget_usage_t usage;
  root = budget(1024u, 64u);
  CHECK(ftun_tun_port_open_with_io_and_budget(root, &device, &fake_io, &port) == FTUN_E_LIMIT && port == NULL);
  CHECK(fixture.creates == 0u); empty_budget(&root);
  root = budget(8u * 1024u * 1024u, 13u);
  CHECK(ftun_tun_port_open_with_io_and_budget(root, &device, &fake_io, &port) == FTUN_E_LIMIT);
  CHECK(fixture.creates == 0u); empty_budget(&root);
  root = budget(8u * 1024u * 1024u, 64u);
  for (int failure = 1; failure <= 5; failure++) {
    if (failure == 4) continue;
    fixture.fail = failure;
    ftun_status_t expected = failure == 2 ? FTUN_E_LIMIT : failure == 3 ? FTUN_E_IO : FTUN_E_REJECTED;
    CHECK(ftun_tun_port_open_with_io_and_budget(root, &device, &fake_io, &port) == expected && port == NULL);
    CHECK(fixture.creates == (size_t)(failure == 5 ? 4 : failure));
    CHECK(!fixture.active && fixture.event == NULL);
    CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u && usage.used_resources.descriptors == 0u);
  }
  fixture.fail = 0;
  size_t creates = fixture.creates;
  fixture.existing = true;
  ftun_status_t collision = ftun_tun_port_open_with_io_and_budget(root, &device, &fake_io, &port);
  CHECK(collision == FTUN_E_REJECTED);
  CHECK(fixture.creates == creates && fixture.closes == creates - 1u);
  fixture.existing = false;
  CHECK(ftun_tun_port_open_with_io_and_budget(root, &device, &fake_io, &port) == FTUN_OK);
  CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK && usage.used_resources.memory_bytes > 2u * 1024u * 1024u && usage.used_resources.descriptors == 14u);
  CHECK(ftun_tun_port_get_info(port, &info) == FTUN_OK && info.mtu == 1500u && info.flags == (FTUN_PACKET_PORT_WAITABLE | FTUN_PACKET_PORT_WRITE_TIMER));
  CHECK(ftun_tun_port_read(port, buffer, sizeof(buffer), &size) == FTUN_E_AGAIN && size == 0u);
  memset(fixture.packet, 0x45, 20u); fixture.packet_size = 20u; fixture.rx_remaining = 1u;
  CHECK(ftun_tun_port_read(port, buffer, sizeof(buffer), &size) == FTUN_OK && size == 20u && memcmp(buffer, fixture.packet, size) == 0);
  CHECK(fixture.released == 1u);
  fixture.packet_size = 1600u; fixture.rx_remaining = 1u;
  CHECK(ftun_tun_port_read(port, buffer, 1500u, &size) == FTUN_E_LIMIT && fixture.released == 2u);
  fixture.fail = 4;
  CHECK(ftun_tun_port_read(port, buffer, sizeof(buffer), &size) == FTUN_E_IO);
  fixture.fail = 0;
  fixture.blocked = true;
  CHECK(ftun_tun_port_write(port, buffer, 20u) == FTUN_E_AGAIN && fixture.sent_count == 0u);
  fixture.blocked = false;
  CHECK(ftun_tun_port_write(port, buffer, 20u) == FTUN_OK && fixture.sent_count == 1u && memcmp(fixture.sent, buffer, 20u) == 0);
  CHECK(ftun_tun_port_close(&port) == FTUN_OK && !fixture.active && fixture.event == NULL);
  empty_budget(&root);
}

typedef struct { size_t created, deleted, sets; bool fail_create, fail_delete; } config_fixture_t;
static config_fixture_t configuration;
static void WINAPI initialize_interface(PMIB_IPINTERFACE_ROW row)
{ memset(row, 0, sizeof(*row)); }
static void WINAPI initialize_address(PMIB_UNICASTIPADDRESS_ROW row)
{
  memset(row, 0, sizeof(*row));
  row->ValidLifetime = row->PreferredLifetime = 0xffffffffu;
}
static NETIO_STATUS WINAPI get_interface(PMIB_IPINTERFACE_ROW row)
{
  CHECK(row->InterfaceLuid.Value == 1234u && (row->Family == AF_INET || row->Family == AF_INET6));
  row->SitePrefixLength = row->Family == AF_INET ? 32u : 64u;
  return NO_ERROR;
}
static NETIO_STATUS WINAPI set_interface(PMIB_IPINTERFACE_ROW row)
{
  CHECK(row->NlMtu == 1500u && row->DadTransmits == 0u && row->RouterDiscoveryBehavior == RouterDiscoveryDisabled);
  CHECK(row->Family != AF_INET || row->SitePrefixLength == 0u);
  configuration.sets++; return NO_ERROR;
}
static NETIO_STATUS WINAPI create_address(const MIB_UNICASTIPADDRESS_ROW *row)
{
  CHECK(row->InterfaceLuid.Value == 1234u && row->DadState == IpDadStatePreferred);
  CHECK(row->PrefixOrigin == IpPrefixOriginManual && row->SuffixOrigin == IpSuffixOriginManual);
  CHECK(row->ValidLifetime == 0xffffffffu && row->PreferredLifetime == 0xffffffffu);
  if (configuration.fail_create && row->Address.si_family == AF_INET6) return ERROR_GEN_FAILURE;
  CHECK(row->Address.si_family == AF_INET ? row->OnLinkPrefixLength == 30u : row->OnLinkPrefixLength == 126u);
  configuration.created++; return NO_ERROR;
}
static NETIO_STATUS WINAPI delete_address(const MIB_UNICASTIPADDRESS_ROW *row)
{
  CHECK(row->InterfaceLuid.Value == 1234u);
  if (configuration.fail_delete) return ERROR_ACCESS_DENIED;
  configuration.deleted++; return NO_ERROR;
}
static void configuration_contract(void)
{
  ftun_interface_ops_t ops = ftun_interface_default_ops;
  ftun_windows_tun_config_io_t io = {initialize_interface, initialize_address, alias_to_luid, get_interface, set_interface, create_address, delete_address};
  ftun_interface_spec_t network = {0};
  ftun_budget_t *root = budget(1024u * 1024u, 16u);
  ftun_budget_usage_t usage;
  void *state = NULL;
  fixture.active = true;
  network.name = spec().name; network.mtu = 1500u; network.budget = root; network.address_count = 2u;
  CHECK(ftun_cidr_parse("172.31.255.1/30", sizeof("172.31.255.1/30") - 1u, false, &network.addresses[0]));
  CHECK(ftun_cidr_parse("fd00:ffff::1/126", sizeof("fd00:ffff::1/126") - 1u, false, &network.addresses[1]));
  ops.context = &io;
  CHECK(ops.configure_when_manual);
  CHECK(ops.restore(ops.context, &network, &state) == FTUN_OK && state != NULL);
  CHECK(configuration.created == 2u && configuration.sets == 2u);
  CHECK(ops.withdraw(ops.context, &state) == FTUN_OK && state == NULL && configuration.deleted == 2u);
  configuration.fail_create = true;
  CHECK(ops.restore(ops.context, &network, &state) == FTUN_E_IO && state != NULL);
  configuration.fail_delete = true;
  CHECK(ops.withdraw(ops.context, &state) == FTUN_E_REJECTED && state != NULL);
  CHECK(ftun_budget_get_usage(root, &usage) == FTUN_OK && usage.used_resources.memory_bytes != 0u);
  configuration.fail_delete = false;
  CHECK(ops.withdraw(ops.context, &state) == FTUN_OK && state == NULL && configuration.deleted == 3u);
  fixture.active = false;
  empty_budget(&root);
}
static ftun_status_t device_open(void *user, ftun_core_t *core, const ftun_tun_spec_t *device, ftun_packet_port_t **port)
{ (void)core; return ftun_tun_port_open_with_io_and_budget(user, device, &fake_io, port); }
static ftun_status_t device_info(void *user, const ftun_packet_port_t *port, ftun_packet_port_info_t *info)
{ (void)user; return ftun_packet_port_get_info(port, info); }
static ftun_status_t device_read(void *user, ftun_packet_port_t *port, void *buffer, size_t capacity, size_t *size)
{ (void)user; return ftun_packet_port_read(port, buffer, capacity, size); }
static ftun_status_t device_write(void *user, ftun_packet_port_t *port, const void *packet, size_t size)
{ (void)user; return ftun_packet_port_write(port, packet, size); }
static ftun_status_t device_close(void *user, ftun_packet_port_t **port)
{ (void)user; return ftun_packet_port_close(port); }
static size_t consumed;
static ftun_status_t consume(void *user, ftun_tun_lease_t lease, ftun_bytes_t packet)
{
  (void)user; (void)lease;
  CHECK(packet.length == fixture.packet_size && memcmp(packet.data, fixture.packet, packet.length) == 0);
  consumed++; return FTUN_OK;
}
static void drive(ftun_event_loop_t *loop, ftun_tun_service_t *service)
{
  size_t callbacks, work;
  CHECK(ftun_event_loop_run_once(loop, false, 64u, &callbacks) == FTUN_OK);
  CHECK(ftun_tun_service_run(service, &work) == FTUN_OK);
}
static void service_contract(void)
{
  ftun_budget_t *root = budget(16u * 1024u * 1024u, 128u);
  ftun_event_loop_t *loop = NULL;
  ftun_buffer_pool_t *buffers = NULL;
  ftun_tun_service_t *service = NULL;
  ftun_tun_lease_t lease = {0}, stale;
  ftun_tun_service_spec_t options = {0};
  ftun_tun_service_usage_t usage;
  ftun_tun_device_ops_t ops = {device_open, device_info, device_read, device_write, device_close, root};
  ftun_tun_consumer_t consumer = {consume, NULL, NULL, NULL};
  memset(&fixture, 0, sizeof(fixture));
  CHECK(ftun_event_loop_create_with_budget(NULL, root, 64u, &loop) == FTUN_OK);
  CHECK(ftun_event_backend_attach(loop) == FTUN_OK);
  CHECK(ftun_buffer_pool_create(root, 0u, 0u, &buffers) == FTUN_OK);
  options.budget = root; options.loop = loop; options.buffers = buffers; options.device = spec();
  options.output_capacity = 2u; options.input_capacity = 4u;
  options.read_quota = 2u; options.write_quota = 2u;
  ftun_status_t created = ftun_tun_service_create_with_ops(&options, &ops, &service);
  CHECK(created == FTUN_OK);
  CHECK(ftun_tun_service_acquire(service, &consumer, &lease) == FTUN_OK);
  fixture.packet_size = 40u; fixture.packet[0] = 0x60u; fixture.rx_remaining = 70u;
  CHECK(SetEvent(fixture.event)); /* 一个自动复位信号必须排空多轮配额。 */
  for (size_t i = 0u; i < 200u && consumed < 70u; i++) drive(loop, service);
  CHECK(consumed == 70u && fixture.released == 70u);
  size_t callbacks;
  CHECK(ftun_event_loop_run_once(loop, false, 64u, &callbacks) == FTUN_OK);
  CHECK(SetEvent(fixture.event)); fixture.rx_remaining = 1u;
  uint64_t now, deadline;
  CHECK(ftun_monotonic_now(&now) == FTUN_OK); deadline = now + 5000u;
  while (consumed != 71u) { drive(loop, service); CHECK(ftun_monotonic_now(&now) == FTUN_OK && now < deadline); }
  fixture.blocked = true;
  ftun_bytes_t packet = {fixture.packet, fixture.packet_size};
  CHECK(ftun_tun_service_write(lease, packet) == FTUN_OK);
  CHECK(ftun_tun_service_write(lease, packet) == FTUN_OK);
  CHECK(ftun_tun_service_write(lease, packet) == FTUN_E_LIMIT);
  size_t attempts = fixture.tx_attempts;
  uint64_t started;
  CHECK(ftun_monotonic_now(&started) == FTUN_OK);
  for (size_t i = 0u; i < 20u; i++) drive(loop, service);
  CHECK(ftun_tun_service_get_usage(service, &usage) == FTUN_OK && usage.queued_packets == 2u && fixture.sent_count == 0u);
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  CHECK(fixture.tx_attempts - attempts <= now - started + 1u); /* 无全速写就绪空转。 */
  fixture.blocked = false;
  CHECK(ftun_monotonic_now(&now) == FTUN_OK); deadline = now + 5000u;
  while (fixture.sent_count != 2u) { drive(loop, service); CHECK(ftun_monotonic_now(&now) == FTUN_OK && now < deadline); }
  CHECK(memcmp(fixture.sent, fixture.packet, fixture.packet_size) == 0);
  fixture.blocked = true;
  CHECK(ftun_tun_service_write(lease, packet) == FTUN_OK);
  CHECK(SetEvent(fixture.event));
  CHECK(ftun_tun_service_rebuild(service) == FTUN_OK && fixture.ends == 1u && fixture.closes == 1u);
  CHECK(ftun_tun_service_get_usage(service, &usage) == FTUN_OK && usage.device_generation == 2u && usage.queued_packets == 0u);
  fixture.rx_remaining = 0u;
  stale = lease;
  CHECK(ftun_tun_service_quiesce(service) == FTUN_OK);
  CHECK(ftun_tun_service_release(&lease) == FTUN_OK);
  CHECK(ftun_tun_service_write(stale, packet) == FTUN_E_STALE);
  CHECK(ftun_tun_service_destroy(&service) == FTUN_OK && fixture.ends == 2u && fixture.closes == 2u);
  CHECK(ftun_buffer_pool_destroy(&buffers) == FTUN_OK);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_backend_detach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  empty_budget(&root);
}
static void owner_contract(void)
{
  ftun_budget_t *root = budget(16u * 1024u * 1024u, 128u);
  ftun_core_t *core = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_config_t config = {0};
  ftun_l3_provider_t provider = {0};
  ftun_tun_device_ops_t device = {device_open, device_info, device_read, device_write, device_close, root};
  ftun_interface_ops_t network = ftun_interface_default_ops;
  ftun_windows_tun_config_io_t io = {initialize_interface, initialize_address,
    alias_to_luid, get_interface, set_interface, create_address, delete_address};
  void *owner = NULL;
  memset(&fixture, 0, sizeof(fixture)); memset(&configuration, 0, sizeof(configuration));
  ftun_config_bind_sections(&config);
  config.tun.present = true; config.tun.interface_name = "ftun-test"; config.tun.mtu = 1500u;
  config.tun.ipv4_address = "172.31.255.1/30"; config.tun.ipv6_address = "fd00:ffff::1/126";
  CHECK(ftun_core_context_create(root, &core) == FTUN_OK);
  CHECK(ftun_event_loop_create_with_budget(core, root, 16u, &loop) == FTUN_OK);
  CHECK(ftun_event_backend_attach(loop) == FTUN_OK);
  network.context = &io;
  ftun_tun_owner_binding_t host = {&provider, loop, &device, &network, 18004u};
  ftun_core_service_binding_t binding = {&host, sizeof(host)};
  CHECK(ftun_tun_owner_service.prepare(core, root, NULL, &binding, &config, 1u, &owner) == FTUN_OK);
  CHECK(ftun_tun_owner_service.activate(owner) == FTUN_OK && provider.service != NULL);
  CHECK(!config.tun.auto_route && configuration.created == 2u && configuration.sets == 2u);
  CHECK(ftun_tun_owner_service.reload_prepare(owner, &config, 2u) == FTUN_OK);
  CHECK(ftun_tun_owner_service.reload_abort(owner) == FTUN_OK);
  config.tun.ipv6_address = "fd00:ffff::5/126";
  CHECK(ftun_tun_owner_service.reload_prepare(owner, &config, 2u) == FTUN_E_RESTART_REQUIRED);
  config.tun.ipv6_address = "fd00:ffff::1/126";
  configuration.fail_delete = true;
  CHECK(ftun_tun_owner_service.destroy_until(&owner, 100u) == FTUN_E_REJECTED && owner != NULL && fixture.active);
  configuration.fail_delete = false;
  CHECK(ftun_tun_owner_service.destroy_until(&owner, 100u) == FTUN_OK && owner == NULL && !fixture.active);
  CHECK(configuration.deleted == 2u && provider.service == NULL);
  configuration.fail_create = true;
  CHECK(ftun_tun_owner_service.prepare(core, root, NULL, &binding, &config, 3u, &owner) == FTUN_OK);
  CHECK(ftun_tun_owner_service.activate(owner) == FTUN_E_IO && provider.service == NULL);
  CHECK(ftun_tun_owner_service.destroy_until(&owner, 100u) == FTUN_OK && owner == NULL && !fixture.active);
  CHECK(configuration.deleted == 3u);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK && ftun_event_backend_detach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  empty_budget(&root);
}

int main(int argc, char **argv)
{
  ftun_platform_tun_io_t io;
  HMODULE module;
  if (argc == 2 && strcmp(argv[1], "missing-dll") == 0) {
    CHECK(ftun_windows_tun_load(&io, &module) == FTUN_E_UNSUPPORTED && module == NULL);
    puts("Wintun: missing executable-sibling DLL rejected"); return 0;
  }
  CHECK(ftun_windows_tun_load(&io, &module) == FTUN_OK && module != NULL);
  CHECK(FreeLibrary(module));
  port_contract(); configuration_contract(); service_contract(); owner_contract();
  puts("Wintun: official DLL exports, API packet ownership, admission, rollback, events, backpressure and quiescence passed (driver not exercised)");
  return 0;
}
