#include "libs/tun/linux/routes.h"
#include "libs/tun/linux/device.h"
#include "platform/linux/uapi.h"
#include "core/limits.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "linux route contract failed: %s\n", #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  ftun_linux_route_resource_t applied[FTUN_LINUX_ROUTE_MAX_RESOURCES];
  ftun_linux_route_resource_t removed[FTUN_LINUX_ROUTE_MAX_RESOURCES * 2u];
  size_t apply_calls;
  size_t remove_calls;
  size_t fail_apply_call;
  ftun_status_t fail_apply_status;
  size_t fail_remove_call;
  ftun_status_t fail_remove_status;
} route_mock_t;

static ftun_status_t mock_apply(void *context,
                                const ftun_linux_route_resource_t *resource)
{
  route_mock_t *mock = (route_mock_t *)context;
  if (mock->apply_calls < FTUN_LINUX_ROUTE_MAX_RESOURCES) {
    mock->applied[mock->apply_calls] = *resource;
  }
  mock->apply_calls++;
  if (mock->fail_apply_call == mock->apply_calls) return mock->fail_apply_status;
  return FTUN_OK;
}

static ftun_status_t mock_remove(void *context,
                                 const ftun_linux_route_resource_t *resource)
{
  route_mock_t *mock = (route_mock_t *)context;
  if (mock->remove_calls < FTUN_LINUX_ROUTE_MAX_RESOURCES * 2u) {
    mock->removed[mock->remove_calls] = *resource;
  }
  mock->remove_calls++;
  if (mock->fail_remove_call == mock->remove_calls) {
    mock->fail_remove_call = 0u;
    return mock->fail_remove_status;
  }
  return FTUN_OK;
}

static ftun_linux_route_io_t mock_io(route_mock_t *mock)
{
  ftun_linux_route_io_t io;
  io.apply = mock_apply;
  io.remove = mock_remove;
  io.context = mock;
  return io;
}

static ftun_route_policy_t route_policy(bool lan, bool strict_route)
{
  ftun_route_policy_t policy;
  memset(&policy, 0, sizeof(policy));
  policy.tun_interface.data = "ftun-route0";
  policy.tun_interface.length = strlen(policy.tun_interface.data);
  policy.tun_ipv4[0] = 10u;
  policy.tun_ipv4[1] = 77u;
  policy.tun_ipv4[2] = 0u;
  policy.tun_ipv4[3] = 1u;
  policy.tun_prefix_length = 30u;
  policy.route_table = 100u;
  policy.rule_priority = 12340u;
  policy.protection_mark = UINT32_C(0x46000001);
  policy.protection_mark_mask = UINT32_MAX;
  policy.manage_local = true;
  if (lan) {
    policy.lan_interface.data = "lan0";
    policy.lan_interface.length = strlen(policy.lan_interface.data);
  }
  policy.strict_route = strict_route;
  return policy;
}

static int check_resource_plan(const route_mock_t *mock)
{
  CHECK(mock->apply_calls == FTUN_LINUX_ROUTE_MAX_RESOURCES);
  CHECK(mock->applied[0].kind == FTUN_LINUX_ROUTE_ADDRESS &&
        mock->applied[0].family == AF_INET &&
        strcmp(mock->applied[0].interface_name, "ftun-route0") == 0 &&
        mock->applied[0].address[0] == 10u &&
        mock->applied[0].prefix_length == 30u);
  CHECK(mock->applied[1].kind == FTUN_LINUX_ROUTE_MARK_RULE &&
        mock->applied[1].table == FTUN_RT_TABLE_MAIN &&
        mock->applied[1].priority == 12340u &&
        mock->applied[1].mark == UINT32_C(0x46000001) &&
        mock->applied[1].mark_mask == UINT32_MAX);
  CHECK(mock->applied[2].kind == FTUN_LINUX_ROUTE_DEFAULT &&
        mock->applied[2].table == 100u &&
        strcmp(mock->applied[2].interface_name, "ftun-route0") == 0);
  CHECK(mock->applied[3].kind == FTUN_LINUX_ROUTE_CAPTURE_RULE &&
        mock->applied[3].family == AF_INET &&
        strcmp(mock->applied[3].interface_name, "lo") == 0 &&
        mock->applied[3].priority == 12341u);
  CHECK(mock->applied[4].kind == FTUN_LINUX_ROUTE_CAPTURE_RULE &&
        strcmp(mock->applied[4].interface_name, "lan0") == 0 &&
        mock->applied[4].priority == 12342u);
  CHECK(mock->applied[5].kind == FTUN_LINUX_ROUTE_BLOCK_IPV6 &&
        mock->applied[5].family == AF_INET6 &&
        strcmp(mock->applied[5].interface_name, "lo") == 0 &&
        mock->applied[5].priority == 12341u);
  CHECK(mock->applied[6].kind == FTUN_LINUX_ROUTE_BLOCK_IPV6 &&
        strcmp(mock->applied[6].interface_name, "lan0") == 0 &&
        mock->applied[6].priority == 12342u);
  CHECK(mock->applied[6].protocol == FTUN_LINUX_ROUTE_PROTOCOL);
  return 0;
}

static int real_smoke(void)
{
  ftun_tun_spec_t tun_spec;
  ftun_tun_spec_t lan_spec;
  ftun_packet_port_t *port = NULL;
  ftun_packet_port_t *lan_port = NULL;
  ftun_route_policy_t policy = route_policy(false, true);
  ftun_route_transaction_t *transaction = NULL;
  ftun_route_transaction_t *duplicate = NULL;
  ftun_linux_route_info_t info;
  tun_spec.name = policy.tun_interface;
  tun_spec.mtu = 1400u;
  CHECK(ftun_linux_tun_open(&tun_spec, &port) == FTUN_OK && port != NULL);
  CHECK(ftun_linux_route_prepare(&policy, &transaction) == FTUN_OK &&
        transaction != NULL);
  CHECK(ftun_linux_route_get_info(transaction, &info) == FTUN_OK &&
        info.resource_count == 5u && info.active_count == 5u &&
        info.strict_route);
  CHECK(ftun_linux_route_prepare(&policy, &duplicate) == FTUN_E_REJECTED &&
        duplicate == NULL);
  CHECK(ftun_linux_route_release(&transaction) == FTUN_OK && transaction == NULL);
  CHECK(ftun_linux_route_prepare(&policy, &transaction) == FTUN_OK);
  CHECK(ftun_linux_route_release(&transaction) == FTUN_OK);
  lan_spec.name.data = "lan0";
  lan_spec.name.length = strlen(lan_spec.name.data);
  lan_spec.mtu = 1400u;
  CHECK(ftun_linux_tun_open(&lan_spec, &lan_port) == FTUN_OK && lan_port != NULL);
  policy = route_policy(true, true);
  policy.manage_local = false;
  CHECK(ftun_linux_route_prepare(&policy, &transaction) == FTUN_OK);
  CHECK(ftun_linux_route_get_info(transaction, &info) == FTUN_OK &&
        info.resource_count == 5u && info.active_count == 5u &&
        info.strict_route);
  CHECK(ftun_linux_route_release(&transaction) == FTUN_OK);
  CHECK(ftun_linux_tun_close(&lan_port) == FTUN_OK);
  CHECK(ftun_linux_tun_close(&port) == FTUN_OK);
  return 0;
}

/* 冲突、反序回滚和所有权清理。 */
static int owned_budget(void)
{
  ftun_budget_options_t options = {0};
  ftun_budget_t *budget = NULL;
  ftun_reservation_t hold = (ftun_reservation_t){0};
  ftun_budget_usage_t usage;
  ftun_route_transaction_t *transaction = NULL;
  ftun_route_policy_t policy = route_policy(false, false);
  route_mock_t mock = {0};
  ftun_linux_route_io_t io = mock_io(&mock);
  options.limit = (ftun_budget_resources_t){65536u, 2u, 1u};
  options.cleanup_reserve.descriptors = 1u;
  CHECK(ftun_budget_create_resources(NULL, &options, &budget) == FTUN_OK);
  CHECK(ftun_budget_reserve_resources(budget,
    (ftun_budget_resources_t){0u, 1u, 0u}, &hold) == FTUN_OK);
  CHECK(ftun_linux_route_prepare_with_io_and_budget(budget, &policy, &io,
    &transaction) == FTUN_E_LIMIT && transaction == NULL && mock.apply_calls == 0u);
  CHECK(ftun_reservation_release(&hold) == FTUN_OK);
  CHECK(ftun_linux_route_prepare_with_io_and_budget(budget, &policy, &io,
    &transaction) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used > 0u &&
    usage.used_resources.descriptors == 0u);
  CHECK(ftun_budget_reserve_resources(budget,
    (ftun_budget_resources_t){0u, 1u, 0u}, &hold) == FTUN_OK);
  CHECK(ftun_linux_route_release(&transaction) == FTUN_OK && transaction == NULL);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == 0u &&
    usage.used_resources.descriptors == 1u && usage.high_watermarks.descriptors == 2u);
  CHECK(ftun_reservation_release(&hold) == FTUN_OK);
  memset(&mock, 0, sizeof(mock));
  mock.fail_apply_call = 2u;
  mock.fail_apply_status = FTUN_E_IO;
  mock.fail_remove_call = 1u;
  mock.fail_remove_status = FTUN_E_IO;
  CHECK(ftun_linux_route_prepare_with_io_and_budget(budget, &policy, &io,
    &transaction) == FTUN_E_STATE_CORRUPT && transaction != NULL);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used > 0u &&
    usage.used_resources.descriptors == 0u);
  CHECK(ftun_linux_route_release(&transaction) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

int main(int argc, char **argv)
{
  route_mock_t mock;
  ftun_linux_route_io_t io;
  ftun_linux_route_io_t incomplete;
  ftun_route_policy_t policy = route_policy(true, true);
  ftun_route_transaction_t *transaction = NULL;
  ftun_linux_route_info_t info;
  size_t index;

  if (argc == 2 && strcmp(argv[1], "--real") == 0) return real_smoke();
  CHECK(argc == 1);
  CHECK(owned_budget() == 0);
  memset(&mock, 0, sizeof(mock));
  io = mock_io(&mock);
  CHECK(ftun_linux_route_prepare_with_io(&policy, &io, &transaction) == FTUN_OK &&
        transaction != NULL);
  CHECK(check_resource_plan(&mock) == 0);
  CHECK(ftun_linux_route_get_info(transaction, &info) == FTUN_OK);
  CHECK(info.resource_count == 7u && info.active_count == 7u && info.strict_route);
  CHECK(ftun_linux_route_release(&transaction) == FTUN_OK && transaction == NULL);
  CHECK(mock.remove_calls == 7u);
  for (index = 0u; index < 7u; index++) {
    CHECK(memcmp(&mock.removed[index], &mock.applied[6u - index],
                 sizeof(mock.removed[index])) == 0);
  }
  CHECK(ftun_linux_route_release(&transaction) == FTUN_OK);

  for (index = 1u; index <= 7u; index++) {
    size_t removed_index;
    memset(&mock, 0, sizeof(mock));
    mock.fail_apply_call = index;
    mock.fail_apply_status = index == 1u ? FTUN_E_REJECTED : FTUN_E_IO;
    io = mock_io(&mock);
    CHECK(ftun_linux_route_prepare_with_io(&policy, &io, &transaction) ==
          mock.fail_apply_status);
    CHECK(transaction == NULL && mock.remove_calls == index - 1u);
    for (removed_index = 0u; removed_index < mock.remove_calls; removed_index++) {
      CHECK(memcmp(&mock.removed[removed_index],
                   &mock.applied[index - 2u - removed_index],
                   sizeof(mock.removed[removed_index])) == 0);
    }
  }

  /* 添加时对象已存在（STALE）：非地址对象是崩溃遗留，原地接管并在释放时撤销；
   * 地址对象可能属于外部，仍然失败并回滚。 */
  memset(&mock, 0, sizeof(mock));
  mock.fail_apply_call = 3u;
  mock.fail_apply_status = FTUN_E_STALE;
  io = mock_io(&mock);
  CHECK(ftun_linux_route_prepare_with_io(&policy, &io, &transaction) == FTUN_OK);
  CHECK(ftun_linux_route_get_info(transaction, &info) == FTUN_OK &&
        info.active_count == 7u && mock.apply_calls == 7u);
  CHECK(ftun_linux_route_release(&transaction) == FTUN_OK && mock.remove_calls == 7u);
  memset(&mock, 0, sizeof(mock));
  mock.fail_apply_call = 1u;
  mock.fail_apply_status = FTUN_E_STALE;
  io = mock_io(&mock);
  CHECK(ftun_linux_route_prepare_with_io(&policy, &io, &transaction) == FTUN_E_STALE &&
        transaction == NULL && mock.remove_calls == 0u);

  memset(&mock, 0, sizeof(mock));
  mock.fail_apply_call = 5u;
  mock.fail_apply_status = FTUN_E_IO;
  mock.fail_remove_call = 2u;
  mock.fail_remove_status = FTUN_E_IO;
  io = mock_io(&mock);
  CHECK(ftun_linux_route_prepare_with_io(&policy, &io, &transaction) ==
        FTUN_E_STATE_CORRUPT && transaction != NULL);
  CHECK(ftun_linux_route_get_info(transaction, &info) == FTUN_OK &&
        info.active_count == 1u);
  CHECK(ftun_linux_route_release(&transaction) == FTUN_OK && transaction == NULL);

  memset(&mock, 0, sizeof(mock));
  io = mock_io(&mock);
  CHECK(ftun_linux_route_prepare_with_io(&policy, &io, &transaction) == FTUN_OK);
  mock.fail_remove_call = 1u;
  mock.fail_remove_status = FTUN_E_STALE;
  CHECK(ftun_linux_route_release(&transaction) == FTUN_OK && transaction == NULL);

  memset(&mock, 0, sizeof(mock));
  io = mock_io(&mock);
  CHECK(ftun_linux_route_prepare_with_io(&policy, &io, &transaction) == FTUN_OK);
  mock.fail_remove_call = 1u;
  mock.fail_remove_status = FTUN_E_REJECTED;
  CHECK(ftun_linux_route_release(&transaction) == FTUN_E_REJECTED &&
        transaction != NULL);
  CHECK(ftun_linux_route_get_info(transaction, &info) == FTUN_OK &&
        info.active_count == 1u);
  CHECK(ftun_linux_route_release(&transaction) == FTUN_OK && transaction == NULL);

  memset(&mock, 0, sizeof(mock));
  io = mock_io(&mock);
  policy = route_policy(false, false);
  CHECK(ftun_linux_route_prepare_with_io(&policy, &io, &transaction) == FTUN_OK);
  CHECK(ftun_linux_route_get_info(transaction, &info) == FTUN_OK &&
        info.resource_count == 4u && !info.strict_route);
  CHECK(ftun_linux_route_release(&transaction) == FTUN_OK);

  policy = route_policy(false, false);
  policy.manage_local = false;
  CHECK(ftun_linux_route_prepare_with_io(&policy, &io, &transaction) ==
        FTUN_E_INVALID && transaction == NULL);
  policy = route_policy(false, false);
  policy.route_table = FTUN_RT_TABLE_MAIN;
  CHECK(ftun_linux_route_prepare_with_io(&policy, &io, &transaction) ==
        FTUN_E_INVALID);
  policy = route_policy(false, false);
  policy.rule_priority = UINT32_MAX;
  CHECK(ftun_linux_route_prepare_with_io(&policy, &io, &transaction) ==
        FTUN_E_INVALID);
  policy = route_policy(false, false);
  policy.protection_mark = 0u;
  CHECK(ftun_linux_route_prepare_with_io(&policy, &io, &transaction) ==
        FTUN_E_INVALID);
  policy = route_policy(false, false);
  policy.protection_mark_mask = UINT32_C(0x0000ffff);
  CHECK(ftun_linux_route_prepare_with_io(&policy, &io, &transaction) ==
        FTUN_E_INVALID);
  policy = route_policy(false, false);
  policy.tun_prefix_length = 0u;
  CHECK(ftun_linux_route_prepare_with_io(&policy, &io, &transaction) ==
        FTUN_E_INVALID);
  policy = route_policy(true, false);
  policy.lan_interface = policy.tun_interface;
  CHECK(ftun_linux_route_prepare_with_io(&policy, &io, &transaction) ==
        FTUN_E_INVALID);
  policy = route_policy(true, false);
  policy.lan_interface.data = "lo";
  policy.lan_interface.length = 2u;
  CHECK(ftun_linux_route_prepare_with_io(&policy, &io, &transaction) ==
        FTUN_E_INVALID);
  policy = route_policy(false, false);
  incomplete = io;
  incomplete.remove = NULL;
  transaction = (ftun_route_transaction_t *)(uintptr_t)1;
  CHECK(ftun_linux_route_prepare_with_io(&policy, &incomplete, &transaction) ==
        FTUN_E_INVALID && transaction == NULL);
  CHECK(ftun_linux_route_prepare_with_io(NULL, &io, &transaction) ==
        FTUN_E_INVALID && transaction == NULL);
  CHECK(ftun_linux_route_prepare_with_io(&policy, &io, NULL) == FTUN_E_INVALID);
  CHECK(ftun_linux_route_get_info(NULL, &info) == FTUN_E_INVALID);
  CHECK(info.resource_count == 0u && info.active_count == 0u && !info.strict_route);
  CHECK(ftun_linux_route_release(NULL) == FTUN_E_INVALID);
  return 0;
}
