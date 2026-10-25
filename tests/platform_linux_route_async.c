#include "platform/linux/route.h"
#include "platform/linux/uapi.h"
#include "platform/linux/interface.h"
#include "core/budget.h"
#include "core/context.h"
#include "event/event.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "async linux route contract failed: %s\n", #x); \
    return 1; \
  } \
} while (0)

#define ASYNC_REQUEST_CAPACITY 128u
#define ASYNC_REPLY_CAPACITY 128u

typedef struct {
  ftun_linux_route_request_t requests[ASYNC_REQUEST_CAPACITY];
  ftun_linux_route_reply_t replies[ASYNC_REPLY_CAPACITY];
  ftun_linux_route_resource_t resources[FTUN_LINUX_ROUTE_MAX_RESOURCES];
  size_t request_count;
  size_t reply_head;
  size_t reply_count;
  size_t resource_count;
  size_t query_calls[FTUN_LINUX_ROUTE_MAX_RESOURCES];
  size_t add_calls[FTUN_LINUX_ROUTE_MAX_RESOURCES];
  size_t remove_calls[FTUN_LINUX_ROUTE_MAX_RESOURCES];
  bool present[FTUN_LINUX_ROUTE_MAX_RESOURCES];
  size_t preexisting_index;
  size_t fail_add_index;
  ftun_status_t fail_add_status;
  size_t drop_add_index;
  size_t add_without_effect_index;
  size_t out_of_order_add_index;
  size_t drop_reconcile_index;
  size_t fail_remove_index;
  size_t drop_remove_index;
  bool fail_remove_once;
  bool check_reentry;
  bool block_submit;
  bool block_receive;
  bool block_sync_remove;
  ftun_status_t reentrant_run_status;
  ftun_status_t reentrant_release_status;
  ftun_linux_route_async_t *operation;
  uint64_t now_ms;
} async_mock_t;

static ftun_route_policy_t async_policy(void)
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
  policy.lan_interface.data = "lan0";
  policy.lan_interface.length = strlen(policy.lan_interface.data);
  policy.strict_route = true;
  return policy;
}

static void async_mock_init(async_mock_t *mock)
{
  memset(mock, 0, sizeof(*mock));
  mock->preexisting_index = SIZE_MAX;
  mock->fail_add_index = SIZE_MAX;
  mock->drop_add_index = SIZE_MAX;
  mock->add_without_effect_index = SIZE_MAX;
  mock->out_of_order_add_index = SIZE_MAX;
  mock->drop_reconcile_index = SIZE_MAX;
  mock->fail_remove_index = SIZE_MAX;
  mock->drop_remove_index = SIZE_MAX;
  mock->reentrant_run_status = FTUN_OK;
  mock->reentrant_release_status = FTUN_OK;
}

static size_t async_mock_resource(async_mock_t *mock,
                                  const ftun_linux_route_resource_t *resource)
{
  size_t index;
  for (index = 0u; index < mock->resource_count; index++) {
    if (memcmp(&mock->resources[index], resource, sizeof(*resource)) == 0) {
      return index;
    }
  }
  if (mock->resource_count >= FTUN_LINUX_ROUTE_MAX_RESOURCES) return SIZE_MAX;
  index = mock->resource_count++;
  mock->resources[index] = *resource;
  if (index == mock->preexisting_index) mock->present[index] = true;
  return index;
}

static int async_mock_reply(async_mock_t *mock, uint32_t sequence,
                            ftun_status_t status, bool present)
{
  size_t tail;
  if (mock->reply_count >= ASYNC_REPLY_CAPACITY) return 0;
  tail = (mock->reply_head + mock->reply_count) % ASYNC_REPLY_CAPACITY;
  memset(&mock->replies[tail], 0, sizeof(mock->replies[tail]));
  mock->replies[tail].sequence = sequence;
  mock->replies[tail].status = status;
  mock->replies[tail].present = present;
  mock->reply_count++;
  return 1;
}

static ftun_status_t async_mock_submit(
  void *context, const ftun_linux_route_request_t *request)
{
  async_mock_t *mock = (async_mock_t *)context;
  size_t index;
  if (mock == NULL || request == NULL || request->sequence == 0u ||
      mock->request_count >= ASYNC_REQUEST_CAPACITY) return FTUN_E_LIMIT;
  if (mock->block_submit) return FTUN_E_AGAIN;
  if (mock->request_count != 0u &&
      request->sequence == mock->requests[mock->request_count - 1u].sequence) {
    return FTUN_E_STATE_CORRUPT;
  }
  mock->requests[mock->request_count++] = *request;
  index = async_mock_resource(mock, &request->resource);
  if (index == SIZE_MAX) return FTUN_E_LIMIT;
  if (mock->check_reentry) {
    size_t work = 0u;
    mock->check_reentry = false;
    mock->reentrant_run_status = ftun_linux_route_async_run(
      mock->operation, mock->now_ms, 1u, &work);
    mock->reentrant_release_status = ftun_linux_route_async_release(
      mock->operation, mock->now_ms, mock->now_ms + 1000u);
  }
  if (request->kind == FTUN_LINUX_ROUTE_REQUEST_QUERY) {
    mock->query_calls[index]++;
    if (index == mock->drop_reconcile_index &&
        mock->query_calls[index] == 2u) return FTUN_OK;
    return async_mock_reply(mock, request->sequence, FTUN_OK,
                            mock->present[index]) ? FTUN_OK : FTUN_E_LIMIT;
  }
  if (request->kind == FTUN_LINUX_ROUTE_REQUEST_ADD) {
    mock->add_calls[index]++;
    if (index == mock->fail_add_index) {
      return async_mock_reply(mock, request->sequence,
        mock->fail_add_status, false) ? FTUN_OK : FTUN_E_LIMIT;
    }
    if (index != mock->add_without_effect_index) mock->present[index] = true;
    if (index == mock->drop_add_index) return FTUN_OK;
    if (index == mock->out_of_order_add_index &&
        !async_mock_reply(mock, request->sequence - 1u, FTUN_OK, false)) {
      return FTUN_E_LIMIT;
    }
    return async_mock_reply(mock, request->sequence, FTUN_OK, false) ?
      FTUN_OK : FTUN_E_LIMIT;
  }
  mock->remove_calls[index]++;
  if (index == mock->fail_remove_index && mock->fail_remove_once) {
    mock->fail_remove_once = false;
    return async_mock_reply(mock, request->sequence, FTUN_E_IO, false) ?
      FTUN_OK : FTUN_E_LIMIT;
  }
  mock->present[index] = false;
  if (index == mock->drop_remove_index) return FTUN_OK;
  return async_mock_reply(mock, request->sequence, FTUN_OK, false) ?
    FTUN_OK : FTUN_E_LIMIT;
}

static ftun_status_t async_mock_receive(void *context,
                                        ftun_linux_route_reply_t *reply)
{
  async_mock_t *mock = (async_mock_t *)context;
  if (mock == NULL || reply == NULL) return FTUN_E_INVALID;
  if (mock->block_receive || mock->reply_count == 0u) return FTUN_E_AGAIN;
  *reply = mock->replies[mock->reply_head];
  mock->reply_head = (mock->reply_head + 1u) % ASYNC_REPLY_CAPACITY;
  mock->reply_count--;
  return FTUN_OK;
}

static ftun_linux_route_async_io_t async_mock_io(async_mock_t *mock)
{
  ftun_linux_route_async_io_t io;
  memset(&io, 0, sizeof(io));
  io.submit = async_mock_submit;
  io.receive = async_mock_receive;
  io.context = mock;
  return io;
}

static int async_present_count(const async_mock_t *mock)
{
  size_t index;
  int count = 0;
  for (index = 0u; index < mock->resource_count; index++) {
    if (mock->present[index]) count++;
  }
  return count;
}

static int async_drive(ftun_linux_route_async_t *operation,
                       async_mock_t *mock, uint64_t *now_ms,
                       ftun_linux_route_async_state_t terminal,
                       size_t quota)
{
  size_t rounds;
  for (rounds = 0u; rounds < 512u; rounds++) {
    ftun_linux_route_async_info_t info;
    size_t work = 0u;
    uint64_t deadline = 0u;
    bool present = false;
    if (ftun_linux_route_async_get_info(operation, &info) != FTUN_OK) return 0;
    if (info.state == terminal) return 1;
    mock->now_ms = *now_ms;
    if (ftun_linux_route_async_run(operation, *now_ms, quota, &work) != FTUN_OK ||
        work > quota) return 0;
    if (work == 0u) {
      if (ftun_linux_route_async_get_info(operation, &info) != FTUN_OK) return 0;
      if (info.state == terminal) return 1;
      if (ftun_linux_route_async_next_deadline(operation, &deadline,
                                                &present) != FTUN_OK ||
          !present) {
        fprintf(stderr, "drive stalled: state=%d result=%d active=%zu "
                "requests=%zu replies=%zu runnable=%d\n",
                (int)info.state, (int)info.result, info.active_count,
                mock->request_count, mock->reply_count, info.runnable);
        return 0;
      }
      *now_ms = deadline;
    }
  }
  fprintf(stderr, "drive exhausted rounds\n");
  return 0;
}

static int test_success_and_serialization(void)
{
  async_mock_t mock;
  ftun_linux_route_async_io_t io;
  ftun_route_policy_t policy = async_policy();
  ftun_linux_route_async_t *operation = NULL;
  ftun_linux_route_async_info_t info;
  uint64_t now_ms = 1000u;
  size_t index;
  async_mock_init(&mock);
  mock.out_of_order_add_index = 1u;
  mock.check_reentry = true;
  io = async_mock_io(&mock);
  CHECK(ftun_linux_route_async_start_with_io(&policy, &io, now_ms, 10u,
    5000u, UINT32_MAX - 4u, &operation) == FTUN_OK && operation != NULL);
  mock.operation = operation;
  CHECK(async_drive(operation, &mock, &now_ms,
                    FTUN_LINUX_ROUTE_ASYNC_READY, 1u));
  CHECK(ftun_linux_route_async_get_info(operation, &info) == FTUN_OK &&
        info.resource_count == FTUN_LINUX_ROUTE_MAX_RESOURCES &&
        info.active_count == FTUN_LINUX_ROUTE_MAX_RESOURCES &&
        info.stale_replies == 1u && info.result == FTUN_OK);
  CHECK(mock.reentrant_run_status == FTUN_E_AGAIN &&
        mock.reentrant_release_status == FTUN_E_AGAIN);
  CHECK(async_present_count(&mock) == (int)FTUN_LINUX_ROUTE_MAX_RESOURCES);
  CHECK(ftun_linux_route_async_destroy(&operation) == FTUN_E_AGAIN &&
        operation != NULL);
  CHECK(ftun_linux_route_async_release(operation, now_ms,
                                       now_ms + 1000u) == FTUN_OK);
  CHECK(ftun_linux_route_async_release(operation, now_ms,
                                       now_ms + 1000u) == FTUN_E_AGAIN);
  CHECK(async_drive(operation, &mock, &now_ms,
                    FTUN_LINUX_ROUTE_ASYNC_RELEASED, 1u));
  for (index = 0u; index < FTUN_LINUX_ROUTE_MAX_RESOURCES; index++) {
    CHECK(mock.remove_calls[index] == 1u && !mock.present[index]);
  }
  CHECK(ftun_linux_route_async_release(operation, now_ms,
                                       now_ms + 1000u) == FTUN_OK);
  CHECK(ftun_linux_route_async_destroy(&operation) == FTUN_OK &&
        operation == NULL);
  CHECK(ftun_linux_route_async_destroy(&operation) == FTUN_OK);
  return 0;
}

static int test_lost_ack_reconcile(void)
{
  async_mock_t mock;
  ftun_linux_route_async_io_t io;
  ftun_route_policy_t policy = async_policy();
  ftun_linux_route_async_t *operation = NULL;
  ftun_linux_route_async_info_t info;
  uint64_t now_ms = 100u;
  async_mock_init(&mock);
  mock.drop_add_index = 2u;
  io = async_mock_io(&mock);
  CHECK(ftun_linux_route_async_start_with_io(&policy, &io, now_ms, 5u,
    1000u, 10u, &operation) == FTUN_OK);
  CHECK(async_drive(operation, &mock, &now_ms,
                    FTUN_LINUX_ROUTE_ASYNC_READY, 3u));
  CHECK(mock.query_calls[2] == 2u);
  CHECK(ftun_linux_route_async_get_info(operation, &info) == FTUN_OK &&
        info.timeouts == 1u && info.active_count == 7u);
  CHECK(ftun_linux_route_async_release(operation, now_ms,
                                       now_ms + 1000u) == FTUN_OK);
  CHECK(async_drive(operation, &mock, &now_ms,
                    FTUN_LINUX_ROUTE_ASYNC_RELEASED, 4u));
  CHECK(async_present_count(&mock) == 0);
  CHECK(ftun_linux_route_async_destroy(&operation) == FTUN_OK);
  return 0;
}

static int test_lost_ack_without_effect(void)
{
  async_mock_t mock;
  ftun_linux_route_async_io_t io;
  ftun_route_policy_t policy = async_policy();
  ftun_linux_route_async_t *operation = NULL;
  ftun_linux_route_async_info_t info;
  uint64_t now_ms = 100u;
  async_mock_init(&mock);
  mock.drop_add_index = 3u;
  mock.add_without_effect_index = 3u;
  io = async_mock_io(&mock);
  CHECK(ftun_linux_route_async_start_with_io(&policy, &io, now_ms, 5u,
    1000u, 20u, &operation) == FTUN_OK);
  CHECK(async_drive(operation, &mock, &now_ms,
                    FTUN_LINUX_ROUTE_ASYNC_FAILED, 8u));
  CHECK(ftun_linux_route_async_get_info(operation, &info) == FTUN_OK &&
        info.result == FTUN_E_TIMEOUT && info.active_count == 0u &&
        info.timeouts == 1u && mock.query_calls[3] == 2u);
  CHECK(async_present_count(&mock) == 0);
  CHECK(ftun_linux_route_async_destroy(&operation) == FTUN_OK);
  return 0;
}

static int test_partial_error_rollback(void)
{
  async_mock_t mock;
  ftun_linux_route_async_io_t io;
  ftun_route_policy_t policy = async_policy();
  ftun_linux_route_async_t *operation = NULL;
  ftun_linux_route_async_info_t info;
  uint64_t now_ms = 100u;
  async_mock_init(&mock);
  mock.fail_add_index = 4u;
  mock.fail_add_status = FTUN_E_IO;
  io = async_mock_io(&mock);
  CHECK(ftun_linux_route_async_start_with_io(&policy, &io, now_ms, 5u,
    1000u, 30u, &operation) == FTUN_OK);
  CHECK(async_drive(operation, &mock, &now_ms,
                    FTUN_LINUX_ROUTE_ASYNC_FAILED, 2u));
  CHECK(ftun_linux_route_async_get_info(operation, &info) == FTUN_OK &&
        info.result == FTUN_E_IO && info.active_count == 0u);
  CHECK(mock.remove_calls[3] == 1u && mock.remove_calls[2] == 1u &&
        mock.remove_calls[1] == 1u && mock.remove_calls[0] == 1u);
  CHECK(async_present_count(&mock) == 0);
  CHECK(ftun_linux_route_async_destroy(&operation) == FTUN_OK);
  return 0;
}

static int test_uncertain_and_cleanup_retry(void)
{
  async_mock_t mock;
  ftun_linux_route_async_io_t io;
  ftun_route_policy_t policy = async_policy();
  ftun_linux_route_async_t *operation = NULL;
  ftun_linux_route_async_info_t info;
  uint64_t now_ms = 100u;
  async_mock_init(&mock);
  mock.drop_add_index = 2u;
  mock.drop_reconcile_index = 2u;
  mock.fail_remove_index = 2u;
  mock.fail_remove_once = true;
  io = async_mock_io(&mock);
  CHECK(ftun_linux_route_async_start_with_io(&policy, &io, now_ms, 5u,
    1000u, 40u, &operation) == FTUN_OK);
  CHECK(async_drive(operation, &mock, &now_ms,
                    FTUN_LINUX_ROUTE_ASYNC_CLEANUP_FAILED, 4u));
  CHECK(ftun_linux_route_async_get_info(operation, &info) == FTUN_OK &&
        info.result == FTUN_E_TIMEOUT && info.cleanup_result == FTUN_E_IO &&
        info.active_count == 1u && info.cleanup_failures == 1u &&
        mock.present[2]);
  CHECK(ftun_linux_route_async_destroy(&operation) == FTUN_E_AGAIN);
  CHECK(ftun_linux_route_async_release(operation, now_ms,
                                       now_ms + 1000u) == FTUN_OK);
  CHECK(async_drive(operation, &mock, &now_ms,
                    FTUN_LINUX_ROUTE_ASYNC_RELEASED, 4u));
  CHECK(async_present_count(&mock) == 0 && mock.remove_calls[2] == 2u);
  CHECK(ftun_linux_route_async_destroy(&operation) == FTUN_OK);
  return 0;
}

static int test_remove_lost_ack(void)
{
  async_mock_t mock;
  ftun_linux_route_async_io_t io;
  ftun_route_policy_t policy = async_policy();
  ftun_linux_route_async_t *operation = NULL;
  ftun_linux_route_async_info_t info;
  uint64_t now_ms = 100u;
  async_mock_init(&mock);
  mock.drop_remove_index = 5u;
  io = async_mock_io(&mock);
  CHECK(ftun_linux_route_async_start_with_io(&policy, &io, now_ms, 5u,
    1000u, 50u, &operation) == FTUN_OK);
  CHECK(async_drive(operation, &mock, &now_ms,
                    FTUN_LINUX_ROUTE_ASYNC_READY, 8u));
  CHECK(ftun_linux_route_async_release(operation, now_ms,
                                       now_ms + 1000u) == FTUN_OK);
  CHECK(async_drive(operation, &mock, &now_ms,
                    FTUN_LINUX_ROUTE_ASYNC_RELEASED, 8u));
  CHECK(ftun_linux_route_async_get_info(operation, &info) == FTUN_OK &&
        info.timeouts == 1u && info.active_count == 0u &&
        mock.query_calls[5] == 2u && async_present_count(&mock) == 0);
  CHECK(ftun_linux_route_async_destroy(&operation) == FTUN_OK);
  return 0;
}

static int test_conflict_and_inputs(void)
{
  async_mock_t mock;
  ftun_linux_route_async_io_t io;
  ftun_linux_route_async_io_t incomplete;
  ftun_route_policy_t policy = async_policy();
  ftun_linux_route_async_t *operation = (ftun_linux_route_async_t *)(uintptr_t)1;
  ftun_linux_route_async_info_t info;
  uint64_t deadline;
  uint64_t now_ms = 100u;
  size_t work = 1u;
  bool present;
  async_mock_init(&mock);
  mock.preexisting_index = 0u;
  io = async_mock_io(&mock);
  CHECK(ftun_linux_route_async_start_with_io(&policy, &io, now_ms, 5u,
    1000u, 60u, &operation) == FTUN_OK);
  CHECK(async_drive(operation, &mock, &now_ms,
                    FTUN_LINUX_ROUTE_ASYNC_FAILED, 8u));
  CHECK(ftun_linux_route_async_get_info(operation, &info) == FTUN_OK &&
        info.result == FTUN_E_REJECTED && info.active_count == 0u &&
        mock.remove_calls[0] == 0u && mock.present[0]);
  mock.present[0] = false;
  CHECK(ftun_linux_route_async_destroy(&operation) == FTUN_OK);

  incomplete = io;
  incomplete.receive = NULL;
  operation = (ftun_linux_route_async_t *)(uintptr_t)1;
  CHECK(ftun_linux_route_async_start_with_io(&policy, &incomplete, now_ms,
    5u, 1000u, 1u, &operation) == FTUN_E_INVALID && operation == NULL);
  CHECK(ftun_linux_route_async_start_with_io(&policy, &io, now_ms,
    0u, 1000u, 1u, &operation) == FTUN_E_INVALID);
  CHECK(ftun_linux_route_async_start_with_io(&policy, &io, now_ms,
    5u, now_ms, 1u, &operation) == FTUN_E_INVALID);
  CHECK(ftun_linux_route_async_start_with_io(&policy, &io, now_ms,
    5u, 1000u, 0u, &operation) == FTUN_E_INVALID);
  CHECK(ftun_linux_route_async_run(NULL, now_ms, 1u, &work) ==
        FTUN_E_INVALID && work == 0u);
  memset(&info, 1, sizeof(info));
  CHECK(ftun_linux_route_async_get_info(NULL, &info) == FTUN_E_INVALID &&
        info.resource_count == 0u);
  deadline = 1u;
  present = true;
  CHECK(ftun_linux_route_async_next_deadline(NULL, &deadline, &present) ==
        FTUN_E_INVALID && deadline == 0u && !present);
  CHECK(ftun_linux_route_async_destroy(NULL) == FTUN_E_INVALID);
  return 0;
}

static int test_network_guard_and_overlay_transactions(void)
{
  ftun_network_prefix_t protected_prefixes[2] = {
    {{0u, 0u, 0u, 0u}, 0u},
    {{172u, 16u, 0u, 0u}, 12u}
  };
  ftun_network_route_t routes[2] = {
    {{{0u, 0u, 0u, 0u}, 0u},
      FTUN_DIAL_PURPOSE_BIT(FTUN_DIAL_PURPOSE_PROXY)},
    {{{172u, 16u, 1u, 0u}, 24u},
      FTUN_DIAL_PURPOSE_BIT(FTUN_DIAL_PURPOSE_BUSINESS)}
  };
  ftun_network_view_spec_t spec;
  ftun_network_view_t *view = NULL;
  ftun_network_view_t *revoked = NULL;
  ftun_linux_route_plan_t guard;
  ftun_linux_route_plan_t overlay;
  ftun_linux_route_async_t *guard_operation = NULL;
  ftun_linux_route_async_t *overlay_operation = NULL;
  ftun_linux_route_async_info_t info;
  ftun_network_dial_decision_t decision;
  ftun_endpoint_t endpoint;
  ftun_linux_route_async_io_t io;
  async_mock_t mock;
  uint64_t now_ms = 100u;

  memset(&spec, 0, sizeof(spec));
  spec.generation = 77u;
  spec.protected_prefixes = protected_prefixes;
  spec.protected_prefix_count = 2u;
  spec.overlay_routes = routes;
  spec.overlay_route_count = 2u;
  CHECK(ftun_network_view_create(&spec, &view) == FTUN_OK);
  CHECK(ftun_linux_route_guard_plan(view, 200u, 12000u, &guard) == FTUN_OK &&
        guard.resource_count == 4u &&
        guard.resources[0].kind == FTUN_LINUX_ROUTE_UNREACHABLE &&
        guard.resources[1].kind == FTUN_LINUX_ROUTE_PROTECT_RULE &&
        guard.resources[2].kind == FTUN_LINUX_ROUTE_UNREACHABLE &&
        guard.resources[3].kind == FTUN_LINUX_ROUTE_PROTECT_RULE &&
        guard.resources[0].metric == UINT32_C(32767) &&
        guard.resources[1].priority == 12000u &&
        guard.resources[3].priority == 12001u);
  CHECK(ftun_linux_route_overlay_plan(view,
          (ftun_string_t){"ftun-route0", 11u}, 200u, 100u, &overlay) ==
        FTUN_OK && overlay.resource_count == 2u &&
        overlay.resources[0].kind == FTUN_LINUX_ROUTE_OVERLAY &&
        overlay.resources[1].kind == FTUN_LINUX_ROUTE_OVERLAY);

  async_mock_init(&mock);
  io = async_mock_io(&mock);
  CHECK(ftun_linux_route_async_start_plan_with_io(&guard, &io, now_ms, 5u,
        1000u, 70u, &guard_operation) == FTUN_OK);
  CHECK(async_drive(guard_operation, &mock, &now_ms,
                    FTUN_LINUX_ROUTE_ASYNC_READY, 2u));
  CHECK(async_present_count(&mock) == 4);

  /* 可达路径部分提交失败只补偿路径，先建立的 guard 继续存在。 */
  mock.fail_add_index = 5u;
  mock.fail_add_status = FTUN_E_IO;
  CHECK(ftun_linux_route_async_start_plan_with_io(&overlay, &io, now_ms, 5u,
        now_ms + 1000u, 80u, &overlay_operation) == FTUN_OK);
  CHECK(async_drive(overlay_operation, &mock, &now_ms,
                    FTUN_LINUX_ROUTE_ASYNC_FAILED, 2u));
  CHECK(ftun_linux_route_async_get_info(overlay_operation, &info) == FTUN_OK &&
        info.result == FTUN_E_IO && info.active_count == 0u &&
        async_present_count(&mock) == 4);
  CHECK(ftun_linux_route_async_destroy(&overlay_operation) == FTUN_OK);

  mock.fail_add_index = SIZE_MAX;
  CHECK(ftun_linux_route_async_start_plan_with_io(&overlay, &io, now_ms, 5u,
        now_ms + 1000u, 90u, &overlay_operation) == FTUN_OK);
  CHECK(async_drive(overlay_operation, &mock, &now_ms,
                    FTUN_LINUX_ROUTE_ASYNC_READY, 2u));
  CHECK(async_present_count(&mock) == 6);

  /* 先发布撤销视图，再撤可达路径；guard 独立保留并拒绝新拨号。 */
  spec.generation = 78u;
  spec.overlay_routes = NULL;
  spec.overlay_route_count = 0u;
  CHECK(ftun_network_view_create(&spec, &revoked) == FTUN_OK);
  memset(&endpoint, 0, sizeof(endpoint));
  endpoint.kind = FTUN_ADDRESS_IPV4;
  memcpy(endpoint.address, (uint8_t[]){10u, 1u, 2u, 3u}, 4u);
  endpoint.port = 1080u;
  CHECK(ftun_network_view_select_dial(revoked, &endpoint,
          FTUN_DIAL_PURPOSE_PROXY, FTUN_DIAL_DOMAIN_AUTO, &decision) ==
        FTUN_E_REJECTED);
  CHECK(ftun_linux_route_async_release(overlay_operation, now_ms,
                                       now_ms + 1000u) == FTUN_OK);
  CHECK(async_drive(overlay_operation, &mock, &now_ms,
                    FTUN_LINUX_ROUTE_ASYNC_RELEASED, 2u));
  CHECK(async_present_count(&mock) == 4);
  CHECK(ftun_linux_route_async_destroy(&overlay_operation) == FTUN_OK);
  CHECK(ftun_linux_route_async_release(guard_operation, now_ms,
                                       now_ms + 1000u) == FTUN_OK);
  CHECK(async_drive(guard_operation, &mock, &now_ms,
                    FTUN_LINUX_ROUTE_ASYNC_RELEASED, 2u));
  CHECK(async_present_count(&mock) == 0);
  CHECK(ftun_linux_route_async_destroy(&guard_operation) == FTUN_OK);
  CHECK(ftun_network_view_release(&revoked) == FTUN_OK);
  CHECK(ftun_network_view_release(&view) == FTUN_OK);
  return 0;
}

static int test_cancel_pending_add(void)
{
  unsigned int scenario;
  for (scenario = 0u; scenario < 5u; scenario++) {
    async_mock_t mock;
    ftun_linux_route_async_io_t io;
    ftun_route_policy_t policy = async_policy();
    ftun_linux_route_async_t *operation = NULL;
    ftun_linux_route_async_info_t info;
    uint64_t now_ms = 100u;
    size_t work = 0u;
    async_mock_init(&mock);
    if (scenario == 1u || scenario == 3u || scenario == 4u) mock.drop_add_index = 0u;
    if (scenario == 4u) mock.add_without_effect_index = 0u;
    if (scenario == 2u) {
      mock.fail_add_index = 0u;
      mock.fail_add_status = FTUN_E_REJECTED;
    }
    io = async_mock_io(&mock);
    CHECK(ftun_linux_route_async_start_with_io(&policy, &io, now_ms, 5u,
      1000u, 120u, &operation) == FTUN_OK);
    /* QUERY 提交、QUERY 回复、ADD 提交；故意暂不派发 ADD ACK。 */
    CHECK(ftun_linux_route_async_run(operation, now_ms, 3u, &work) == FTUN_OK && work == 3u);
    CHECK(mock.add_calls[0] == 1u);
    if (scenario == 2u) mock.present[0] = true; /* 竞争者的对象不可删除。 */
    CHECK(ftun_linux_route_async_release(operation, now_ms,
      scenario == 3u ? now_ms + 1u : 1000u) == FTUN_OK);
    CHECK(ftun_linux_route_async_destroy(&operation) == FTUN_E_AGAIN);
    if (scenario == 3u) {
      CHECK(async_drive(operation, &mock, &now_ms, FTUN_LINUX_ROUTE_ASYNC_CLEANUP_FAILED, 1u));
      CHECK(ftun_linux_route_async_get_info(operation, &info) == FTUN_OK && info.active_count == 1u);
      CHECK(ftun_linux_route_async_release(operation, now_ms, now_ms + 1000u) == FTUN_OK);
    }
    CHECK(async_drive(operation, &mock, &now_ms, FTUN_LINUX_ROUTE_ASYNC_RELEASED, 1u));
    CHECK(mock.add_calls[1] == 0u && async_present_count(&mock) == (scenario == 2u ? 1 : 0));
    CHECK(mock.remove_calls[0] == (scenario == 2u || scenario == 4u ? 0u : 1u));
    CHECK(ftun_linux_route_async_destroy(&operation) == FTUN_OK);
  }
  return 0;
}

static ftun_status_t sync_apply(void *context, const ftun_linux_route_resource_t *resource)
{
  async_mock_t *mock = context;
  size_t index = async_mock_resource(mock, resource);
  if (index == SIZE_MAX) return FTUN_E_LIMIT;
  if (index == mock->fail_add_index) return FTUN_E_IO;
  if (mock->present[index]) return FTUN_E_REJECTED;
  mock->present[index] = true;
  return FTUN_OK;
}

static ftun_status_t sync_remove(void *context, const ftun_linux_route_resource_t *resource)
{
  async_mock_t *mock = context;
  size_t index = async_mock_resource(mock, resource);
  if (index == SIZE_MAX) return FTUN_E_LIMIT;
  if (mock->block_sync_remove || index == mock->fail_remove_index) return FTUN_E_IO;
  mock->present[index] = false;
  return FTUN_OK;
}

static int test_adopt_owned_resources(void)
{
  unsigned int partial;
  for (partial = 0u; partial < 3u; partial++) {
    async_mock_t mock;
    ftun_linux_route_async_io_t io;
    ftun_linux_route_io_t sync_io = {sync_apply, sync_remove, &mock};
    ftun_route_policy_t policy = async_policy();
    ftun_route_transaction_t *source = NULL, *original;
    ftun_linux_route_async_t *operation = NULL;
    ftun_linux_route_async_info_t info;
    uint64_t now_ms = 100u;
    async_mock_init(&mock);
    if (partial == 1u) { mock.fail_add_index = 4u; mock.fail_remove_index = 2u; }
    io = async_mock_io(&mock);
    ftun_budget_t *budget = NULL;
    ftun_budget_usage_t budget_usage;
    CHECK(ftun_budget_create(NULL, 65536u, 0u, &budget) == FTUN_OK);
    CHECK(ftun_linux_route_prepare_with_io_and_budget(budget, &policy, &sync_io, &source) ==
      (partial == 1u ? FTUN_E_STATE_CORRUPT : FTUN_OK));
    CHECK(source != NULL);
    if (partial == 2u) {
      mock.block_sync_remove = true;
      CHECK(ftun_linux_route_release(&source) == FTUN_E_IO && source != NULL);
    }
    CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK && budget_usage.used > 0u);
    original = source;
    CHECK(ftun_linux_route_async_adopt_with_io(&source, &io, now_ms, 0u,
      1000u, 1u, &operation) == FTUN_E_INVALID && source == original && operation == NULL);
    CHECK(ftun_linux_route_async_adopt_with_io(&source, &io, now_ms, 5u,
      1000u, 1u, &operation) == FTUN_OK && source == NULL);
    CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK && budget_usage.used == 0u);
    CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
    CHECK(ftun_linux_route_async_get_info(operation, &info) == FTUN_OK &&
      info.state == (partial ? FTUN_LINUX_ROUTE_ASYNC_CLEANUP_FAILED : FTUN_LINUX_ROUTE_ASYNC_READY));
    CHECK(info.active_count == (partial == 1u ? 1u : 7u) && mock.request_count == 0u);
    CHECK(ftun_linux_route_async_destroy(&operation) == FTUN_E_AGAIN);
    CHECK(ftun_linux_route_async_release(operation, now_ms, 1000u) == FTUN_OK);
    CHECK(async_drive(operation, &mock, &now_ms, FTUN_LINUX_ROUTE_ASYNC_RELEASED, 1u));
    CHECK(async_present_count(&mock) == 0);
    CHECK(ftun_linux_route_async_destroy(&operation) == FTUN_OK);
  }
  return 0;
}

static int test_submit_backpressure_deadline(void)
{
  async_mock_t mock;
  ftun_linux_route_async_io_t io;
  ftun_route_policy_t policy = async_policy();
  ftun_linux_route_async_t *operation = NULL;
  ftun_linux_route_async_info_t info;
  uint64_t deadline = 0u;
  bool present = false;
  size_t work = 0u;
  async_mock_init(&mock);
  mock.block_submit = true;
  io = async_mock_io(&mock);
  CHECK(ftun_linux_route_async_start_with_io(&policy, &io, 100u, 5u,
    110u, 1u, &operation) == FTUN_OK);
  CHECK(ftun_linux_route_async_run(operation, 100u, 1u, &work) == FTUN_OK && work == 0u);
  CHECK(ftun_linux_route_async_next_deadline(operation, &deadline, &present) == FTUN_OK &&
    present && deadline == 110u);
  CHECK(ftun_linux_route_async_run(operation, 110u, 1u, &work) == FTUN_OK && work == 1u);
  CHECK(ftun_linux_route_async_get_info(operation, &info) == FTUN_OK &&
    info.state == FTUN_LINUX_ROUTE_ASYNC_FAILED && info.result == FTUN_E_TIMEOUT &&
    info.active_count == 0u && mock.request_count == 0u);
  CHECK(ftun_linux_route_async_destroy(&operation) == FTUN_OK);
  return 0;
}

static int test_total_deadline_before_reply(void)
{
  unsigned int scenario;
  for (scenario = 0u; scenario < 9u; scenario++) {
    async_mock_t mock;
    ftun_linux_route_async_io_t io;
    ftun_route_policy_t policy = async_policy();
    ftun_linux_route_async_t *operation = NULL;
    ftun_linux_route_async_info_t info;
    size_t work = 0u, index = scenario == 8u ? 1u : 0u;
    size_t requests, replies;
    uint64_t now_ms = 111u, deadline;
    bool present;
    bool rejected = scenario == 1u || scenario == 4u || scenario == 8u;
    bool absent = scenario == 3u || scenario == 7u;
    async_mock_init(&mock);
    if (rejected) {
      mock.fail_add_index = index;
      mock.fail_add_status = FTUN_E_REJECTED;
    }
    if (scenario == 2u || scenario == 3u || scenario == 6u || scenario == 7u) {
      mock.drop_add_index = index;
    }
    if (absent) mock.add_without_effect_index = index;
    io = async_mock_io(&mock);
    CHECK(ftun_linux_route_async_start_with_io(&policy, &io, 100u, 5u,
      110u, 1u, &operation) == FTUN_OK);
    /* ADD 已发出；覆盖成功/拒绝 ACK、丢失 ACK 和查询中的到期。 */
    CHECK(ftun_linux_route_async_run(operation, 100u, index == 0u ? 3u : 7u,
      &work) == FTUN_OK && work == (index == 0u ? 3u : 7u));
    CHECK(mock.add_calls[index] == 1u);
    if (rejected) mock.present[index] = true; /* 竞争者对象。 */
    if (scenario == 6u || scenario == 7u) {
      CHECK(ftun_linux_route_async_run(operation, 105u, 2u, &work) == FTUN_OK && work == 2u);
      CHECK(mock.query_calls[index] == 2u && mock.reply_count == 1u);
    }
    requests = mock.request_count;
    replies = mock.reply_count;
    CHECK(ftun_linux_route_async_run(operation, 110u, 1u, &work) == FTUN_OK && work == 1u);
    CHECK(ftun_linux_route_async_get_info(operation, &info) == FTUN_OK &&
      info.state == FTUN_LINUX_ROUTE_ASYNC_CLEANUP_FAILED && info.active_count == index + 1u &&
      info.result == FTUN_E_TIMEOUT && info.cleanup_result == FTUN_E_TIMEOUT && !info.runnable);
    CHECK(mock.request_count == requests && mock.reply_count == replies);
    CHECK(ftun_linux_route_async_next_deadline(operation, &deadline, &present) == FTUN_OK && !present);
    CHECK(ftun_linux_route_async_destroy(&operation) == FTUN_E_AGAIN);
    if (scenario == 4u || scenario == 5u) {
      /* 显式重试也会再次到期，原 ACK 身份须跨多次保留。 */
      mock.block_receive = true;
      CHECK(ftun_linux_route_async_release(operation, now_ms, now_ms + 1u) == FTUN_OK);
      CHECK(ftun_linux_route_async_run(operation, now_ms, 1u, &work) == FTUN_OK && work == 0u);
      now_ms++;
      CHECK(ftun_linux_route_async_run(operation, now_ms, 1u, &work) == FTUN_OK && work == 1u);
      CHECK(ftun_linux_route_async_get_info(operation, &info) == FTUN_OK &&
        info.state == FTUN_LINUX_ROUTE_ASYNC_CLEANUP_FAILED && info.active_count == 1u);
      CHECK(ftun_linux_route_async_next_deadline(operation, &deadline, &present) == FTUN_OK && !present);
      CHECK(mock.request_count == requests && mock.reply_count == replies);
      mock.block_receive = false;
      now_ms++;
    }
    CHECK(ftun_linux_route_async_release(operation, now_ms, now_ms + 1000u) == FTUN_OK);
    CHECK(ftun_linux_route_async_destroy(&operation) == FTUN_E_AGAIN);
    CHECK(async_drive(operation, &mock, &now_ms, FTUN_LINUX_ROUTE_ASYNC_RELEASED, 1u));
    CHECK(mock.add_calls[index + 1u] == 0u && async_present_count(&mock) == (rejected ? 1 : 0));
    CHECK(mock.remove_calls[index] == (rejected || absent ? 0u : 1u));
    if (index != 0u) CHECK(mock.remove_calls[0] == 1u);
    CHECK(ftun_linux_route_async_destroy(&operation) == FTUN_OK);
  }
  return 0;
}

static int interface_drive(const ftun_interface_async_ops_t *ops, void *state,
  uint64_t *now_ms, ftun_interface_state_t terminal)
{
  size_t round;
  for (round = 0u; round < 256u; round++) {
    ftun_interface_async_info_t info;
    size_t work = 0u;
    if (ops->query(ops->context, state, &info) != FTUN_OK) return 0;
    if (info.state == terminal) return 1;
    if (ops->run(ops->context, state, *now_ms, 1u, &work) != FTUN_OK || work > 1u) return 0;
    if (work == 0u && info.has_deadline) *now_ms = info.next_deadline_ms;
  }
  return 0;
}

static int test_interface_async_adapter(void)
{
  async_mock_t mock;
  ftun_linux_route_async_io_t io;
  ftun_linux_route_io_t sync_io = {sync_apply, sync_remove, &mock};
  ftun_interface_ops_t ops = ftun_linux_interface_ops;
  ftun_interface_spec_t spec = {{"ftun-route0", 11u}, {10u, 77u, 0u, 1u}, 30u, 0x4654u, true, NULL};
  ftun_interface_async_options_t options = {0};
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_budget_usage_t baseline, usage;
  ftun_reservation_t *pressure = NULL;
  ftun_interface_async_info_t info;
  void *source = NULL, *state = NULL, *original;
  unsigned int iteration;
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 65536u, &budget) == FTUN_OK);
  CHECK(ftun_core_context_create(budget, &core) == FTUN_OK);
  CHECK(ftun_event_loop_create_with_capacity(core, 8u, &loop) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &baseline) == FTUN_OK);
  options = (ftun_interface_async_options_t){budget, loop, 100u, 5u, 1000u};
  ops.context = &sync_io;
  ops.async.context = &io;
  for (iteration = 0u; iteration < 2u; iteration++) {
    uint64_t now_ms = 100u;
    async_mock_init(&mock);
    io = async_mock_io(&mock);
    if (iteration == 0u) {
      CHECK(ops.restore(ops.context, &spec, &source) == FTUN_OK);
      original = source;
      CHECK(ftun_budget_reserve_cleanup(budget, baseline.total_available, &pressure) == FTUN_OK);
      CHECK(ops.async.adopt(ops.async.context, &source, &options, &state) == FTUN_E_LIMIT &&
        source == original && state == NULL);
      CHECK(ftun_reservation_release(&pressure) == FTUN_OK);
      CHECK(ftun_budget_reserve(budget, baseline.normal_available, &pressure) == FTUN_OK);
      CHECK(ops.async.adopt(ops.async.context, &source, &options, &state) == FTUN_OK && source == NULL);
      CHECK(ftun_reservation_release(&pressure) == FTUN_OK);
      CHECK(mock.request_count == 0u);
    } else {
      CHECK(ops.async.start(ops.async.context, &spec, &options, &state) == FTUN_OK);
      CHECK(interface_drive(&ops.async, state, &now_ms, FTUN_INTERFACE_READY));
    }
    CHECK(ops.async.query(ops.async.context, state, &info) == FTUN_OK && info.state == FTUN_INTERFACE_READY);
    CHECK(ops.async.destroy(ops.async.context, &state) == FTUN_E_AGAIN && state != NULL);
    CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used > baseline.used);
    CHECK(ops.async.withdraw(ops.async.context, state, now_ms, now_ms + 1000u) == FTUN_OK);
    CHECK(interface_drive(&ops.async, state, &now_ms, FTUN_INTERFACE_RELEASED));
    CHECK(ops.async.destroy(ops.async.context, &state) == FTUN_OK && state == NULL);
    CHECK(async_present_count(&mock) == 0);
    CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used == baseline.used &&
      usage.used_resources.descriptors == baseline.used_resources.descriptors);
  }
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK);
  CHECK(ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

int main(void)
{
  CHECK(test_cancel_pending_add() == 0);
  CHECK(test_adopt_owned_resources() == 0);
  CHECK(test_submit_backpressure_deadline() == 0);
  CHECK(test_total_deadline_before_reply() == 0);
  CHECK(test_interface_async_adapter() == 0);
  CHECK(test_success_and_serialization() == 0);
  CHECK(test_lost_ack_reconcile() == 0);
  CHECK(test_lost_ack_without_effect() == 0);
  CHECK(test_partial_error_rollback() == 0);
  CHECK(test_uncertain_and_cleanup_retry() == 0);
  CHECK(test_remove_lost_ack() == 0);
  CHECK(test_conflict_and_inputs() == 0);
  CHECK(test_network_guard_and_overlay_transactions() == 0);
  return 0;
}
