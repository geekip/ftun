#include "app/config/model.h"
#include "app/runtime_support.h"
#include "libs/tun/linux/routes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const ftun_app_runtime_support_t *original;
static ftun_app_runtime_support_t support;
static unsigned int starts, prepares, applied, removed;
static bool invalid;
static ftun_linux_route_reply_t pending_reply;
static bool has_reply;

static bool auto_route(void)
{
  const char *value = getenv("FTUN_TEST_CONTROL_AUTO_ROUTE");
  if (value == NULL) abort();
  return strcmp(value, "true") == 0;
}

static ftun_status_t start(ftun_core_t *core, ftun_budget_t *budget,
  const ftun_config_t *config, uint64_t generation,
  ftun_app_runtime_candidate_t **out, uint32_t *stage)
{
  starts++;
  if (generation != 1u || applied != 0u) invalid = true;
  return original->start(core, budget, config, generation, out, stage);
}

static ftun_status_t prepare(ftun_budget_t *budget, const ftun_config_t *config, uint64_t maximum,
  const ftun_app_prepare_context_t *context,
  ftun_app_runtime_candidate_t **out, bool *publish)
{
  prepares++;
  /* 第二次候选关闭 TUN，仍必须使用尚未提交的当前路由授权。 */
  if (context->generation != (prepares == 1u ? 2u : 3u) ||
      context->allow_system_resolver == auto_route() ||
      context->socket_mark != UINT32_C(0x4654)) invalid = true;
  return original->prepare(budget, config, maximum, context, out, publish);
}

const ftun_app_runtime_support_t *__real_ftun_app_runtime_support(void);
const ftun_app_runtime_support_t *__wrap_ftun_app_runtime_support(void)
{
  if (original == NULL) {
    original = __real_ftun_app_runtime_support();
    if (original == NULL) abort();
    support = *original;
    support.start = start;
    support.prepare = prepare;
  }
  return &support;
}

/* 实际路由事务使用无宿主副作用的后端，仍验证 apply/release 对称。 */
static ftun_status_t apply(void *context, const ftun_linux_route_resource_t *resource)
{ (void)context; (void)resource; applied++; return FTUN_OK; }
static ftun_status_t remove_route(void *context, const ftun_linux_route_resource_t *resource)
{ (void)context; (void)resource; removed++; return FTUN_OK; }

ftun_status_t __wrap_ftun_linux_route_prepare(const ftun_route_policy_t *policy,
  ftun_route_transaction_t **out)
{
  const ftun_linux_route_io_t io = {apply, remove_route, NULL};
  return ftun_linux_route_prepare_with_io(policy, &io, out);
}

ftun_status_t __wrap_ftun_linux_route_prepare_with_budget(ftun_budget_t *budget,
  const ftun_route_policy_t *policy, ftun_route_transaction_t **out)
{
  const ftun_linux_route_io_t io = {apply, remove_route, NULL};
  return ftun_linux_route_prepare_with_io_and_budget(budget, policy, &io, out);
}

static ftun_status_t submit(void *context, const ftun_linux_route_request_t *request)
{
  (void)context;
  if (request->kind != FTUN_LINUX_ROUTE_REQUEST_REMOVE || has_reply) return FTUN_E_INVALID;
  removed++;
  pending_reply = (ftun_linux_route_reply_t){request->sequence, FTUN_OK, false};
  has_reply = true;
  return FTUN_OK;
}

static ftun_status_t receive_reply(void *context, ftun_linux_route_reply_t *reply)
{
  (void)context;
  if (!has_reply) return FTUN_E_AGAIN;
  *reply = pending_reply;
  has_reply = false;
  return FTUN_OK;
}

ftun_status_t __wrap_ftun_linux_route_async_adopt(ftun_route_transaction_t **source,
  ftun_event_loop_t *loop, uint64_t now_ms, uint64_t step_timeout_ms,
  uint64_t deadline_ms, ftun_linux_route_async_t **out)
{
  const ftun_linux_route_async_io_t io = {submit, receive_reply, NULL};
  (void)loop;
  return ftun_linux_route_async_adopt_with_io(source, &io, now_ms,
    step_timeout_ms, deadline_ms, 1u, out);
}

int ftun_test_control_policy_verify(void)
{
  if (invalid || starts != 1u || prepares != 3u || applied != removed ||
      (auto_route() ? applied == 0u : applied != 0u)) {
    fprintf(stderr, "control policy failed: starts=%u prepares=%u routes=%u/%u invalid=%u\n",
      starts, prepares, applied, removed, (unsigned int)invalid);
    return 1;
  }
  puts("control policy: startup generation, active-route authorization and reload copies passed");
  return 0;
}
