#define _GNU_SOURCE 1
#include "platform/route.h"
#include "platform/linux/route_transaction.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define FTUN_ROUTE_ASYNC_MAGIC UINT32_C(0x46544152)

typedef enum {
  FTUN_ROUTE_ASYNC_PREFLIGHT = 1,
  FTUN_ROUTE_ASYNC_CHANGE,
  FTUN_ROUTE_ASYNC_RECONCILE
} ftun_route_async_step_t;

struct ftun_platform_route_async {
  uint32_t magic;
  ftun_route_kernel_t kernel;
  ftun_route_resource_t resources[FTUN_LINUX_ROUTE_PLAN_MAX_RESOURCES];
  bool active[FTUN_LINUX_ROUTE_PLAN_MAX_RESOURCES];
  size_t resource_count;
  size_t active_count;
  size_t cursor;
  size_t remove_cursor;
  ftun_route_async_state_t state;
  ftun_route_async_step_t step;
  ftun_status_t result;
  ftun_status_t cleanup_result;
  ftun_status_t ambiguous_result;
  ftun_route_async_io_t io;
  uint64_t step_timeout_ms;
  uint64_t total_deadline_ms;
  uint64_t pending_deadline_ms;
  uint32_t next_sequence;
  size_t stale_replies;
  size_t timeouts;
  size_t cleanup_failures;
  bool has_current;
  bool request_sent;
  bool running;
  bool release_requested;
  bool retained_add;
  /* 安装前清理遗留对象：sweeping 期间逐个资源发放宽选择子的删除，直到 STALE。 */
  bool sweep;
  bool sweeping;
  size_t sweep_rounds;
  size_t strays_removed;
  bool repairing;
  ftun_status_t repair_result;
  size_t repair_runs;
  size_t repairs;
  size_t repair_failures;
  bool system_io;
  /* 同一路由表号的实例互斥锁；与 operation 同生命周期。 */
  ftun_handle_t lock_descriptor;
  ftun_route_events_t events;
  bool watching;
};

size_t ftun_platform_route_async_allocation_size(void)
{
  return sizeof(ftun_platform_route_async_t);
}

static uint64_t ftun_route_async_add_deadline(uint64_t now_ms,
                                              uint64_t timeout_ms)
{
  return timeout_ms > UINT64_MAX - now_ms ? UINT64_MAX : now_ms + timeout_ms;
}

static uint64_t ftun_route_async_step_deadline(
  const ftun_platform_route_async_t *operation, uint64_t now_ms)
{
  uint64_t deadline = ftun_route_async_add_deadline(
    now_ms, operation->step_timeout_ms);
  if (deadline > operation->total_deadline_ms) {
    deadline = operation->total_deadline_ms;
  }
  return deadline;
}

static uint32_t ftun_route_async_next_sequence(
  ftun_platform_route_async_t *operation)
{
  uint32_t sequence = operation->next_sequence;
  operation->next_sequence++;
  if (operation->next_sequence == 0u) operation->next_sequence = 1u;
  return sequence;
}

static void ftun_route_async_io_ready(void *user, uint32_t events)
{
  ftun_platform_route_async_t *operation = user;
  if ((events & (FTUN_POLLER_READ | FTUN_POLLER_WRITE)) != 0u) {
    operation->kernel.io_ready = true;
    operation->kernel.runnable = true;
  }
  if ((events & FTUN_POLLER_ERROR) != 0u) {
    operation->kernel.io_error = true;
    operation->kernel.runnable = true;
  }
}

static void ftun_route_async_timer_ready(void *user, uint32_t events)
{
  ftun_platform_route_async_t *operation = user;
  if ((events & FTUN_ROUTE_TIMER) != 0u) operation->kernel.runnable = true;
}

static ftun_status_t ftun_route_native_watch(ftun_platform_route_async_t *operation)
{
  ftun_status_t status = operation->events.watch(operation->events.context,
    (ftun_native_socket_t)operation->kernel.descriptor,
    FTUN_POLLER_READ | FTUN_POLLER_ERROR, ftun_route_async_io_ready, operation);
  if (status == FTUN_OK) operation->watching = true;
  return status;
}
static ftun_status_t ftun_route_native_unwatch(ftun_platform_route_async_t *operation)
{
  ftun_status_t status = operation->events.unwatch(operation->events.context);
  if (status == FTUN_OK) operation->watching = false;
  return status;
}

static ftun_status_t ftun_route_async_timer_cancel(
  ftun_platform_route_async_t *operation)
{
  if (!operation->system_io) return FTUN_OK;
  return operation->events.untimer(operation->events.context);
}

static ftun_status_t ftun_route_async_timer_start(
  ftun_platform_route_async_t *operation, uint64_t deadline_ms)
{
  ftun_status_t status;
  if (!operation->system_io) return FTUN_OK;
  status = ftun_route_async_timer_cancel(operation);
  if (status != FTUN_OK) return status;
  return operation->events.timer(operation->events.context, deadline_ms,
    ftun_route_async_timer_ready, operation);
}

static ftun_status_t ftun_system_route_async_submit(void *context,
  const ftun_route_request_t *request)
{
  ftun_platform_route_async_t *operation = context;
  ftun_status_t status = ftun_platform_route_submit(&operation->kernel, request);
  if (status == FTUN_OK || status == FTUN_E_AGAIN) {
    (void)operation->events.update(operation->events.context,
      FTUN_POLLER_READ | FTUN_POLLER_ERROR | (operation->kernel.write_interest ? FTUN_POLLER_WRITE : 0u));
  }
  return status;
}
static ftun_status_t ftun_system_route_async_receive(void *context, ftun_route_reply_t *reply)
{
  ftun_platform_route_async_t *operation = context;
  return ftun_platform_route_receive(&operation->kernel, reply);
}

static ftun_status_t ftun_route_async_pending_clear(
  ftun_platform_route_async_t *operation)
{
  ftun_status_t status = ftun_route_async_timer_cancel(operation);
  operation->request_sent = false;
  operation->kernel.pending_sequence = 0u;
  operation->pending_deadline_ms = 0u;
  operation->kernel.pending_kind = 0;
  return status;
}

static void ftun_route_async_finish_cleanup(
  ftun_platform_route_async_t *operation)
{
  operation->has_current = false;
  if (operation->active_count != 0u) {
    operation->state = FTUN_ROUTE_ASYNC_CLEANUP_FAILED;
    if (operation->cleanup_result == FTUN_OK) {
      operation->cleanup_result = FTUN_E_STATE_CORRUPT;
    }
  } else if (operation->state == FTUN_ROUTE_ASYNC_RELEASING) {
    operation->state = FTUN_ROUTE_ASYNC_RELEASED;
  } else {
    operation->state = FTUN_ROUTE_ASYNC_FAILED;
  }
  operation->kernel.runnable = false;
}

static void ftun_route_async_begin_cleanup(
  ftun_platform_route_async_t *operation, ftun_status_t result,
  bool releasing)
{
  if (operation->result == FTUN_OK) operation->result = result;
  operation->state = releasing ? FTUN_ROUTE_ASYNC_RELEASING :
    FTUN_ROUTE_ASYNC_COMPENSATING;
  operation->remove_cursor = operation->resource_count;
  operation->has_current = false;
  operation->step = FTUN_ROUTE_ASYNC_CHANGE;
  operation->kernel.runnable = true;
  if (operation->active_count == 0u) ftun_route_async_finish_cleanup(operation);
}

static void ftun_route_async_cleanup_failed(
  ftun_platform_route_async_t *operation, ftun_status_t status)
{
  if (operation->cleanup_result == FTUN_OK) operation->cleanup_result = status;
  operation->cleanup_failures++;
  operation->has_current = false;
  operation->step = FTUN_ROUTE_ASYNC_CHANGE;
  operation->kernel.runnable = true;
}

/* 修复失败不撤销事务：资源保持原所有权，回到 READY 等待下次对账。 */
static void ftun_route_async_repair_end(
  ftun_platform_route_async_t *operation, ftun_status_t status)
{
  operation->repairing = false;
  operation->repair_result = status;
  if (status != FTUN_OK) operation->repair_failures++;
  operation->has_current = false;
  operation->step = FTUN_ROUTE_ASYNC_PREFLIGHT;
  operation->state = FTUN_ROUTE_ASYNC_READY;
  operation->kernel.runnable = false;
}

static void ftun_route_async_apply_failed(
  ftun_platform_route_async_t *operation, ftun_status_t status)
{
  if (operation->repairing && !operation->release_requested) {
    ftun_route_async_repair_end(operation, status);
    return;
  }
  ftun_route_async_begin_cleanup(operation, status, operation->release_requested);
}

static void ftun_route_async_removed(ftun_platform_route_async_t *operation)
{
  if (operation->active[operation->cursor]) {
    operation->active[operation->cursor] = false;
    operation->active_count--;
  }
  operation->has_current = false;
  operation->step = FTUN_ROUTE_ASYNC_CHANGE;
  operation->kernel.runnable = true;
}

static void ftun_route_async_applied(ftun_platform_route_async_t *operation)
{
  if (operation->repairing && operation->step != FTUN_ROUTE_ASYNC_PREFLIGHT) {
    operation->repairs++;
  }
  if (!operation->active[operation->cursor]) {
    operation->active[operation->cursor] = true;
    operation->active_count++;
  }
  operation->cursor++;
  operation->has_current = false;
  operation->step = FTUN_ROUTE_ASYNC_PREFLIGHT;
  operation->kernel.runnable = true;
  if (operation->release_requested) {
    ftun_route_async_begin_cleanup(operation, FTUN_E_CANCELLED, true);
  }
}

static int ftun_route_async_prepare_current(
  ftun_platform_route_async_t *operation)
{
  if (operation->state == FTUN_ROUTE_ASYNC_APPLYING) {
    while (operation->sweeping &&
           operation->cursor < operation->resource_count &&
           operation->resources[operation->cursor].kind ==
             FTUN_LINUX_ROUTE_ADDRESS) {
      operation->cursor++;
    }
    if (operation->sweeping && operation->cursor >= operation->resource_count) {
      operation->sweeping = false;
      operation->cursor = 0u;
      operation->step = FTUN_ROUTE_ASYNC_PREFLIGHT;
    }
    if (operation->cursor >= operation->resource_count) {
      if (operation->repairing) {
        ftun_route_async_repair_end(operation, FTUN_OK);
        return 0;
      }
      operation->state = FTUN_ROUTE_ASYNC_READY;
      operation->kernel.runnable = false;
      return 0;
    }
    operation->has_current = true;
    return 1;
  }
  while (operation->remove_cursor != 0u) {
    operation->remove_cursor--;
    if (operation->active[operation->remove_cursor]) {
      operation->cursor = operation->remove_cursor;
      operation->has_current = true;
      return 1;
    }
  }
  ftun_route_async_finish_cleanup(operation);
  return 0;
}

static void ftun_route_async_reply(
  ftun_platform_route_async_t *operation,
  const ftun_route_reply_t *reply)
{
  bool applying = operation->state == FTUN_ROUTE_ASYNC_APPLYING;
  if (operation->sweeping) {
    /* OK：删掉了一个遗留对象，同一资源再试一次；STALE：已经没有了。 */
    if (reply->status == FTUN_OK) {
      operation->strays_removed++;
      if (++operation->sweep_rounds >= FTUN_LINUX_ROUTE_SWEEP_LIMIT) {
        ftun_route_async_apply_failed(operation, FTUN_E_LIMIT);
        return;
      }
    } else if (reply->status == FTUN_E_STALE) {
      operation->cursor++;
      operation->sweep_rounds = 0u;
    } else {
      ftun_route_async_apply_failed(operation, reply->status);
      return;
    }
    operation->has_current = false;
    operation->kernel.runnable = true;
    return;
  }
  if (operation->step == FTUN_ROUTE_ASYNC_PREFLIGHT) {
    if (reply->status != FTUN_OK) {
      ftun_route_async_apply_failed(operation, reply->status);
    } else if (reply->present) {
      /* 实例锁保证没有其他存活实例使用同一表号；协议号 186 且完全一致
       * 的对象只能是上次崩溃遗留，原地接管并在释放时撤销。地址对象不带
       * 协议标记，可能属于外部，仍按冲突拒绝。 */
      if (operation->resources[operation->cursor].kind ==
            FTUN_LINUX_ROUTE_ADDRESS && !operation->active[operation->cursor]) {
        ftun_route_async_apply_failed(operation, FTUN_E_REJECTED);
      } else {
        ftun_route_async_applied(operation);
      }
    } else {
      operation->step = FTUN_ROUTE_ASYNC_CHANGE;
      operation->kernel.runnable = true;
    }
    return;
  }
  if (operation->step == FTUN_ROUTE_ASYNC_CHANGE) {
    if (applying) {
      if (reply->status == FTUN_OK) ftun_route_async_applied(operation);
      else ftun_route_async_apply_failed(operation, reply->status);
    } else if (reply->status == FTUN_OK || reply->status == FTUN_E_STALE) {
      ftun_route_async_removed(operation);
    } else {
      ftun_route_async_cleanup_failed(operation, reply->status);
    }
    return;
  }
  if (reply->status != FTUN_OK) {
    if (applying) {
      if (!operation->active[operation->cursor]) {
        operation->active[operation->cursor] = true;
        operation->active_count++;
      }
      ftun_route_async_apply_failed(operation, FTUN_E_STATE_CORRUPT);
    } else {
      ftun_route_async_cleanup_failed(operation, FTUN_E_STATE_CORRUPT);
    }
  } else if (applying) {
    if (reply->present) ftun_route_async_applied(operation);
    else ftun_route_async_apply_failed(operation, operation->ambiguous_result);
  } else if (!reply->present) {
    ftun_route_async_removed(operation);
  } else {
    ftun_route_async_cleanup_failed(operation, operation->ambiguous_result);
  }
}

static void ftun_route_async_timeout(ftun_platform_route_async_t *operation)
{
  bool applying = operation->state == FTUN_ROUTE_ASYNC_APPLYING;
  operation->timeouts++;
  if (operation->sweeping) {
    ftun_route_async_apply_failed(operation, FTUN_E_TIMEOUT);
    return;
  }
  if (operation->step == FTUN_ROUTE_ASYNC_CHANGE) {
    operation->ambiguous_result = FTUN_E_TIMEOUT;
    operation->step = FTUN_ROUTE_ASYNC_RECONCILE;
    operation->kernel.runnable = true;
  } else if (operation->step == FTUN_ROUTE_ASYNC_PREFLIGHT) {
    ftun_route_async_apply_failed(operation, FTUN_E_TIMEOUT);
  } else if (applying) {
    if (!operation->active[operation->cursor]) {
      operation->active[operation->cursor] = true;
      operation->active_count++;
    }
    ftun_route_async_apply_failed(operation, FTUN_E_TIMEOUT);
  } else {
    ftun_route_async_cleanup_failed(operation, FTUN_E_TIMEOUT);
  }
}

static ftun_route_request_kind_t ftun_route_async_request_kind(
  const ftun_platform_route_async_t *operation)
{
  if (operation->sweeping) return FTUN_LINUX_ROUTE_REQUEST_REMOVE;
  if (operation->step != FTUN_ROUTE_ASYNC_CHANGE) {
    return FTUN_LINUX_ROUTE_REQUEST_QUERY;
  }
  return operation->state == FTUN_ROUTE_ASYNC_APPLYING ?
    FTUN_LINUX_ROUTE_REQUEST_ADD : FTUN_LINUX_ROUTE_REQUEST_REMOVE;
}

static ftun_status_t ftun_route_async_allocate_plan(
  const ftun_route_plan_t *plan, const ftun_route_async_io_t *io,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  uint32_t initial_sequence, ftun_platform_route_async_t **out)
{
  ftun_platform_route_async_t *operation;
  if (out != NULL) *out = NULL;
  if (out == NULL || !ftun_route_plan_valid(plan) || io == NULL ||
      io->submit == NULL || io->receive == NULL || step_timeout_ms == 0u ||
      total_deadline_ms <= now_ms || initial_sequence == 0u) {
    return FTUN_E_INVALID;
  }
  operation = (ftun_platform_route_async_t *)calloc(1u, sizeof(*operation));
  if (operation == NULL) return FTUN_E_LIMIT;
  operation->magic = FTUN_ROUTE_ASYNC_MAGIC;
  operation->kernel.descriptor = -1;
  operation->lock_descriptor = -1;
  operation->io = *io;
  operation->step_timeout_ms = step_timeout_ms;
  operation->total_deadline_ms = total_deadline_ms;
  operation->next_sequence = initial_sequence;
  operation->state = FTUN_ROUTE_ASYNC_APPLYING;
  operation->step = FTUN_ROUTE_ASYNC_PREFLIGHT;
  operation->result = FTUN_OK;
  operation->cleanup_result = FTUN_OK;
  operation->kernel.runnable = true;
  operation->resource_count = plan->resource_count;
  memcpy(operation->resources, plan->resources,
         plan->resource_count * sizeof(plan->resources[0]));
  operation->sweep = plan->sweep;
  operation->sweeping = plan->sweep;
  *out = operation;
  return FTUN_OK;
}

static ftun_status_t ftun_route_async_policy_plan(
  const ftun_route_policy_t *policy, ftun_route_plan_t *out)
{
  ftun_platform_route_transaction_t transaction;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (out == NULL || !ftun_route_policy_valid(policy)) return FTUN_E_INVALID;
  memset(&transaction, 0, sizeof(transaction));
  if (!ftun_route_build(policy, &transaction)) return FTUN_E_LIMIT;
  out->resource_count = transaction.resource_count;
  memcpy(out->resources, transaction.resources,
         transaction.resource_count * sizeof(transaction.resources[0]));
  return ftun_route_plan_valid(out) ? FTUN_OK : FTUN_E_INVALID;
}

ftun_status_t ftun_platform_route_async_start_with_io(
  const ftun_route_policy_t *policy, const ftun_route_async_io_t *io,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  uint32_t initial_sequence, ftun_platform_route_async_t **out)
{
  ftun_route_plan_t plan;
  ftun_status_t status = ftun_route_async_policy_plan(policy, &plan);
  if (status != FTUN_OK) {
    if (out != NULL) *out = NULL;
    return status;
  }
  return ftun_route_async_allocate_plan(&plan, io, now_ms, step_timeout_ms,
    total_deadline_ms, initial_sequence, out);
}

ftun_status_t ftun_platform_route_async_start_plan_with_io(
  const ftun_route_plan_t *plan, const ftun_route_async_io_t *io,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  uint32_t initial_sequence, ftun_platform_route_async_t **out)
{
  return ftun_route_async_allocate_plan(plan, io, now_ms, step_timeout_ms,
    total_deadline_ms, initial_sequence, out);
}

static ftun_status_t ftun_route_async_start_system_plan(
  const ftun_route_plan_t *plan, uint32_t lock_table,
  const ftun_route_events_t *events,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  ftun_platform_route_async_t **out)
{
  ftun_platform_route_async_t *operation = NULL;
  ftun_route_async_io_t io;
  ftun_status_t status;
  uint32_t sequence;
  ftun_handle_t descriptor;
  if (out != NULL) *out = NULL;
  if (events == NULL || out == NULL || !ftun_route_plan_valid(plan)) {
    return FTUN_E_INVALID;
  }
  ftun_handle_t lock_descriptor;
  status = ftun_route_lock_table(lock_table, &lock_descriptor);
  if (status != FTUN_OK) return status;
  status = ftun_platform_route_open(&descriptor);
  if (status != FTUN_OK) {
    if (lock_descriptor >= 0) (void)ftun_platform_route_close(lock_descriptor);
    return status;
  }
  sequence = (uint32_t)(now_ms ^ (uint64_t)(unsigned int)descriptor);
  if (sequence == 0u) sequence = 1u;
  memset(&io, 0, sizeof(io));
  io.submit = ftun_system_route_async_submit;
  io.receive = ftun_system_route_async_receive;
  status = ftun_route_async_allocate_plan(plan, &io, now_ms, step_timeout_ms,
    total_deadline_ms, sequence, &operation);
  if (status != FTUN_OK) {
    (void)ftun_platform_route_close(descriptor);
    if (lock_descriptor >= 0) (void)ftun_platform_route_close(lock_descriptor);
    return status;
  }
  operation->system_io = true;
  operation->kernel.descriptor = (int)descriptor;
  operation->lock_descriptor = lock_descriptor;
  operation->events = *events;
  operation->io.context = operation;
  status = ftun_route_native_watch(operation);
  if (status != FTUN_OK) {
    operation->magic = 0u;
    (void)ftun_platform_route_close(descriptor);
    if (lock_descriptor >= 0) (void)ftun_platform_route_close(lock_descriptor);
    free(operation);
    return status;
  }
  *out = operation;
  return FTUN_OK;
}

ftun_status_t ftun_platform_route_async_start_plan(
  const ftun_route_plan_t *plan, const ftun_route_events_t *events,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  ftun_platform_route_async_t **out)
{
  return ftun_route_async_start_system_plan(plan, 0u, events, now_ms,
    step_timeout_ms, total_deadline_ms, out);
}

ftun_status_t ftun_platform_route_async_start(
  const ftun_route_policy_t *policy, const ftun_route_events_t *events,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  ftun_platform_route_async_t **out)
{
  ftun_route_plan_t plan;
  ftun_status_t status;
  status = ftun_route_async_policy_plan(policy, &plan);
  if (status != FTUN_OK) {
    if (out != NULL) *out = NULL;
    return status;
  }
  /* 策略事务持有表互斥锁，同表同优先级的协议号 186 对象只能是遗留。 */
  plan.sweep = true;
  return ftun_route_async_start_system_plan(&plan, policy->routing_domain, events,
    now_ms, step_timeout_ms, total_deadline_ms, out);
}

static ftun_status_t ftun_route_async_adopt_plan(
  ftun_platform_route_transaction_t **source, ftun_platform_route_async_t **out,
  ftun_route_plan_t *plan)
{
  ftun_route_info_t info;
  size_t index, active = 0u;
  if (source == NULL || *source == NULL || out == NULL || *out != NULL) return FTUN_E_INVALID;
  if (ftun_platform_route_get_info(*source, &info) != FTUN_OK ||
      info.resource_count == 0u || info.resource_count > FTUN_LINUX_ROUTE_MAX_RESOURCES) {
    return FTUN_E_INVALID;
  }
  for (index = 0u; index < info.resource_count; index++) {
    if ((*source)->active[index]) active++;
  }
  if (active != info.active_count) return FTUN_E_STATE_CORRUPT;
  memset(plan, 0, sizeof(*plan));
  plan->resource_count = info.resource_count;
  memcpy(plan->resources, (*source)->resources, info.resource_count * sizeof(plan->resources[0]));
  return FTUN_OK;
}

static void ftun_route_async_adopt_commit(ftun_platform_route_transaction_t **source,
  ftun_platform_route_async_t *operation, ftun_platform_route_async_t **out)
{
  ftun_platform_route_transaction_t *owned = *source;
  memcpy(operation->active, owned->active, owned->resource_count * sizeof(owned->active[0]));
  operation->active_count = owned->active_count;
  /* 表互斥锁随资源一起转交，关闭描述符才释放。 */
  if (owned->lock_descriptor >= 0 && operation->lock_descriptor < 0) {
    operation->lock_descriptor = owned->lock_descriptor;
    owned->lock_descriptor = -1;
  }
  operation->kernel.runnable = false;
  if (!owned->retiring && operation->active_count == operation->resource_count) {
    operation->state = FTUN_ROUTE_ASYNC_READY;
  } else if (operation->active_count == 0u) {
    operation->state = FTUN_ROUTE_ASYNC_RELEASED;
  } else {
    operation->state = FTUN_ROUTE_ASYNC_CLEANUP_FAILED;
    operation->result = operation->cleanup_result = FTUN_E_STATE_CORRUPT;
  }
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *source = NULL;
  *out = operation;
}

ftun_status_t ftun_platform_route_async_adopt_with_io(
  ftun_platform_route_transaction_t **source, const ftun_route_async_io_t *io,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  uint32_t initial_sequence, ftun_platform_route_async_t **out)
{
  ftun_route_plan_t plan;
  ftun_platform_route_async_t *operation = NULL;
  ftun_status_t status = ftun_route_async_adopt_plan(source, out, &plan);
  if (status != FTUN_OK) return status;
  status = ftun_route_async_allocate_plan(&plan, io, now_ms, step_timeout_ms,
    total_deadline_ms, initial_sequence, &operation);
  if (status == FTUN_OK) ftun_route_async_adopt_commit(source, operation, out);
  return status;
}

ftun_status_t ftun_platform_route_async_adopt(
  ftun_platform_route_transaction_t **source, const ftun_route_events_t *events,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  ftun_platform_route_async_t **out)
{
  ftun_route_plan_t plan;
  ftun_platform_route_async_t *operation = NULL;
  ftun_status_t status = ftun_route_async_adopt_plan(source, out, &plan);
  if (status != FTUN_OK) return status;
  status = ftun_route_async_start_system_plan(&plan, 0u, events, now_ms,
    step_timeout_ms, total_deadline_ms, &operation);
  if (status == FTUN_OK) ftun_route_async_adopt_commit(source, operation, out);
  return status;
}

ftun_status_t ftun_platform_route_async_run(ftun_platform_route_async_t *operation,
                                         uint64_t now_ms, size_t max_work,
                                         size_t *out_work)
{
  size_t work = 0u;
  ftun_status_t return_status = FTUN_OK;
  if (out_work != NULL) *out_work = 0u;
  if (operation == NULL || operation->magic != FTUN_ROUTE_ASYNC_MAGIC ||
      max_work == 0u || out_work == NULL) return FTUN_E_INVALID;
  if (operation->running) return FTUN_E_AGAIN;
  operation->running = true;
  if (now_ms >= operation->total_deadline_ms && operation->repairing &&
      !operation->release_requested &&
      operation->state == FTUN_ROUTE_ASYNC_APPLYING) {
    /* 修复期限到达：已有资源不动，迟到回复按陈旧处理，下次对账重试。 */
    operation->timeouts++;
    return_status = ftun_route_async_pending_clear(operation);
    ftun_route_async_repair_end(operation, FTUN_E_TIMEOUT);
    work++;
  }
  if (now_ms >= operation->total_deadline_ms &&
      (operation->state == FTUN_ROUTE_ASYNC_APPLYING ||
       operation->state == FTUN_ROUTE_ASYNC_COMPENSATING ||
       operation->state == FTUN_ROUTE_ASYNC_RELEASING)) {
    bool releasing = operation->state == FTUN_ROUTE_ASYNC_RELEASING;
    /* 总期限优先于迟到回复。保留未决 ADD 的请求身份，新的 release
     * 先确认 ACK/reconcile，不能把明确拒绝的外部对象当作自己的资源。 */
    if (operation->state == FTUN_ROUTE_ASYNC_APPLYING &&
        operation->has_current &&
        (operation->step == FTUN_ROUTE_ASYNC_RECONCILE ||
         (operation->request_sent && operation->kernel.pending_kind == FTUN_LINUX_ROUTE_REQUEST_ADD))) {
      operation->retained_add = true;
      if (!operation->active[operation->cursor]) {
        operation->active[operation->cursor] = true;
        operation->active_count++;
      }
    }
    operation->timeouts++;
    if (operation->result == FTUN_OK) operation->result = FTUN_E_TIMEOUT;
    return_status = operation->retained_add ?
      ftun_route_async_timer_cancel(operation) : ftun_route_async_pending_clear(operation);
    if (!operation->retained_add) operation->has_current = false;
    operation->kernel.runnable = false;
    if (operation->active_count != 0u) {
      operation->cleanup_result = FTUN_E_TIMEOUT;
      operation->state = FTUN_ROUTE_ASYNC_CLEANUP_FAILED;
    } else {
      operation->state = releasing ? FTUN_ROUTE_ASYNC_RELEASED : FTUN_ROUTE_ASYNC_FAILED;
    }
    work++;
  }
  while (work < max_work) {
    ftun_status_t status;
    if (operation->state == FTUN_ROUTE_ASYNC_READY ||
        operation->state == FTUN_ROUTE_ASYNC_FAILED ||
        operation->state == FTUN_ROUTE_ASYNC_CLEANUP_FAILED ||
        operation->state == FTUN_ROUTE_ASYNC_RELEASED) break;
    if (!operation->has_current && !ftun_route_async_prepare_current(operation)) {
      break;
    }
    if (!operation->request_sent) {
      ftun_route_request_t request;
      if (now_ms >= operation->total_deadline_ms) {
        ftun_route_async_timeout(operation);
        work++;
        continue;
      }
      memset(&request, 0, sizeof(request));
      request.sequence = ftun_route_async_next_sequence(operation);
      request.kind = ftun_route_async_request_kind(operation);
      request.resource = operation->resources[operation->cursor];
      request.resource.stray = operation->sweeping;
      status = operation->io.submit(operation->io.context, &request);
      if (status == FTUN_E_AGAIN) {
        operation->kernel.runnable = false;
        /* 即使首个报文还未写入，也必须有总期限唤醒。 */
        return_status = ftun_route_async_timer_start(operation, operation->total_deadline_ms);
        break;
      }
      if (status == FTUN_E_STALE && request.kind == FTUN_LINUX_ROUTE_REQUEST_REMOVE &&
          operation->state != FTUN_ROUTE_ASYNC_APPLYING) {
        /* 构造请求时对象所属接口已不存在：资源已随接口消失，无需发送。 */
        ftun_route_async_removed(operation);
        work++;
        continue;
      }
      if (status != FTUN_OK) {
        if (operation->state == FTUN_ROUTE_ASYNC_APPLYING) {
          ftun_route_async_apply_failed(operation, status);
        } else {
          ftun_route_async_cleanup_failed(operation, status);
        }
        work++;
        continue;
      }
      operation->kernel.pending_sequence = request.sequence;
      operation->kernel.pending_kind = request.kind;
      operation->pending_deadline_ms =
        ftun_route_async_step_deadline(operation, now_ms);
      operation->request_sent = true;
      operation->kernel.runnable = false;
      status = ftun_route_async_timer_start(operation,
        operation->pending_deadline_ms);
      if (status != FTUN_OK) {
        operation->ambiguous_result = status;
        operation->step = FTUN_ROUTE_ASYNC_RECONCILE;
        status = ftun_route_async_pending_clear(operation);
        if (status != FTUN_OK) {
          return_status = status;
          break;
        }
        operation->kernel.runnable = true;
      }
      work++;
      continue;
    }
    {
      ftun_route_reply_t reply;
      operation->kernel.runnable = false;
      status = operation->io.receive(operation->io.context, &reply);
      if (status == FTUN_E_AGAIN) {
        if (now_ms >= operation->pending_deadline_ms) {
          status = ftun_route_async_pending_clear(operation);
          if (status != FTUN_OK) {
            return_status = status;
            break;
          }
          ftun_route_async_timeout(operation);
          work++;
          continue;
        }
        if (operation->kernel.runnable) {
          work++;
          continue;
        }
        break;
      }
      if (status != FTUN_OK) {
        ftun_route_request_kind_t kind = operation->kernel.pending_kind;
        ftun_status_t clear_status =
          ftun_route_async_pending_clear(operation);
        if (clear_status != FTUN_OK) {
          return_status = clear_status;
          break;
        }
        if (operation->sweeping) {
          ftun_route_async_apply_failed(operation, status);
        } else if (kind == FTUN_LINUX_ROUTE_REQUEST_ADD ||
            kind == FTUN_LINUX_ROUTE_REQUEST_REMOVE) {
          operation->ambiguous_result = status;
          operation->step = FTUN_ROUTE_ASYNC_RECONCILE;
          operation->kernel.runnable = true;
        } else if (operation->state == FTUN_ROUTE_ASYNC_APPLYING) {
          ftun_route_async_apply_failed(operation, status);
        } else {
          ftun_route_async_cleanup_failed(operation, status);
        }
        work++;
        continue;
      }
      work++;
      if (reply.sequence != operation->kernel.pending_sequence) {
        operation->stale_replies++;
        operation->kernel.runnable = true;
        continue;
      }
      status = ftun_route_async_pending_clear(operation);
      if (status != FTUN_OK) {
        return_status = status;
        break;
      }
      ftun_route_async_reply(operation, &reply);
    }
  }
  operation->running = false;
  if (operation->system_io &&
      (operation->state == FTUN_ROUTE_ASYNC_READY ||
       operation->state == FTUN_ROUTE_ASYNC_FAILED ||
       operation->state == FTUN_ROUTE_ASYNC_CLEANUP_FAILED ||
       operation->state == FTUN_ROUTE_ASYNC_RELEASED)) {
    /* 终态只保留资源责任；迟到 ACK 不应在共享 events 上持续触发 READ。 */
    ftun_status_t status = ftun_route_native_unwatch(operation);
    if (return_status == FTUN_OK) return_status = status;
  }
  *out_work = work;
  return return_status;
}

ftun_status_t ftun_platform_route_async_next_deadline(
  const ftun_platform_route_async_t *operation, uint64_t *out_deadline,
  bool *out_present)
{
  if (out_deadline != NULL) *out_deadline = 0u;
  if (out_present != NULL) *out_present = false;
  if (operation == NULL || operation->magic != FTUN_ROUTE_ASYNC_MAGIC ||
      out_deadline == NULL || out_present == NULL) return FTUN_E_INVALID;
  if (operation->state != FTUN_ROUTE_ASYNC_APPLYING &&
      operation->state != FTUN_ROUTE_ASYNC_COMPENSATING &&
      operation->state != FTUN_ROUTE_ASYNC_RELEASING) return FTUN_OK;
  if (operation->request_sent) {
    *out_deadline = operation->pending_deadline_ms;
    *out_present = true;
  } else if (operation->state == FTUN_ROUTE_ASYNC_APPLYING ||
             operation->state == FTUN_ROUTE_ASYNC_COMPENSATING ||
             operation->state == FTUN_ROUTE_ASYNC_RELEASING) {
    *out_deadline = operation->total_deadline_ms;
    *out_present = true;
  }
  return FTUN_OK;
}

ftun_status_t ftun_platform_route_async_get_info(
  const ftun_platform_route_async_t *operation,
  ftun_route_async_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (operation == NULL || operation->magic != FTUN_ROUTE_ASYNC_MAGIC ||
      out == NULL) return FTUN_E_INVALID;
  out->resource_count = operation->resource_count;
  out->active_count = operation->active_count;
  out->state = operation->state;
  out->result = operation->result;
  out->cleanup_result = operation->cleanup_result;
  out->pending_sequence = operation->kernel.pending_sequence;
  out->stale_replies = operation->stale_replies;
  out->timeouts = operation->timeouts;
  out->cleanup_failures = operation->cleanup_failures;
  out->runnable = operation->kernel.runnable;
  out->repairing = operation->repairing;
  out->repair_result = operation->repair_result;
  out->repair_runs = operation->repair_runs;
  out->repairs = operation->repairs;
  out->repair_failures = operation->repair_failures;
  out->strays_removed = operation->strays_removed;
  return FTUN_OK;
}

ftun_status_t ftun_platform_route_async_repair(
  ftun_platform_route_async_t *operation, uint64_t now_ms,
  uint64_t total_deadline_ms)
{
  ftun_status_t status;
  if (operation == NULL || operation->magic != FTUN_ROUTE_ASYNC_MAGIC ||
      total_deadline_ms <= now_ms) return FTUN_E_INVALID;
  if (operation->running || operation->repairing) return FTUN_E_AGAIN;
  if (operation->state != FTUN_ROUTE_ASYNC_READY ||
      operation->release_requested) return FTUN_E_INVALID;
  if (operation->system_io && !operation->watching) {
    status = ftun_route_native_watch(operation);
    if (status != FTUN_OK) return status;
  }
  operation->repairing = true;
  operation->repair_runs++;
  operation->repair_result = FTUN_OK;
  operation->total_deadline_ms = total_deadline_ms;
  operation->state = FTUN_ROUTE_ASYNC_APPLYING;
  operation->step = FTUN_ROUTE_ASYNC_PREFLIGHT;
  operation->cursor = 0u;
  operation->has_current = false;
  operation->kernel.runnable = true;
  return FTUN_OK;
}

ftun_status_t ftun_platform_route_async_release(
  ftun_platform_route_async_t *operation, uint64_t now_ms,
  uint64_t total_deadline_ms)
{
  ftun_status_t status;
  if (operation == NULL || operation->magic != FTUN_ROUTE_ASYNC_MAGIC ||
      total_deadline_ms <= now_ms) return FTUN_E_INVALID;
  if (operation->running) return FTUN_E_AGAIN;
  if (operation->state == FTUN_ROUTE_ASYNC_RELEASED) return FTUN_OK;
  if (operation->system_io && !operation->watching) {
    status = ftun_route_native_watch(operation);
    if (status != FTUN_OK) return status;
  }
  if (operation->state == FTUN_ROUTE_ASYNC_COMPENSATING ||
      operation->state == FTUN_ROUTE_ASYNC_RELEASING ||
      operation->release_requested) {
    if (operation->state != FTUN_ROUTE_ASYNC_CLEANUP_FAILED) return FTUN_E_AGAIN;
  }
  if (operation->retained_add) {
    uint64_t deadline = ftun_route_async_add_deadline(now_ms, operation->step_timeout_ms);
    if (deadline > total_deadline_ms) deadline = total_deadline_ms;
    status = ftun_route_async_timer_start(operation,
      operation->request_sent ? deadline : total_deadline_ms);
    if (status != FTUN_OK) return status;
    /* active 的暂记只阻止销毁，不构成删除授权。恢复原请求后由结果
     * 决定是否重新取得所有权；失败 ACK 不得进入该资源的撤销路径。 */
    operation->active[operation->cursor] = false;
    operation->active_count--;
    operation->retained_add = false;
    operation->release_requested = true;
    operation->cleanup_result = FTUN_OK;
    operation->total_deadline_ms = total_deadline_ms;
    if (operation->request_sent) operation->pending_deadline_ms = deadline;
    operation->state = FTUN_ROUTE_ASYNC_APPLYING;
    operation->kernel.runnable = true;
    return FTUN_OK;
  }
  /* ADD 发出后须先消费 ACK 或完成 reconcile。直接清除 pending 会丢失
   * 已生效资源，盲目删除又可能误删 CREATE|EXCL 拒绝的外部对象。 */
  if (operation->state == FTUN_ROUTE_ASYNC_APPLYING &&
      operation->has_current &&
      ((operation->request_sent && operation->kernel.pending_kind == FTUN_LINUX_ROUTE_REQUEST_ADD) ||
       operation->step == FTUN_ROUTE_ASYNC_RECONCILE)) {
    operation->release_requested = true;
    operation->result = FTUN_E_CANCELLED;
    operation->total_deadline_ms = total_deadline_ms;
    if (operation->request_sent && operation->pending_deadline_ms > total_deadline_ms) {
      operation->pending_deadline_ms = total_deadline_ms;
      return ftun_route_async_timer_start(operation, total_deadline_ms);
    }
    return FTUN_OK;
  }
  status = ftun_route_async_pending_clear(operation);
  if (status != FTUN_OK) return status;
  operation->total_deadline_ms = total_deadline_ms;
  operation->cleanup_result = FTUN_OK;
  operation->release_requested = true;
  if (operation->state == FTUN_ROUTE_ASYNC_FAILED &&
      operation->active_count == 0u) {
    operation->state = FTUN_ROUTE_ASYNC_RELEASED;
    operation->kernel.runnable = false;
    return FTUN_OK;
  }
  ftun_route_async_begin_cleanup(operation,
    operation->state == FTUN_ROUTE_ASYNC_APPLYING ?
      FTUN_E_CANCELLED : operation->result, true);
  return FTUN_OK;
}

ftun_status_t ftun_platform_route_async_destroy(
  ftun_platform_route_async_t **operation)
{
  ftun_platform_route_async_t *owned;
  ftun_status_t status;
  if (operation == NULL) return FTUN_E_INVALID;
  owned = *operation;
  if (owned == NULL) return FTUN_OK;
  if (owned->magic != FTUN_ROUTE_ASYNC_MAGIC) return FTUN_E_INVALID;
  if (owned->running || owned->active_count != 0u ||
      (owned->state != FTUN_ROUTE_ASYNC_FAILED &&
       owned->state != FTUN_ROUTE_ASYNC_RELEASED)) return FTUN_E_AGAIN;
  status = ftun_route_async_timer_cancel(owned);
  if (status != FTUN_OK) return status;
  if (owned->system_io) {
    ftun_handle_t descriptor;
    status = ftun_route_native_unwatch(owned);
    if (status != FTUN_OK) return status;
    descriptor = owned->kernel.descriptor;
    owned->kernel.descriptor = -1;
    if (descriptor >= 0 && ftun_platform_route_close(descriptor) != FTUN_OK) return FTUN_E_IO;
    /* 关闭描述符即释放 flock。 */
    if (owned->lock_descriptor >= 0) {
      descriptor = owned->lock_descriptor;
      owned->lock_descriptor = -1;
      if (ftun_platform_route_close(descriptor) != FTUN_OK) return FTUN_E_IO;
    }
  }
  owned->magic = 0u;
  memset(&owned->io, 0, sizeof(owned->io));
  free(owned);
  *operation = NULL;
  return FTUN_OK;
}
