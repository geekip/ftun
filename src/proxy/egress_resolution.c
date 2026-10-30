#include "proxy/egress_internal.h"
#include "core/recovery.h"
#include "libs/resolver/dual.h"
#include "platform/clock.h"
#include "platform/sysresolve.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct ftun_proxy_resolution {
  ftun_reservation_t reservation;
  ftun_proxy_resolution_job_t *job;
  ftun_recovery_scheduler_t *recovery;
  ftun_recovery_id_t recovery_id;
  ftun_error_t error;
  uint64_t expires_at_ms;
  uint32_t mark;
  char interface_name[FTUN_SOCKET_INTERFACE_BYTES];
  size_t interface_length;
};

struct ftun_proxy_resolution_job {
  ftun_reservation_t reservation;
  const ftun_egress_provider_t *provider;
  ftun_proxy_egress_node_t *node;
  ftun_core_t *core;
  ftun_dial_request_t request;
  ftun_operation_t *operation;
  ftun_proxy_resolution_waiter_t *head;
  bool recovering;
  ftun_status_t cancelled;
  ftun_status_t start_status;
};

static bool same_policy(const ftun_proxy_resolution_t *cache,
  const ftun_dial_request_t *request)
{
  return cache->mark == request->protection.mark &&
    cache->interface_length == request->protection.interface_name.length &&
    (cache->interface_length == 0u || memcmp(cache->interface_name,
      request->protection.interface_name.data, cache->interface_length) == 0);
}

bool ftun_proxy_resolution_valid(const ftun_proxy_egress_node_t *node, uint64_t now)
{
  return node->resolved && (node->proxy.server.kind != FTUN_ADDRESS_DOMAIN ||
    (node->resolution != NULL && now < node->resolution->expires_at_ms));
}

bool ftun_proxy_resolution_cached(const ftun_proxy_egress_node_t *node,
  const ftun_dial_request_t *request, uint64_t now, ftun_endpoint_t *out)
{
  if (!ftun_proxy_resolution_valid(node, now) || !same_policy(node->resolution, request)) return false;
  *out = node->endpoint;
  return true;
}

static void remove_waiter(ftun_proxy_resolution_waiter_t *waiter)
{
  ftun_proxy_resolution_job_t *job = waiter->job;
  if (waiter->previous != NULL) waiter->previous->next = waiter->next;
  else job->head = waiter->next;
  if (waiter->next != NULL) waiter->next->previous = waiter->previous;
  waiter->job = NULL;
  waiter->next = waiter->previous = NULL;
}

ftun_status_t ftun_proxy_resolution_cancel(ftun_proxy_resolution_waiter_t *waiter,
  ftun_status_t reason)
{
  ftun_proxy_resolution_job_t *job = waiter->job;
  ftun_status_t status;
  if (job == NULL) return FTUN_OK;
  remove_waiter(waiter);
  if (job->head != NULL || job->operation == NULL) return FTUN_OK;
  job->cancelled = reason;
  status = ftun_operation_cancel(job->operation);
  return status == FTUN_E_AGAIN || status == FTUN_E_STALE ? FTUN_OK : status;
}

static void free_job(ftun_proxy_resolution_job_t *job)
{
  ftun_reservation_t reservation = job->reservation;
  ftun_network_view_t *view = (ftun_network_view_t *)job->request.network_view;
  ftun_network_view_release(&view);
  ftun_egress_release(&job->provider);
  free(job);
  ftun_reservation_release(&reservation);
}

static void resolved(ftun_operation_t *operation, ftun_error_t error,
  const ftun_system_resolve_result_t *result, void *context)
{
  ftun_proxy_resolution_job_t *job = context;
  ftun_proxy_egress_node_t *node = job->node;
  ftun_proxy_resolution_t *cache = node->resolution;
  uint64_t now = 0u;
  ftun_status_t status = ftun_monotonic_now(&now);
  (void)operation;
  job->operation = NULL;
  if (status != FTUN_OK) error.status = status;
  if (job->cancelled != FTUN_OK) error.status = job->cancelled;
  if (error.status == FTUN_OK) {
    assert(result != NULL && result->address_count != 0u);
    node->endpoint = result->addresses[0];
    node->endpoint.port = node->proxy.server.port;
    cache->expires_at_ms = result->expires_at_ms;
    node->resolved = now < cache->expires_at_ms;
  } else {
    node->resolved = false;
    cache->expires_at_ms = 0u;
  }
  cache->error = error;
  status = FTUN_OK;
  if (job->recovering) status = ftun_recovery_attempt_finish(cache->recovery,
    cache->recovery_id, now, job->cancelled == FTUN_E_CANCELLED ? FTUN_OK : error.status,
    error.status == FTUN_E_LIMIT ? FTUN_RECOVERY_FAULT_RESOURCE : FTUN_RECOVERY_FAULT_NETWORK);
  else if (error.status != FTUN_OK && job->cancelled != FTUN_E_CANCELLED) status = ftun_recovery_report_failure(
    cache->recovery, cache->recovery_id, now,
    error.status == FTUN_E_LIMIT ? FTUN_RECOVERY_FAULT_RESOURCE : FTUN_RECOVERY_FAULT_NETWORK);
  assert(status == FTUN_OK);
  (void)status;
  cache->job = NULL;
  while (job->head != NULL) {
    ftun_proxy_resolution_waiter_t *waiter = job->head;
    remove_waiter(waiter);
    waiter->completion(waiter->user, error, &node->endpoint);
  }
  free_job(job);
}

static ftun_status_t bootstrap_start(void *context, ftun_core_t *core,
  const ftun_resolver_provider_request_t *request, ftun_operation_t **out)
{
  ftun_bootstrap_request_t query = {0};
  (void)context;
  query.loop = request->loop;
  query.operations = request->operations;
  query.budget = request->system.budget;
  query.domain = request->system.domain;
  query.servers = request->servers;
  query.server_count = request->server_count;
  query.network_view = request->network_view;
  query.network_generation = request->network_generation;
  query.protection = request->system.protection;
  query.deadline_ms = request->system.deadline_ms;
  query.query_id = request->query_id;
  query.query_type = request->system.query_type;
  query.completion = request->system.completion;
  query.user = request->system.user;
  return ftun_bootstrap_resolve(core, &query, out);
}

static ftun_status_t start_job(ftun_proxy_resolution_job_t *job)
{
  const ftun_proxy_egress_t *plan = job->provider->context;
  ftun_resolver_provider_request_t request = {0};
  ftun_endpoint_t server;
  ftun_status_t status;
  if (plan->bootstrap.bootstrap_count != 0u) server = plan->bootstrap.bootstrap[0];
  else {
    ftun_reservation_t descriptor = {0};
    status = ftun_budget_reserve_resources(plan->reservation.budget,
      (ftun_budget_resources_t){0u, 1u, 0u}, &descriptor);
    if (status == FTUN_OK) status = ftun_system_nameserver(&server);
    ftun_reservation_release(&descriptor);
    if (status != FTUN_OK) return status;
  }
  request.loop = job->request.loop;
  request.operations = job->request.operations;
  request.system.budget = plan->reservation.budget;
  request.system.domain = job->node->proxy.server.domain;
  request.system.protection = job->request.protection;
  request.system.deadline_ms = job->request.deadline_ms;
  request.system.completion = resolved;
  request.system.user = job;
  request.network_view = job->request.network_view;
  request.network_generation = job->request.network_generation;
  request.servers = &server;
  request.server_count = 1u;
  request.query_id = (uint16_t)plan->generation;
  if (plan->bootstrap.ipv6) {
    const ftun_resolver_provider_ops_t ops = {bootstrap_start, NULL, NULL, NULL, NULL, NULL};
    return ftun_resolver_dual_start(&ops, NULL, job->core, &request, &job->operation);
  }
  return bootstrap_start(NULL, job->core, &request, &job->operation);
}

static ftun_status_t retry(void *context, ftun_recovery_id_t id)
{
  ftun_proxy_resolution_t *cache = context;
  (void)id;
  assert(cache->job != NULL);
  cache->job->recovering = true;
  cache->job->start_status = start_job(cache->job);
  return cache->job->start_status;
}

static ftun_status_t create_cache(ftun_proxy_egress_t *plan,
  ftun_proxy_egress_node_t *node, uint64_t now)
{
  ftun_proxy_resolution_t *cache;
  ftun_reservation_t reservation = {0};
  ftun_recovery_policy_t policy = {1000u, 30000u, 60000u, 200u, 60000u, plan->generation + (uint64_t)(node - plan->nodes) + 1u};
  ftun_recovery_spec_t spec = {0};
  ftun_status_t status = ftun_budget_reserve(plan->reservation.budget, sizeof(*cache), &reservation);
  if (status != FTUN_OK) return status;
  cache = calloc(1u, sizeof(*cache));
  if (cache == NULL) { ftun_reservation_release(&reservation); return FTUN_E_LIMIT; }
  cache->reservation = reservation;
  status = ftun_recovery_scheduler_create(plan->reservation.budget, 1u, &policy, &cache->recovery);
  spec.kind = 1u;
  spec.attempt = retry;
  spec.user = cache;
  if (status == FTUN_OK) status = ftun_recovery_entity_register(cache->recovery, &spec, now, &cache->recovery_id);
  if (status != FTUN_OK) { ftun_proxy_resolution_destroy(cache); return status; }
  node->resolution = cache;
  return FTUN_OK;
}

void ftun_proxy_resolution_destroy(ftun_proxy_resolution_t *cache)
{
  if (cache == NULL) return;
  assert(cache->job == NULL);
  ftun_status_t status = ftun_recovery_scheduler_destroy(&cache->recovery);
  assert(status == FTUN_OK);
  (void)status;
  ftun_reservation_t reservation = cache->reservation;
  free(cache);
  ftun_reservation_release(&reservation);
}

ftun_status_t ftun_proxy_resolution_start(ftun_proxy_egress_t *plan,
  ftun_proxy_egress_node_t *node, ftun_core_t *core,
  const ftun_dial_request_t *request, uint64_t now,
  ftun_proxy_resolution_waiter_t *waiter)
{
  ftun_proxy_resolution_t *cache = node->resolution;
  ftun_proxy_resolution_job_t *job;
  ftun_recovery_info_t info;
  ftun_reservation_t reservation = {0};
  ftun_status_t status;
  if (cache == NULL) {
    status = create_cache(plan, node, now);
    if (status != FTUN_OK) return status;
    cache = node->resolution;
  }
  job = cache->job;
  if (job != NULL) {
    /* 不同owner循环/队列或View的在途请求不共享解析的网络授权。 */
    if (job->cancelled != FTUN_OK || !same_policy(cache, request) ||
        job->request.loop != request->loop || job->request.operations != request->operations ||
        job->request.network_view != request->network_view ||
        job->request.network_generation != request->network_generation) return FTUN_E_AGAIN;
  } else {
    if (!same_policy(cache, request)) {
      status = ftun_recovery_entity_unregister(cache->recovery, cache->recovery_id);
      ftun_recovery_spec_t spec = {1u, 0u, retry, NULL, cache};
      if (status == FTUN_OK) status = ftun_recovery_entity_register(cache->recovery, &spec, now, &cache->recovery_id);
      assert(status == FTUN_OK);
      (void)status;
      cache->mark = request->protection.mark;
      cache->interface_length = request->protection.interface_name.length;
      if (cache->interface_length != 0u) memcpy(cache->interface_name,
        request->protection.interface_name.data, cache->interface_length);
      node->resolved = false;
    }
    status = ftun_recovery_query(cache->recovery, 0u, &info);
    assert(status == FTUN_OK);
    if (info.state == FTUN_RECOVERY_WAITING && now < info.next_ms) return cache->error.status;
    status = ftun_budget_reserve(plan->reservation.budget, sizeof(*job), &reservation);
    if (status != FTUN_OK) return status;
    job = calloc(1u, sizeof(*job));
    if (job == NULL) { ftun_reservation_release(&reservation); return FTUN_E_LIMIT; }
    job->reservation = reservation;
    job->provider = &plan->provider;
    ftun_egress_retain(job->provider);
    job->node = node;
    job->core = core;
    job->request = *request;
    job->request.budget = plan->reservation.budget;
    job->request.allowed = NULL;
    job->request.allowed_count = 0u;
    job->request.deadline_ms = now > UINT64_MAX - 5000u ? UINT64_MAX : now + 5000u;
    job->request.protection.interface_name.data = cache->interface_name;
    if (request->network_view != NULL) {
      status = ftun_network_view_retain((ftun_network_view_t *)request->network_view);
      if (status != FTUN_OK) {
        job->request.network_view = NULL;
        free_job(job);
        return status;
      }
    }
    cache->job = job;
    node->resolved = false;
    if (info.state == FTUN_RECOVERY_WAITING) {
      size_t work;
      status = ftun_recovery_run(cache->recovery, now, 1u, &work);
      assert(status == FTUN_OK && work == 1u);
      status = job->start_status;
    } else status = start_job(job);
    if (status != FTUN_OK) {
      cache->error = (ftun_error_t){status, 0u, 0};
      if (!job->recovering) {
        ftun_status_t reported = ftun_recovery_report_failure(cache->recovery,
          cache->recovery_id, now, FTUN_RECOVERY_FAULT_RESOURCE);
        assert(reported == FTUN_OK);
        (void)reported;
      }
      cache->job = NULL;
      free_job(job);
      return status;
    }
  }
  waiter->job = job;
  waiter->next = job->head;
  if (job->head != NULL) job->head->previous = waiter;
  job->head = waiter;
  return FTUN_OK;
}
