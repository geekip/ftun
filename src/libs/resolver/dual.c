#include "libs/resolver/dual.h"
#include "core/operation.h"
#include "util/endpoint.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

typedef struct dual dual_t;
typedef struct {
  dual_t *owner;
  ftun_operation_t *operation;
  ftun_status_t status;
  size_t count;
  ftun_endpoint_t addresses[FTUN_SYSTEM_RESOLVER_MAX_RESULTS];
} answer_t;
struct dual {
  ftun_reservation_t reservation;
  ftun_operation_t *operation;
  ftun_operation_token_t token;
  ftun_system_resolve_completion_fn completion;
  void *user;
  char domain[FTUN_SYSTEM_RESOLVER_MAX_DOMAIN_BYTES + 1u];
  size_t domain_length;
  answer_t answers[2];
  bool starting, cancelling;
};
static void finish(dual_t *dual)
{
  ftun_status_t status = FTUN_OK;
  size_t count = dual->answers[0].count + dual->answers[1].count;
  if (dual->starting || dual->answers[0].operation != NULL || dual->answers[1].operation != NULL) return;
  if (dual->cancelling) status = FTUN_E_CANCELLED;
  else for (size_t i = 0u; i < 2u; i++) {
    if (dual->answers[i].status != FTUN_OK && dual->answers[i].status != FTUN_E_RESOLVE) {
      status = dual->answers[i].status;
      break;
    }
  }
  if (status == FTUN_OK && count == 0u) status = FTUN_E_RESOLVE;
  if (status == FTUN_OK && count > FTUN_SYSTEM_RESOLVER_MAX_RESULTS) status = FTUN_E_LIMIT;
  ftun_status_t completed = ftun_operation_complete(dual->token, (ftun_error_t){status, 0u, 0});
  assert(completed == FTUN_OK);
  (void)completed;
}
static void answered(ftun_operation_t *operation, ftun_error_t error,
  const ftun_system_resolve_result_t *result, void *context)
{
  answer_t *answer = context;
  dual_t *dual = answer->owner;
  (void)operation;
  answer->operation = NULL;
  answer->status = error.status;
  if (error.status == FTUN_OK) {
    if (result == NULL || result->addresses == NULL || result->address_count == 0u ||
        result->domain.data == NULL || result->address_count > FTUN_SYSTEM_RESOLVER_MAX_RESULTS ||
        result->domain.length != dual->domain_length ||
        memcmp(result->domain.data, dual->domain, dual->domain_length) != 0) answer->status = FTUN_E_STATE_CORRUPT;
    else {
      answer->count = result->address_count;
      memcpy(answer->addresses, result->addresses, answer->count * sizeof(*answer->addresses));
    }
  }
  finish(dual);
}
static ftun_status_t cancel(void *context)
{
  dual_t *dual = context;
  ftun_status_t status = FTUN_OK;
  bool pending = false;
  dual->cancelling = true;
  for (size_t i = 0u; i < 2u; i++) {
    if (dual->answers[i].operation != NULL) {
      ftun_status_t child = ftun_operation_cancel(dual->answers[i].operation);
      pending = true;
      if (child != FTUN_OK && child != FTUN_E_AGAIN && child != FTUN_E_STALE && status == FTUN_OK) status = child;
    }
  }
  return status != FTUN_OK ? status : pending ? FTUN_E_AGAIN : FTUN_OK;
}
static void completed(ftun_operation_t *operation, ftun_error_t error, void *context)
{
  dual_t *dual = context;
  ftun_endpoint_t addresses[FTUN_SYSTEM_RESOLVER_MAX_RESULTS];
  ftun_system_resolve_result_t result = {{dual->domain, dual->domain_length}, addresses, 0u};
  ftun_reservation_t reservation = dual->reservation;
  if (error.status == FTUN_OK) for (size_t i = 0u; i < 2u; i++) {
    memcpy(addresses + result.address_count, dual->answers[i].addresses,
      dual->answers[i].count * sizeof(*addresses));
    result.address_count += dual->answers[i].count;
  }
  dual->completion(operation, error, &result, dual->user);
  free(dual);
  ftun_reservation_release(&reservation);
}
ftun_status_t ftun_resolver_dual_start(const ftun_resolver_provider_ops_t *ops,
  void *context, ftun_core_t *core, const ftun_resolver_provider_request_t *request,
  ftun_operation_t **out)
{
  ftun_resolver_provider_request_t delegated = *request;
  ftun_reservation_t reservation = {0};
  dual_t *dual;
  ftun_status_t status = ftun_budget_reserve(request->system.budget, sizeof(*dual), &reservation);
  *out = NULL;
  if (status != FTUN_OK) return status;
  dual = calloc(1u, sizeof(*dual));
  if (dual == NULL) { ftun_reservation_release(&reservation); return FTUN_E_LIMIT; }
  dual->reservation = reservation;
  dual->completion = request->system.completion;
  dual->user = request->system.user;
  dual->domain_length = request->system.domain.length;
  memcpy(dual->domain, request->system.domain.data, dual->domain_length);
  status = ftun_operation_accept(request->operations, completed, dual, &dual->operation, &dual->token);
  if (status != FTUN_OK) { free(dual); ftun_reservation_release(&reservation); return status; }
  status = ftun_operation_set_cancel_hook(dual->operation, cancel, dual);
  assert(status == FTUN_OK);
  dual->starting = true;
  delegated.system.ipv6 = false;
  delegated.system.domain = (ftun_string_t){dual->domain, dual->domain_length};
  delegated.system.completion = answered;
  for (size_t i = 0u; i < 2u; i++) {
    answer_t *answer = &dual->answers[i];
    answer->owner = dual;
    delegated.system.query_type = i == 0u ? 1u : 28u;
    delegated.system.user = answer;
    answer->status = ops->start(context, core, &delegated, &answer->operation);
  }
  dual->starting = false;
  finish(dual);
  *out = dual->operation;
  return FTUN_OK;
}
