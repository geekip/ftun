#include "util/endpoint.h"
#include "dns/server.h"

#include "core/context.h"
#include "platform/clock.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define FTUN_DNS_SERVER_STAGE_ADMISSION 1u
#define FTUN_DNS_SERVER_STAGE_TRANSPORT 2u
#define FTUN_DNS_SERVER_STAGE_RESPONSE 3u
#define FTUN_DNS_SERVER_STAGE_TIMEOUT 4u
/* 刚恢复的上游地址只给这么长的试探期限（与剩余期限的一半取小）。 */
#define FTUN_DNS_SERVER_PROBE_MAX_MS 1000u

struct ftun_dns_server {
  ftun_budget_t *budget;
  ftun_operation_queue_t *operations;
  ftun_endpoint_t upstream;
  ftun_upstream_set_t *upstream_set;
  uint32_t outbound_id;
  uint64_t fingerprint;
  ftun_dns_transport_t transport;
  size_t max_response_bytes;
  ftun_dns_query_transport_t query_transport;
  ftun_dns_cache_t *cache;
  ftun_dns_server_now_fn now;
  void *now_user;
  ftun_reservation_t reservation;
  size_t inflight;
  int tcp_fallback;
  int fakeip;
};

typedef struct {
  ftun_dns_server_t *server;
  ftun_operation_t *operation;
  ftun_operation_token_t completion_token;
  ftun_reservation_t reservation;
  ftun_dns_query_t query;
  ftun_dns_query_completion_fn completion;
  void *completion_user;
  void *transport_request;
  uint8_t *response;
  size_t response_length;
  ftun_dns_transport_t current_transport;
  ftun_dns_transport_binding_t binding;
  bool selected;
  bool upstream_chosen;
  bool failed_over;
  bool probing;
  size_t upstream_index;
  /* 本次尝试的期限；有备用地址时只占剩余期限的一部分，留出换地址的时间。 */
  uint64_t attempt_deadline_ms;
  bool cancelling;
  bool completed_during_cancel;
} ftun_dns_exchange_context_t;

static ftun_error_t ftun_dns_server_error(ftun_status_t status,
                                          uint32_t stage)
{
  return (ftun_error_t){status, stage, 0};
}

static ftun_status_t ftun_dns_server_default_now(void *user, uint64_t *out)
{
  (void)user;
  return ftun_monotonic_now(out);
}

static int ftun_dns_server_endpoint_valid(const ftun_endpoint_t *endpoint)
{
  return endpoint != NULL && ftun_endpoint_is_ip(endpoint) &&
         endpoint->port != 0u && endpoint->domain.length == 0u;
}

static uint8_t ftun_dns_server_fold(uint8_t value)
{
  return value >= (uint8_t)'A' && value <= (uint8_t)'Z' ?
    (uint8_t)(value + ((uint8_t)'a' - (uint8_t)'A')) : value;
}

static int ftun_dns_server_name_equal(ftun_dns_name_t left,
                                      ftun_dns_name_t right)
{
  size_t index;
  if (left.length != right.length) return 0;
  for (index = 0u; index < left.length; index++) {
    if (ftun_dns_server_fold(left.data[index]) !=
        ftun_dns_server_fold(right.data[index])) return 0;
  }
  return 1;
}

static ftun_status_t ftun_dns_server_query_validate(
  ftun_budget_t *budget, const ftun_dns_query_t *query)
{
  ftun_dns_message_t *message = NULL;
  ftun_status_t status;
  if (query == NULL || query->completion == NULL ||
      query->resolution_mode != 1u || query->deadline_ms == 0u ||
      query->wire.data == NULL || query->wire.length < FTUN_DNS_HEADER_BYTES ||
      query->wire.length > FTUN_DNS_MAX_MESSAGE_BYTES) return FTUN_E_INVALID;
  status = ftun_dns_message_parse_with_budget(budget, query->wire, &message);
  if (status != FTUN_OK) return status;
  if ((message->flags & 0x8000u) != 0u || message->id != query->id ||
      message->question.type != query->question.type ||
      message->question.class_code != query->question.class_code ||
      !ftun_dns_server_name_equal(message->question.name,
                                  query->question.name)) {
    status = FTUN_E_PROTOCOL;
  }
  ftun_dns_message_release(&message);
  return status;
}

static ftun_status_t ftun_dns_server_finish(
  ftun_dns_exchange_context_t *context, ftun_status_t status,
  uint32_t stage)
{
  return ftun_operation_complete_deferred(context->completion_token,
                                  ftun_dns_server_error(status, stage));
}

static void ftun_dns_server_operation_completed(ftun_operation_t *operation,
                                                ftun_error_t error,
                                                void *user)
{
  ftun_dns_exchange_context_t *context =
    (ftun_dns_exchange_context_t *)user;
  ftun_dns_server_t *server = context->server;
  ftun_reservation_t reservation = context->reservation;
  ftun_bytes_t response = {NULL, 0u};
  if (error.status == FTUN_OK) {
    response.data = context->response;
    response.length = context->response_length;
  }
  context->operation = NULL;
  context->completion(operation, error, response, context->completion_user);
  if (server->inflight != 0u) server->inflight--;
  memset(context, 0, sizeof(*context));
  free(context);
  ftun_reservation_release(&reservation);
}

static ftun_status_t ftun_dns_server_cancel(void *user)
{
  ftun_dns_exchange_context_t *context =
    (ftun_dns_exchange_context_t *)user;
  void *request;
  ftun_status_t status;
  if (context == NULL) return FTUN_E_INVALID;
  if (context->transport_request == NULL) return FTUN_OK;
  request = context->transport_request;
  context->cancelling = true;
  context->completed_during_cancel = false;
  /* 取消可以同步交付原请求结果；不要把旧句柄的清空写进回调中新建的
   * TCP fallback 请求。新请求尚在途时取消未静默，留给 owner 后续重试。 */
  status = context->server->query_transport.cancel(
    context->server->query_transport.context, &request);
  context->cancelling = false;
  if (!context->completed_during_cancel) context->transport_request = request;
  else if (context->transport_request != NULL && status == FTUN_OK) {
    status = FTUN_E_AGAIN;
  }
  return status;
}

static void ftun_dns_server_transport_completed(
  void *user, ftun_status_t status, ftun_dns_transport_t transport,
  const ftun_endpoint_t *source, ftun_bytes_t response);

static ftun_status_t ftun_dns_server_submit(
  ftun_dns_exchange_context_t *context, ftun_dns_transport_t transport)
{
  ftun_dns_server_t *server = context->server;
  uint64_t now;
  ftun_status_t status = server->now(server->now_user, &now);
  if (status != FTUN_OK) return ftun_dns_server_finish(context, status, FTUN_DNS_SERVER_STAGE_TRANSPORT);
  if (now >= context->query.deadline_ms) {
    return ftun_dns_server_finish(context, FTUN_E_TIMEOUT,
                                  FTUN_DNS_SERVER_STAGE_TIMEOUT);
  }
  if (!context->selected) {
    status = server->query_transport.select(server->query_transport.context,
      server->outbound_id, &context->binding);
    if (status != FTUN_OK) {
      return ftun_dns_server_finish(context, status,
                                    FTUN_DNS_SERVER_STAGE_TRANSPORT);
    }
    if (context->binding.scope == NULL ||
        context->binding.root_id != server->outbound_id) {
      return ftun_dns_server_finish(context, FTUN_E_STATE_CORRUPT,
                                    FTUN_DNS_SERVER_STAGE_TRANSPORT);
    }
    context->selected = true;
  }
  if (!context->upstream_chosen) {
    context->upstream_chosen = true;
    context->attempt_deadline_ms = context->query.deadline_ms;
    if (server->upstream_set != NULL) {
      bool recovering = false;
      size_t alternative = 0u;
      uint64_t remaining = context->query.deadline_ms - now;
      status = ftun_upstream_set_pick(server->upstream_set, SIZE_MAX,
        &context->upstream_index, &recovering);
      if (status != FTUN_OK) {
        /* 所有地址都在退避中：立即失败，不阻塞。 */
        return ftun_dns_server_finish(context, status,
                                      FTUN_DNS_SERVER_STAGE_TRANSPORT);
      }
      context->query.upstream =
        *ftun_upstream_set_endpoint(server->upstream_set, context->upstream_index);
      /* 有备用地址时第一次尝试只用剩余期限的一半；刚恢复的地址最多 1 秒，
       * 这次试探失败改发备用地址，不占用“换一个地址”的限额。 */
      if (ftun_upstream_set_pick(server->upstream_set, context->upstream_index,
                                 &alternative, &(bool){false}) == FTUN_OK) {
        uint64_t share = remaining / 2u;
        if (recovering && share > FTUN_DNS_SERVER_PROBE_MAX_MS) {
          share = FTUN_DNS_SERVER_PROBE_MAX_MS;
        }
        context->attempt_deadline_ms = now + share;
        context->probing = recovering;
      }
    }
  }
  context->query.transport = transport;
  context->current_transport = transport;
  status = server->query_transport.submit(
    server->query_transport.context, &context->binding,
    context->query.policy_fingerprint, context->query.server_fingerprint,
    &context->query.upstream, transport, context->query.wire,
    context->attempt_deadline_ms,
    ftun_dns_server_transport_completed, context,
    &context->transport_request);
  if (status != FTUN_OK || context->transport_request == NULL) {
    context->transport_request = NULL;
    return ftun_dns_server_finish(context,
      status == FTUN_OK ? FTUN_E_STATE_CORRUPT : status,
      FTUN_DNS_SERVER_STAGE_TRANSPORT);
  }
  return FTUN_OK;
}

/* 当前地址不健康（网络类失败，或应答无法解析/对不上）：记入集合，并在剩余期限内
 * 换下一个地址重新提交。上游自己返回的 SERVFAIL/REFUSED 是合法应答，不走这里。
 * 换成功返回 true；没有集合、没有备用地址或限额用完返回 false，由调用方如实失败。 */
static bool ftun_dns_server_failover(ftun_dns_exchange_context_t *context)
{
  ftun_dns_server_t *server = context->server;
  size_t next = 0u;
  if (server->upstream_set == NULL) return false;
  uint64_t now;
  ftun_status_t status = server->now(server->now_user, &now);
  if (status == FTUN_OK) status = ftun_upstream_set_report_failure(server->upstream_set, context->upstream_index);
  if (status != FTUN_OK) {
    (void)ftun_dns_server_finish(context, status, FTUN_DNS_SERVER_STAGE_TRANSPORT);
    return true;
  }
  if ((!context->probing && context->failed_over) ||
      now >= context->query.deadline_ms ||
      ftun_upstream_set_pick(server->upstream_set, context->upstream_index,
                             &next, &(bool){false}) != FTUN_OK) return false;
  if (!context->probing) context->failed_over = true;
  context->probing = false;
  context->upstream_index = next;
  context->query.upstream = *ftun_upstream_set_endpoint(server->upstream_set, next);
  context->attempt_deadline_ms = context->query.deadline_ms;
  (void)ftun_dns_server_submit(context, context->current_transport);
  return true;
}

static void ftun_dns_server_transport_completed(
  void *user, ftun_status_t status, ftun_dns_transport_t transport,
  const ftun_endpoint_t *source, ftun_bytes_t response)
{
  ftun_dns_exchange_context_t *context =
    (ftun_dns_exchange_context_t *)user;
  ftun_dns_server_t *server;
  ftun_dns_message_t *message = NULL;
  bool matches = false;
  uint64_t now;
  assert(context != NULL && context->server != NULL);
  server = context->server;
  if (context->cancelling) context->completed_during_cancel = true;
  context->transport_request = NULL;
  if (status != FTUN_OK) {
    /* 网络类失败（超时、IO）：记入健康状态并换地址。取消不算失败。 */
    if (!context->cancelling &&
        (status == FTUN_E_TIMEOUT || status == FTUN_E_IO) &&
        ftun_dns_server_failover(context)) return;
    (void)ftun_dns_server_finish(context, status,
                                 FTUN_DNS_SERVER_STAGE_TRANSPORT);
    return;
  }
  status = server->query_transport.response_now == NULL
    ? server->now(server->now_user, &now)
    : server->query_transport.response_now(server->query_transport.context, &now);
  if (status != FTUN_OK) {
    (void)ftun_dns_server_finish(context, status, FTUN_DNS_SERVER_STAGE_RESPONSE);
    return;
  }
  if (now >= context->query.deadline_ms) {
    (void)ftun_dns_server_finish(context, FTUN_E_TIMEOUT,
                                 FTUN_DNS_SERVER_STAGE_TIMEOUT);
    return;
  }
  if (transport != context->current_transport ||
      response.data == NULL || response.length > server->max_response_bytes) {
    if (ftun_dns_server_failover(context)) return;
    (void)ftun_dns_server_finish(context, FTUN_E_PROTOCOL,
                                 FTUN_DNS_SERVER_STAGE_RESPONSE);
    return;
  }
  status = ftun_dns_message_parse_with_budget(server->budget, response, &message);
  if (status == FTUN_OK) {
    status = ftun_dns_message_matches(message, &context->query, transport,
                                      source, &matches);
  }
  if (status != FTUN_OK || !matches) {
    ftun_dns_message_release(&message);
    /* 应答无法解析或与查询对不上：按上游不健康处理。解析失败的原因可能是畸形的
     * 计数或标签（解析器对它们返回 LIMIT/PROTOCOL），无法与本地预算不足可靠区分；
     * 代价只是该地址进入一次退避，每次查询最多换一个地址。 */
    if (ftun_dns_server_failover(context)) return;
    (void)ftun_dns_server_finish(context,
      status == FTUN_OK ? FTUN_E_PROTOCOL : status,
      FTUN_DNS_SERVER_STAGE_RESPONSE);
    return;
  }
  if ((message->flags & 0x0200u) != 0u && transport == FTUN_DNS_TRANSPORT_UDP) {
    ftun_dns_message_release(&message);
    if (!server->tcp_fallback) {
      (void)ftun_dns_server_finish(context, FTUN_E_UNSUPPORTED,
                                   FTUN_DNS_SERVER_STAGE_RESPONSE);
      return;
    }
    /* 同一地址上的 TCP 重试不受“留出换地址时间”的缩短期限限制。 */
    context->attempt_deadline_ms = context->query.deadline_ms;
    (void)ftun_dns_server_submit(context, FTUN_DNS_TRANSPORT_TCP);
    return;
  }
  ftun_dns_message_release(&message);
  memcpy(context->response, response.data, response.length);
  context->response_length = response.length;
  if (server->cache != NULL) {
    (void)ftun_dns_cache_store(server->cache, &context->query,
      (ftun_bytes_t){context->response, context->response_length});
  }
  (void)ftun_dns_server_finish(context, FTUN_OK,
                               FTUN_DNS_SERVER_STAGE_RESPONSE);
}

ftun_status_t ftun_dns_server_create(const ftun_dns_server_options_t *options,
                                     ftun_dns_server_t **out)
{
  ftun_dns_server_t *server;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (options == NULL || options->budget == NULL ||
      options->operations == NULL || out == NULL ||
      !ftun_dns_server_endpoint_valid(&options->upstream) ||
      (options->transport != FTUN_DNS_TRANSPORT_UDP &&
       options->transport != FTUN_DNS_TRANSPORT_TCP) ||
      options->max_response_bytes < FTUN_DNS_HEADER_BYTES ||
      options->max_response_bytes > FTUN_DNS_MAX_MESSAGE_BYTES ||
      options->query_transport.select == NULL ||
      options->query_transport.submit == NULL ||
      options->query_transport.cancel == NULL) return FTUN_E_INVALID;
  status = ftun_budget_reserve(options->budget, sizeof(*server), &reservation);
  if (status != FTUN_OK) return status;
  server = (ftun_dns_server_t *)calloc(1u, sizeof(*server));
  if (server == NULL) {
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  server->budget = options->budget;
  server->operations = options->operations;
  server->upstream = options->upstream;
  server->upstream_set = options->upstream_set;
  server->outbound_id = options->outbound_id;
  server->fingerprint = options->fingerprint;
  server->transport = options->transport;
  server->tcp_fallback = options->tcp_fallback ? 1 : 0;
  server->fakeip = options->fakeip ? 1 : 0;
  server->max_response_bytes = options->max_response_bytes;
  server->query_transport = options->query_transport;
  server->cache = options->cache;
  server->now = options->now == NULL ? ftun_dns_server_default_now : options->now;
  server->now_user = options->now_user;
  server->reservation = reservation;
  *out = server;
  return FTUN_OK;
}

ftun_status_t ftun_dns_server_get_info(const ftun_dns_server_t *server,
                                       ftun_dns_server_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (server == NULL || out == NULL) return FTUN_E_INVALID;
  out->outbound_id = server->outbound_id;
  out->fingerprint = server->fingerprint;
  out->inflight = server->inflight;
  out->transport = server->transport;
  out->tcp_fallback = server->tcp_fallback != 0;
  out->fakeip = server->fakeip != 0;
  return FTUN_OK;
}

ftun_status_t ftun_dns_exchange(ftun_core_t *core,
                                const ftun_dns_server_t *server_const,
                                const ftun_dns_query_t *query,
                                ftun_operation_t **out)
{
  ftun_dns_server_t *server = (ftun_dns_server_t *)server_const;
  ftun_dns_exchange_context_t *context;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_budget_t *core_budget = NULL;
  ftun_dns_answer_t *cached = NULL;
  uint8_t *cursor;
  size_t bytes;
  size_t response_capacity;
  ftun_status_t cache_status = FTUN_E_EOF;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (core == NULL || server == NULL || query == NULL || out == NULL ||
      ftun_core_context_budget(core, &core_budget) != FTUN_OK) {
    return FTUN_E_INVALID;
  }
  (void)core_budget;
  status = ftun_dns_server_query_validate(server->budget, query);
  if (status != FTUN_OK) return status;
  uint64_t now;
  status = server->now(server->now_user, &now);
  if (status != FTUN_OK) return status;
  if (now >= query->deadline_ms) {
    return FTUN_E_TIMEOUT;
  }
  if (server->cache != NULL) {
    cache_status = ftun_dns_cache_lookup(server->cache, query, &cached);
  }
  if (cache_status == FTUN_OK && cached == NULL) {
    cache_status = FTUN_E_STATE_CORRUPT;
  }
  response_capacity = cache_status == FTUN_OK &&
    cached->wire_length <= server->max_response_bytes
    ? cached->wire_length
    : (cache_status == FTUN_E_EOF ? server->max_response_bytes : 0u);
  if (sizeof(*context) > SIZE_MAX - query->wire.length ||
      sizeof(*context) + query->wire.length > SIZE_MAX -
        query->question.name.length ||
      sizeof(*context) + query->wire.length + query->question.name.length >
        SIZE_MAX - response_capacity) {
    ftun_dns_answer_release(&cached);
    return FTUN_E_LIMIT;
  }
  bytes = sizeof(*context) + query->wire.length + query->question.name.length +
          response_capacity;
  status = ftun_budget_reserve(server->budget, bytes, &reservation);
  if (status != FTUN_OK) {
    ftun_dns_answer_release(&cached);
    return status;
  }
  context = (ftun_dns_exchange_context_t *)calloc(1u, bytes);
  if (context == NULL) {
    ftun_dns_answer_release(&cached);
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  context->server = server;
  context->reservation = reservation;
  context->query = *query;
  context->completion = query->completion;
  context->completion_user = query->completion_user;
  cursor = (uint8_t *)(context + 1);
  memcpy(cursor, query->wire.data, query->wire.length);
  context->query.wire.data = cursor;
  cursor += query->wire.length;
  memcpy(cursor, query->question.name.data, query->question.name.length);
  context->query.question.name.data = cursor;
  cursor += query->question.name.length;
  context->response = cursor;
  context->query.upstream = server->upstream;
  context->query.server_fingerprint = server->fingerprint;
  context->query.outbound_id = server->outbound_id;
  status = ftun_operation_accept(server->operations,
    ftun_dns_server_operation_completed, context, &context->operation,
    &context->completion_token);
  if (status != FTUN_OK) goto fail;
  status = ftun_operation_set_cancel_hook(context->operation,
                                          ftun_dns_server_cancel, context);
  if (status != FTUN_OK) {
    (void)ftun_operation_reject(&context->operation);
    goto fail;
  }
  server->inflight++;
  *out = context->operation;
  if (cache_status == FTUN_OK) {
    if (cached->wire_length <= server->max_response_bytes) {
      memcpy(context->response, cached->wire, cached->wire_length);
      context->response_length = cached->wire_length;
      ftun_dns_answer_release(&cached);
      return ftun_dns_server_finish(context, FTUN_OK,
                                    FTUN_DNS_SERVER_STAGE_RESPONSE);
    }
    ftun_dns_answer_release(&cached);
    return ftun_dns_server_finish(context, FTUN_E_LIMIT,
                                  FTUN_DNS_SERVER_STAGE_RESPONSE);
  }
  if (cache_status != FTUN_E_EOF) {
    return ftun_dns_server_finish(context, cache_status,
                                  FTUN_DNS_SERVER_STAGE_TRANSPORT);
  }
  return ftun_dns_server_submit(context, server->transport);

fail:
  ftun_dns_answer_release(&cached);
  free(context);
  ftun_reservation_release(&reservation);
  return status;
}

ftun_status_t ftun_dns_server_destroy(ftun_dns_server_t **server)
{
  ftun_dns_server_t *owned;
  ftun_reservation_t reservation;
  if (server == NULL) return FTUN_E_INVALID;
  owned = *server;
  if (owned == NULL) return FTUN_OK;
  if (owned->inflight != 0u) return FTUN_E_AGAIN;
  reservation = owned->reservation;
  free(owned);
  *server = NULL;
  ftun_reservation_release(&reservation);
  return FTUN_OK;
}
