#ifndef FTUN_TRANSPORT_CARRIER_H
#define FTUN_TRANSPORT_CARRIER_H

#include "internal/contracts.h"
#include "core/budget.h"
#include "core/operation.h"
#include "util/buffer.h"

typedef struct ftun_carrier ftun_carrier_t;

typedef enum {
  FTUN_CARRIER_FLOW_STREAM = 1,
  FTUN_CARRIER_FLOW_DATAGRAM = 2
} ftun_carrier_flow_kind_t;

typedef enum {
  FTUN_CARRIER_SEND_STREAM = 1,
  FTUN_CARRIER_SEND_DATAGRAM = 2,
  FTUN_CARRIER_SEND_CONTROL = 3
} ftun_carrier_send_kind_t;

typedef struct {
  ftun_carrier_t *carrier;
  size_t slot;
  uint64_t generation;
} ftun_carrier_owner_token_t;

typedef struct {
  ftun_carrier_t *carrier;
  size_t slot;
  uint64_t generation;
} ftun_carrier_flow_token_t;

typedef struct {
  ftun_carrier_t *carrier;
  size_t slot;
  uint64_t generation;
  uint64_t fragment_generation;
} ftun_carrier_send_token_t;

typedef struct {
  ftun_budget_t *budget;
  size_t max_owners;
  size_t max_flows;
  size_t max_pending_messages;
  size_t max_pending_bytes;
  size_t control_reserve_messages;
  size_t control_reserve_bytes;
  size_t connection_credit_bytes;
  size_t control_credit_bytes;
  size_t max_work_per_round;
} ftun_carrier_options_t;

typedef struct {
  uint32_t owner_id;
  ftun_operation_queue_t *return_operations;
  size_t max_pending_messages;
  size_t max_pending_bytes;
  /* Called after a remote carrier transition makes a return operation ready.
   * It may only wake/schedule the logical owner and must not dispatch inline. */
  void (*return_ready)(void *user);
  void *return_ready_user;
} ftun_carrier_owner_options_t;

typedef struct {
  uint64_t flow_id;
  ftun_carrier_flow_kind_t kind;
  size_t credit_bytes;
  size_t max_pending_messages;
  size_t max_pending_bytes;
} ftun_carrier_flow_options_t;

typedef struct {
  /* OK transfers the accepted prefix to the backend until complete/cancel.
   * Stream may accept a non-zero prefix. Datagram/control must accept the
   * complete offered frame. AGAIN and other errors retain nothing. */
  ftun_status_t (*send_start)(void *context, ftun_carrier_send_token_t send,
                              ftun_carrier_send_kind_t kind,
                              uint32_t owner_id, uint64_t flow_id,
                              size_t offered, size_t *accepted);
  /* cancel must be bounded and must not re-enter send_complete. */
  ftun_status_t (*send_cancel)(void *context,
                               ftun_carrier_send_token_t send);
  void (*destroy)(void *context);
  void *context;
} ftun_carrier_backend_t;

typedef struct {
  size_t max_owners;
  size_t max_flows;
  size_t max_pending_messages;
  size_t max_pending_bytes;
  size_t active_owners;
  size_t active_flows;
  size_t pending_messages;
  size_t pending_bytes;
  size_t normal_pending_messages;
  size_t control_pending_messages;
  size_t connection_credit_bytes;
  size_t connection_inflight_bytes;
  size_t control_credit_bytes;
  size_t control_inflight_bytes;
  size_t completed_messages;
  size_t failed_messages;
  size_t cancelled_messages;
  size_t rejected_messages;
  uint64_t generation;
  ftun_status_t terminal_status;
  bool accepting;
  bool failed;
} ftun_carrier_usage_t;

typedef struct {
  uint32_t owner_id;
  size_t max_pending_messages;
  size_t max_pending_bytes;
  size_t active_flows;
  size_t pending_messages;
  size_t pending_bytes;
  bool accepting;
  bool in_callback;
} ftun_carrier_owner_usage_t;

typedef struct {
  uint64_t flow_id;
  ftun_carrier_flow_kind_t kind;
  size_t credit_bytes;
  size_t inflight_bytes;
  size_t max_pending_messages;
  size_t max_pending_bytes;
  size_t pending_messages;
  size_t pending_bytes;
  bool accepting;
} ftun_carrier_flow_usage_t;

/* Connection-level carrier scheduler. All mutable carrier state remains on
 * one owner loop. Logical owners exchange only generation handles, numeric
 * flow ids and retained immutable BufferSlice values. Return completion is
 * delivered through each owner's real Operation queue. The implementation is
 * a transport boundary and scheduler; it is not a wire mux, QUIC, encryption
 * or a claim of cross-thread mutable-state safety. */
ftun_status_t ftun_carrier_create(const ftun_carrier_options_t *options,
                                  const ftun_carrier_backend_t *backend,
                                  ftun_carrier_t **out);
ftun_status_t ftun_carrier_owner_open(
  ftun_carrier_t *carrier, const ftun_carrier_owner_options_t *options,
  ftun_carrier_owner_token_t *out);
ftun_status_t ftun_carrier_owner_stop(ftun_carrier_owner_token_t owner);
ftun_status_t ftun_carrier_owner_close(ftun_carrier_owner_token_t *owner);
ftun_status_t ftun_carrier_owner_get_usage(
  ftun_carrier_owner_token_t owner, ftun_carrier_owner_usage_t *out);

ftun_status_t ftun_carrier_flow_open(
  ftun_carrier_owner_token_t owner, const ftun_carrier_flow_options_t *options,
  ftun_carrier_flow_token_t *out);
ftun_status_t ftun_carrier_flow_send(
  ftun_carrier_flow_token_t flow, const ftun_buffer_slice_t *payload,
  ftun_completion_fn completion, void *completion_user,
  ftun_operation_t **out_operation);
ftun_status_t ftun_carrier_flow_stop(ftun_carrier_flow_token_t flow);
ftun_status_t ftun_carrier_flow_close(ftun_carrier_flow_token_t *flow);
ftun_status_t ftun_carrier_flow_get_usage(
  ftun_carrier_flow_token_t flow, ftun_carrier_flow_usage_t *out);

ftun_status_t ftun_carrier_owner_send_control(
  ftun_carrier_owner_token_t owner, const ftun_buffer_slice_t *payload,
  ftun_completion_fn completion, void *completion_user,
  ftun_operation_t **out_operation);
/* One action is one backend start attempt. Owner and message cursors persist
 * across calls; control and data alternate when both are eligible. */
ftun_status_t ftun_carrier_process(ftun_carrier_t *carrier, size_t max_work,
                                   size_t *out_work);
/* Backend view remains borrowed through start and accepted ownership. */
ftun_status_t ftun_carrier_send_view(
  ftun_carrier_send_token_t send, ftun_carrier_send_kind_t *kind,
  uint32_t *owner_id, uint64_t *flow_id, ftun_bytes_t *payload);
ftun_status_t ftun_carrier_send_complete(ftun_carrier_send_token_t send,
                                         ftun_error_t error);
/* fail fans one connection failure out to every accepted message. Failed
 * backend cancellation is retained and retried by fail/stop. */
ftun_status_t ftun_carrier_fail(ftun_carrier_t *carrier,
                                ftun_error_t error);
ftun_status_t ftun_carrier_stop(ftun_carrier_t *carrier);
ftun_status_t ftun_carrier_get_usage(const ftun_carrier_t *carrier,
                                     ftun_carrier_usage_t *out);
ftun_status_t ftun_carrier_destroy(ftun_carrier_t **carrier);

#endif
