#include "carrier.h"

#include <stdlib.h>
#include <string.h>

typedef enum {
  FTUN_CARRIER_MESSAGE_FREE = 0,
  FTUN_CARRIER_MESSAGE_QUEUED,
  FTUN_CARRIER_MESSAGE_STARTING,
  FTUN_CARRIER_MESSAGE_INFLIGHT,
  FTUN_CARRIER_MESSAGE_CANCELLING,
  FTUN_CARRIER_MESSAGE_RETURNING,
  FTUN_CARRIER_MESSAGE_CALLBACK
} ftun_carrier_message_state_t;

struct ftun_carrier_message;
typedef struct {
  struct ftun_carrier_message *head;
  struct ftun_carrier_message *tail;
} ftun_carrier_pending_t;

typedef struct {
  ftun_carrier_t *carrier;
  ftun_operation_queue_t *return_operations;
  void (*return_ready)(void *user);
  void *return_ready_user;
  uint32_t owner_id;
  size_t slot;
  uint64_t generation;
  size_t max_pending_messages;
  size_t max_pending_bytes;
  size_t pending_messages;
  size_t pending_bytes;
  size_t active_flows;
  size_t message_cursor;
  ftun_carrier_pending_t pending;
  int accepting;
  int in_callback;
} ftun_carrier_owner_t;

struct ftun_carrier_message;

typedef struct {
  ftun_carrier_t *carrier;
  uint64_t flow_id;
  size_t slot;
  uint64_t generation;
  size_t owner_slot;
  uint64_t owner_generation;
  ftun_carrier_flow_kind_t kind;
  size_t credit_bytes;
  size_t inflight_bytes;
  size_t max_pending_messages;
  size_t max_pending_bytes;
  size_t pending_messages;
  size_t pending_bytes;
  struct ftun_carrier_message *send_head;
  struct ftun_carrier_message *send_tail;
  ftun_carrier_pending_t pending;
  int accepting;
} ftun_carrier_flow_t;

typedef struct ftun_carrier_message {
  ftun_carrier_t *carrier;
  struct ftun_carrier_message *free_next;
  struct ftun_carrier_message *send_previous;
  struct ftun_carrier_message *send_next;
  struct ftun_carrier_message *ready_left;
  struct ftun_carrier_message *ready_right;
  struct ftun_carrier_message *ready_parent;
  struct ftun_carrier_message *pending_previous[3];
  struct ftun_carrier_message *pending_next[3];
  int ready_height;
  int ready_linked;
  ftun_operation_t *operation;
  ftun_operation_token_t completion_token;
  ftun_buffer_slice_t payload;
  ftun_completion_fn completion;
  void *completion_user;
  size_t slot;
  uint64_t generation;
  uint64_t fragment_generation;
  size_t owner_slot;
  uint64_t owner_generation;
  size_t flow_slot;
  uint64_t flow_generation;
  ftun_carrier_send_kind_t kind;
  ftun_carrier_message_state_t state;
  uint64_t last_attempt_round;
  size_t offset;
  size_t offered;
  size_t accepted;
  int send_linked;
} ftun_carrier_message_t;

struct ftun_carrier {
  ftun_budget_t *budget;
  ftun_reservation_t *reservation;
  ftun_carrier_backend_t backend;
  ftun_carrier_owner_t *owners;
  ftun_carrier_flow_t *flows;
  ftun_carrier_message_t *messages;
  ftun_carrier_message_t *free_messages;
  ftun_carrier_message_t *ready[2];
  size_t ready_empty_datagrams;
  size_t last_selection_visits;
  size_t last_work;
  size_t selection_visits;
  size_t max_selection_visits;
  int processing;
  int cancelling;
  int failing;
  ftun_carrier_pending_t pending;
  size_t index_visits;
  size_t last_index_visits;
  size_t last_cleanup_visits;
  size_t cleanup_visits;
  size_t last_backend_attempts;
  size_t max_owners;
  size_t max_flows;
  size_t max_pending_messages;
  size_t max_pending_bytes;
  size_t control_reserve_messages;
  size_t control_reserve_bytes;
  size_t connection_credit_bytes;
  size_t control_credit_bytes;
  size_t max_work_per_round;
  size_t active_owners;
  size_t active_flows;
  size_t pending_messages;
  size_t pending_bytes;
  size_t normal_pending_messages;
  size_t control_pending_messages;
  size_t normal_pending_bytes;
  size_t control_pending_bytes;
  size_t connection_inflight_bytes;
  size_t control_inflight_bytes;
  size_t owner_cursor;
  uint64_t process_round;
  uint64_t next_generation;
  uint64_t generation;
  size_t completed_messages;
  size_t failed_messages;
  size_t cancelled_messages;
  size_t rejected_messages;
  ftun_error_t terminal_error;
  int accepting;
  int failed;
  int prefer_control;
};

static void ftun_carrier_count(size_t *value)
{
  if (*value != SIZE_MAX) (*value)++;
}

static size_t ftun_carrier_work_add(size_t left, size_t right)
{ return right > SIZE_MAX - left ? SIZE_MAX : left + right; }

static void ftun_carrier_work_begin(ftun_carrier_t *carrier)
{
  carrier->last_selection_visits = carrier->last_cleanup_visits = 0u;
  carrier->last_work = carrier->last_backend_attempts = 0u;
  carrier->last_index_visits = 0u;
}

static void ftun_carrier_work_end(ftun_carrier_t *carrier)
{
  carrier->selection_visits = ftun_carrier_work_add(carrier->selection_visits, carrier->last_selection_visits);
  carrier->cleanup_visits = ftun_carrier_work_add(carrier->cleanup_visits, carrier->last_cleanup_visits);
  if (carrier->last_selection_visits > carrier->max_selection_visits)
    carrier->max_selection_visits = carrier->last_selection_visits;
  carrier->last_work = ftun_carrier_work_add(carrier->last_selection_visits, carrier->last_backend_attempts);
  carrier->last_work = ftun_carrier_work_add(carrier->last_work, carrier->last_index_visits);
  carrier->last_work = ftun_carrier_work_add(carrier->last_work, carrier->last_cleanup_visits);
}

static void ftun_carrier_index_count(ftun_carrier_t *carrier)
{
  ftun_carrier_count(&carrier->index_visits);
  if (carrier->processing || carrier->cancelling || carrier->failing)
    ftun_carrier_count(&carrier->last_index_visits);
}

static uint64_t ftun_carrier_next_generation(ftun_carrier_t *carrier)
{
  carrier->next_generation++;
  if (carrier->next_generation == 0u) carrier->next_generation++;
  return carrier->next_generation;
}

static ftun_error_t ftun_carrier_error(ftun_status_t status)
{
  ftun_error_t error;
  memset(&error, 0, sizeof(error));
  error.status = status;
  return error;
}

static int ftun_carrier_options_valid(const ftun_carrier_options_t *options)
{
  return options != NULL && options->budget != NULL &&
    options->max_owners != 0u && options->max_flows != 0u &&
    options->max_pending_messages > options->control_reserve_messages &&
    options->max_pending_bytes > options->control_reserve_bytes &&
    options->control_reserve_messages != 0u &&
    options->control_reserve_bytes != 0u &&
    options->connection_credit_bytes != 0u &&
    options->control_credit_bytes != 0u &&
    options->max_work_per_round != 0u;
}

static int ftun_carrier_backend_valid(const ftun_carrier_backend_t *backend)
{
  return backend != NULL && backend->send_start != NULL &&
    backend->send_cancel != NULL && backend->destroy != NULL;
}

static ftun_carrier_owner_t *ftun_carrier_owner_resolve(
  ftun_carrier_owner_token_t token)
{
  ftun_carrier_owner_t *owner;
  if (token.carrier == NULL || token.generation == 0u ||
      token.slot >= token.carrier->max_owners) return NULL;
  owner = &token.carrier->owners[token.slot];
  if (owner->carrier != token.carrier ||
      owner->generation != token.generation) return NULL;
  return owner;
}

static ftun_carrier_flow_t *ftun_carrier_flow_resolve(
  ftun_carrier_flow_token_t token)
{
  ftun_carrier_flow_t *flow;
  if (token.carrier == NULL || token.generation == 0u ||
      token.slot >= token.carrier->max_flows) return NULL;
  flow = &token.carrier->flows[token.slot];
  if (flow->carrier != token.carrier ||
      flow->generation != token.generation) return NULL;
  return flow;
}

static ftun_carrier_message_t *ftun_carrier_message_resolve(
  ftun_carrier_send_token_t token)
{
  ftun_carrier_message_t *message;
  if (token.carrier == NULL || token.generation == 0u ||
      token.fragment_generation == 0u ||
      token.slot >= token.carrier->max_pending_messages) return NULL;
  message = &token.carrier->messages[token.slot];
  if (message->carrier != token.carrier ||
      message->generation != token.generation ||
      message->fragment_generation != token.fragment_generation) return NULL;
  return message;
}

static ftun_carrier_send_token_t ftun_carrier_send_token(
  const ftun_carrier_message_t *message)
{
  ftun_carrier_send_token_t token;
  memset(&token, 0, sizeof(token));
  if (message != NULL) {
    token.carrier = message->carrier;
    token.slot = message->slot;
    token.generation = message->generation;
    token.fragment_generation = message->fragment_generation;
  }
  return token;
}

static ftun_carrier_owner_t *ftun_carrier_message_owner(
  ftun_carrier_message_t *message)
{
  ftun_carrier_owner_t *owner;
  if (message == NULL || message->carrier == NULL ||
      message->owner_slot >= message->carrier->max_owners) return NULL;
  owner = &message->carrier->owners[message->owner_slot];
  if (owner->carrier != message->carrier ||
      owner->generation != message->owner_generation) return NULL;
  return owner;
}

static ftun_carrier_flow_t *ftun_carrier_message_flow(
  ftun_carrier_message_t *message)
{
  ftun_carrier_flow_t *flow;
  if (message == NULL || message->carrier == NULL ||
      message->kind == FTUN_CARRIER_SEND_CONTROL ||
      message->flow_slot >= message->carrier->max_flows) return NULL;
  flow = &message->carrier->flows[message->flow_slot];
  if (flow->carrier != message->carrier ||
      flow->generation != message->flow_generation) return NULL;
  return flow;
}

static void ftun_carrier_wake_owner(ftun_carrier_message_t *message)
{
  ftun_carrier_owner_t *owner = ftun_carrier_message_owner(message);
  if (owner != NULL && owner->return_ready != NULL) {
    owner->return_ready(owner->return_ready_user);
  }
}

/* 三条独立拥有链：全连接、owner、flow。RETURNING仍占拥有额度，
 * 直到Operation回调返回才摘链；遍历先轮转当前项，不跨后端调用保存next。 */
static void ftun_carrier_pending_append(ftun_carrier_pending_t *list,
  ftun_carrier_message_t *message, size_t lane)
{
  message->pending_previous[lane] = list->tail;
  message->pending_next[lane] = NULL;
  if (list->tail != NULL) list->tail->pending_next[lane] = message;
  else list->head = message;
  list->tail = message;
}

static void ftun_carrier_pending_remove(ftun_carrier_pending_t *list,
  ftun_carrier_message_t *message, size_t lane)
{
  if (message->pending_previous[lane] != NULL) message->pending_previous[lane]->pending_next[lane] = message->pending_next[lane];
  else list->head = message->pending_next[lane];
  if (message->pending_next[lane] != NULL) message->pending_next[lane]->pending_previous[lane] = message->pending_previous[lane];
  else list->tail = message->pending_previous[lane];
  message->pending_next[lane] = message->pending_previous[lane] = NULL;
}

static void ftun_carrier_pending_rotate(ftun_carrier_pending_t *list, size_t lane)
{
  ftun_carrier_message_t *message = list->head;
  if (message == list->tail) return;
  ftun_carrier_pending_remove(list, message, lane);
  ftun_carrier_pending_append(list, message, lane);
}

static void ftun_carrier_pending_link(ftun_carrier_message_t *message)
{
  ftun_carrier_owner_t *owner = ftun_carrier_message_owner(message);
  ftun_carrier_flow_t *flow = ftun_carrier_message_flow(message);
  ftun_carrier_pending_append(&message->carrier->pending, message, 0u);
  ftun_carrier_pending_append(&owner->pending, message, 1u);
  if (flow != NULL) ftun_carrier_pending_append(&flow->pending, message, 2u);
}

static void ftun_carrier_pending_unlink(ftun_carrier_message_t *message)
{
  ftun_carrier_owner_t *owner = ftun_carrier_message_owner(message);
  ftun_carrier_flow_t *flow = ftun_carrier_message_flow(message);
  ftun_carrier_pending_remove(&message->carrier->pending, message, 0u);
  ftun_carrier_pending_remove(&owner->pending, message, 1u);
  if (flow != NULL) ftun_carrier_pending_remove(&flow->pending, message, 2u);
}

/* 只索引可重试的控制帧/Datagram和Stream队首，按owner/slot排序。
 * 槽位数组仍拥有对象；AVL链接随实际sizeof准入，不分配调度节点。 */
static int ftun_carrier_ready_height(ftun_carrier_message_t *node)
{ return node == NULL ? 0 : node->ready_height; }

static void ftun_carrier_ready_refresh(ftun_carrier_message_t *node)
{
  int left = ftun_carrier_ready_height(node->ready_left);
  int right = ftun_carrier_ready_height(node->ready_right);
  node->ready_height = 1 + (left > right ? left : right);
}

static void ftun_carrier_ready_replace(ftun_carrier_message_t *old,
  ftun_carrier_message_t *replacement)
{
  if (old->ready_parent == NULL) old->carrier->ready[old->kind == FTUN_CARRIER_SEND_CONTROL] = replacement;
  else if (old->ready_parent->ready_left == old) old->ready_parent->ready_left = replacement;
  else old->ready_parent->ready_right = replacement;
  if (replacement != NULL) replacement->ready_parent = old->ready_parent;
}

static ftun_carrier_message_t *ftun_carrier_ready_rotate(ftun_carrier_message_t *node, int left)
{
  ftun_carrier_message_t *pivot = left ? node->ready_right : node->ready_left;
  ftun_carrier_index_count(node->carrier);
  ftun_carrier_ready_replace(node, pivot);
  if (left) {
    node->ready_right = pivot->ready_left;
    if (node->ready_right != NULL) node->ready_right->ready_parent = node;
    pivot->ready_left = node;
  } else {
    node->ready_left = pivot->ready_right;
    if (node->ready_left != NULL) node->ready_left->ready_parent = node;
    pivot->ready_right = node;
  }
  node->ready_parent = pivot;
  ftun_carrier_ready_refresh(node);
  ftun_carrier_ready_refresh(pivot);
  return pivot;
}

static void ftun_carrier_ready_balance(ftun_carrier_message_t *node)
{
  while (node != NULL) {
    int balance;
    ftun_carrier_index_count(node->carrier);
    ftun_carrier_ready_refresh(node);
    balance = ftun_carrier_ready_height(node->ready_left) - ftun_carrier_ready_height(node->ready_right);
    if (balance > 1) {
      if (ftun_carrier_ready_height(node->ready_left->ready_left) < ftun_carrier_ready_height(node->ready_left->ready_right))
        (void)ftun_carrier_ready_rotate(node->ready_left, 1);
      node = ftun_carrier_ready_rotate(node, 0);
    } else if (balance < -1) {
      if (ftun_carrier_ready_height(node->ready_right->ready_right) < ftun_carrier_ready_height(node->ready_right->ready_left))
        (void)ftun_carrier_ready_rotate(node->ready_right, 0);
      node = ftun_carrier_ready_rotate(node, 1);
    }
    node = node->ready_parent;
  }
}

static void ftun_carrier_ready_insert(ftun_carrier_message_t *message)
{
  ftun_carrier_message_t **place, *parent = NULL;
  ftun_carrier_flow_t *flow;
  if (message->ready_linked || message->state != FTUN_CARRIER_MESSAGE_QUEUED) return;
  if (message->kind == FTUN_CARRIER_SEND_STREAM) {
    flow = ftun_carrier_message_flow(message);
    if (flow == NULL || flow->send_head != message) return;
  }
  place = &message->carrier->ready[message->kind == FTUN_CARRIER_SEND_CONTROL];
  while (*place != NULL) {
    parent = *place;
    ftun_carrier_index_count(message->carrier);
    place = message->owner_slot < parent->owner_slot ||
      (message->owner_slot == parent->owner_slot && message->slot < parent->slot)
      ? &parent->ready_left : &parent->ready_right;
  }
  *place = message;
  message->ready_parent = parent;
  message->ready_height = 1;
  message->ready_linked = 1;
  if (message->kind == FTUN_CARRIER_SEND_DATAGRAM && message->payload.length == 0u)
    message->carrier->ready_empty_datagrams++;
  ftun_carrier_ready_balance(parent);
}

static void ftun_carrier_ready_remove(ftun_carrier_message_t *message)
{
  ftun_carrier_message_t *repair;
  if (!message->ready_linked) return;
  if (message->kind == FTUN_CARRIER_SEND_DATAGRAM && message->payload.length == 0u)
    message->carrier->ready_empty_datagrams--;
  ftun_carrier_index_count(message->carrier);
  if (message->ready_left != NULL && message->ready_right != NULL) {
    ftun_carrier_message_t *next = message->ready_right;
    while (next->ready_left != NULL) {
      next = next->ready_left;
      ftun_carrier_index_count(message->carrier);
    }
    if (next->ready_parent == message) repair = next;
    else {
      repair = next->ready_parent;
      ftun_carrier_ready_replace(next, next->ready_right);
      next->ready_right = message->ready_right;
      next->ready_right->ready_parent = next;
    }
    ftun_carrier_ready_replace(message, next);
    next->ready_left = message->ready_left;
    next->ready_left->ready_parent = next;
  } else {
    repair = message->ready_parent;
    ftun_carrier_ready_replace(message, message->ready_left != NULL ? message->ready_left : message->ready_right);
  }
  message->ready_left = message->ready_right = message->ready_parent = NULL;
  message->ready_height = message->ready_linked = 0;
  ftun_carrier_ready_balance(repair);
}

static ftun_carrier_message_t *ftun_carrier_ready_lower(ftun_carrier_t *carrier,
  ftun_carrier_message_t *node, size_t owner, size_t slot)
{
  ftun_carrier_message_t *found = NULL;
  while (node != NULL) {
    ftun_carrier_count(&carrier->last_selection_visits);
    if (node->owner_slot < owner || (node->owner_slot == owner && node->slot < slot)) node = node->ready_right;
    else { found = node; node = node->ready_left; }
  }
  return found;
}

static ftun_carrier_message_t *ftun_carrier_ready_next(ftun_carrier_t *carrier,
  ftun_carrier_message_t *node)
{
  if (node->ready_right != NULL) {
    node = node->ready_right;
    ftun_carrier_count(&carrier->last_selection_visits);
    while (node->ready_left != NULL) {
      node = node->ready_left;
      ftun_carrier_count(&carrier->last_selection_visits);
    }
    return node;
  }
  while (node->ready_parent != NULL && node->ready_parent->ready_right == node) {
    node = node->ready_parent;
    ftun_carrier_count(&carrier->last_selection_visits);
  }
  return node->ready_parent;
}

static void ftun_carrier_send_unlink(ftun_carrier_message_t *message)
{
  ftun_carrier_flow_t *flow;
  ftun_carrier_ready_remove(message);
  if (!message->send_linked) return;
  flow = ftun_carrier_message_flow(message);
  if (message->send_previous != NULL) {
    message->send_previous->send_next = message->send_next;
  } else {
    flow->send_head = message->send_next;
  }
  if (message->send_next != NULL) {
    message->send_next->send_previous = message->send_previous;
  } else {
    flow->send_tail = message->send_previous;
  }
  message->send_previous = NULL;
  message->send_next = NULL;
  message->send_linked = 0;
  if (flow->send_head != NULL) ftun_carrier_ready_insert(flow->send_head);
}

static void ftun_carrier_credit_release(ftun_carrier_message_t *message)
{
  ftun_carrier_t *carrier = message->carrier;
  ftun_carrier_flow_t *flow;
  if (message->kind == FTUN_CARRIER_SEND_CONTROL) {
    if (carrier->control_inflight_bytes >= message->accepted) {
      carrier->control_inflight_bytes -= message->accepted;
    } else {
      carrier->control_inflight_bytes = 0u;
    }
  } else {
    flow = ftun_carrier_message_flow(message);
    if (carrier->connection_inflight_bytes >= message->accepted) {
      carrier->connection_inflight_bytes -= message->accepted;
    } else {
      carrier->connection_inflight_bytes = 0u;
    }
    if (flow != NULL && flow->inflight_bytes >= message->accepted) {
      flow->inflight_bytes -= message->accepted;
    } else if (flow != NULL) {
      flow->inflight_bytes = 0u;
    }
  }
  message->accepted = 0u;
  message->offered = 0u;
}

static ftun_status_t ftun_carrier_message_finish(
  ftun_carrier_message_t *message, ftun_error_t error)
{
  ftun_status_t status;
  if (message == NULL || message->operation == NULL ||
      (message->state != FTUN_CARRIER_MESSAGE_QUEUED &&
       message->state != FTUN_CARRIER_MESSAGE_INFLIGHT)) {
    return FTUN_E_STATE_CORRUPT;
  }
  status = ftun_operation_set_cancel_hook(message->operation, NULL, NULL);
  if (status != FTUN_OK) return status;
  status = ftun_operation_complete(message->completion_token, error);
  if (status != FTUN_OK) return status;
  ftun_carrier_send_unlink(message);
  message->state = FTUN_CARRIER_MESSAGE_RETURNING;
  ftun_carrier_wake_owner(message);
  return FTUN_OK;
}

static ftun_status_t ftun_carrier_message_cancel(void *user)
{
  ftun_carrier_message_t *message = (ftun_carrier_message_t *)user;
  ftun_carrier_t *carrier;
  ftun_status_t status;
  if (message == NULL || message->carrier == NULL) {
    return FTUN_E_STATE_CORRUPT;
  }
  carrier = message->carrier;
  if (message->state == FTUN_CARRIER_MESSAGE_QUEUED) {
    ftun_carrier_send_unlink(message);
    message->state = FTUN_CARRIER_MESSAGE_RETURNING;
    return FTUN_OK;
  }
  if (message->state == FTUN_CARRIER_MESSAGE_STARTING ||
      message->state == FTUN_CARRIER_MESSAGE_CANCELLING) {
    return FTUN_E_AGAIN;
  }
  if (message->state != FTUN_CARRIER_MESSAGE_INFLIGHT) {
    return FTUN_E_STALE;
  }
  message->state = FTUN_CARRIER_MESSAGE_CANCELLING;
  if (carrier->processing || carrier->cancelling || carrier->failing)
    ftun_carrier_count(&carrier->last_cleanup_visits);
  status = carrier->backend.send_cancel(carrier->backend.context,
                                        ftun_carrier_send_token(message));
  if (status != FTUN_OK) {
    message->state = FTUN_CARRIER_MESSAGE_INFLIGHT;
    return status;
  }
  ftun_carrier_credit_release(message);
  ftun_carrier_send_unlink(message);
  message->state = FTUN_CARRIER_MESSAGE_RETURNING;
  return FTUN_OK;
}

static void ftun_carrier_message_dispatched(ftun_operation_t *operation,
                                            ftun_error_t error, void *user)
{
  ftun_carrier_message_t *message = (ftun_carrier_message_t *)user;
  ftun_carrier_t *carrier;
  ftun_carrier_owner_t *owner;
  ftun_carrier_flow_t *flow;
  ftun_completion_fn completion;
  void *completion_user;
  size_t length;
  size_t slot;
  ftun_status_t release_status;
  if (message == NULL || message->carrier == NULL) return;
  carrier = message->carrier;
  owner = ftun_carrier_message_owner(message);
  flow = ftun_carrier_message_flow(message);
  if (owner == NULL || message->state != FTUN_CARRIER_MESSAGE_RETURNING ||
      carrier->pending_messages == 0u ||
      carrier->pending_bytes < message->payload.length ||
      owner->pending_messages == 0u ||
      owner->pending_bytes < message->payload.length ||
      (message->kind != FTUN_CARRIER_SEND_CONTROL &&
       (flow == NULL || flow->pending_messages == 0u ||
        flow->pending_bytes < message->payload.length))) {
    error.status = FTUN_E_STATE_CORRUPT;
  }
  length = message->payload.length;
  completion = message->completion;
  completion_user = message->completion_user;
  slot = message->slot;
  message->state = FTUN_CARRIER_MESSAGE_CALLBACK;
  release_status = ftun_buffer_slice_release(&message->payload);
  if (release_status != FTUN_OK) error.status = release_status;
  owner->in_callback = 1;
  completion(operation, error, completion_user);
  owner->in_callback = 0;

  ftun_carrier_pending_unlink(message);
  if (carrier->pending_messages != 0u) carrier->pending_messages--;
  if (carrier->pending_bytes >= length) carrier->pending_bytes -= length;
  if (owner->pending_messages != 0u) owner->pending_messages--;
  if (owner->pending_bytes >= length) owner->pending_bytes -= length;
  if (message->kind == FTUN_CARRIER_SEND_CONTROL) {
    if (carrier->control_pending_messages != 0u) {
      carrier->control_pending_messages--;
    }
    if (carrier->control_pending_bytes >= length) {
      carrier->control_pending_bytes -= length;
    }
  } else {
    if (carrier->normal_pending_messages != 0u) {
      carrier->normal_pending_messages--;
    }
    if (carrier->normal_pending_bytes >= length) {
      carrier->normal_pending_bytes -= length;
    }
    if (flow != NULL) {
      if (flow->pending_messages != 0u) flow->pending_messages--;
      if (flow->pending_bytes >= length) flow->pending_bytes -= length;
    }
  }
  if (error.status == FTUN_OK) {
    ftun_carrier_count(&carrier->completed_messages);
  } else if (error.status == FTUN_E_CANCELLED) {
    ftun_carrier_count(&carrier->cancelled_messages);
  } else {
    ftun_carrier_count(&carrier->failed_messages);
  }
  memset(message, 0, sizeof(*message));
  message->slot = slot;
  message->free_next = carrier->free_messages;
  carrier->free_messages = message;
}

static void ftun_carrier_message_release_unaccepted(
  ftun_carrier_message_t *message)
{
  ftun_carrier_t *carrier;
  size_t slot;
  if (message == NULL || message->carrier == NULL) return;
  carrier = message->carrier;
  slot = message->slot;
  (void)ftun_buffer_slice_release(&message->payload);
  memset(message, 0, sizeof(*message));
  message->slot = slot;
  message->free_next = carrier->free_messages;
  carrier->free_messages = message;
}

ftun_status_t ftun_carrier_create(const ftun_carrier_options_t *options,
                                  const ftun_carrier_backend_t *backend,
                                  ftun_carrier_t **out)
{
  ftun_carrier_t *carrier;
  ftun_reservation_t *reservation = NULL;
  ftun_budget_resources_t resources;
  ftun_status_t status;
  size_t owner_bytes;
  size_t flow_bytes;
  size_t message_bytes;
  size_t charge;
  size_t index;
  if (out != NULL) *out = NULL;
  if (out == NULL || !ftun_carrier_options_valid(options) ||
      !ftun_carrier_backend_valid(backend)) return FTUN_E_INVALID;
  if (options->max_owners > SIZE_MAX / sizeof(ftun_carrier_owner_t) ||
      options->max_flows > SIZE_MAX / sizeof(ftun_carrier_flow_t) ||
      options->max_pending_messages >
        SIZE_MAX / sizeof(ftun_carrier_message_t)) return FTUN_E_LIMIT;
  owner_bytes = options->max_owners * sizeof(ftun_carrier_owner_t);
  flow_bytes = options->max_flows * sizeof(ftun_carrier_flow_t);
  message_bytes = options->max_pending_messages *
    sizeof(ftun_carrier_message_t);
  if (owner_bytes > SIZE_MAX - sizeof(*carrier) ||
      flow_bytes > SIZE_MAX - sizeof(*carrier) - owner_bytes ||
      message_bytes > SIZE_MAX - sizeof(*carrier) - owner_bytes - flow_bytes) {
    return FTUN_E_LIMIT;
  }
  charge = sizeof(*carrier) + owner_bytes + flow_bytes + message_bytes;
  /* Carrier 本身没有物理 FD；具体 backend 负责其自有传输资源准入。 */
  resources = (ftun_budget_resources_t){charge, 0u,
                                        options->max_pending_messages};
  status = ftun_budget_reserve_resources(options->budget, resources,
                                         &reservation);
  if (status != FTUN_OK) return status;
  carrier = (ftun_carrier_t *)calloc(1u, sizeof(*carrier));
  if (carrier != NULL) {
    carrier->owners = (ftun_carrier_owner_t *)calloc(
      options->max_owners, sizeof(*carrier->owners));
    carrier->flows = (ftun_carrier_flow_t *)calloc(
      options->max_flows, sizeof(*carrier->flows));
    carrier->messages = (ftun_carrier_message_t *)calloc(
      options->max_pending_messages, sizeof(*carrier->messages));
  }
  if (carrier == NULL || carrier->owners == NULL || carrier->flows == NULL ||
      carrier->messages == NULL) {
    if (carrier != NULL) {
      free(carrier->messages);
      free(carrier->flows);
      free(carrier->owners);
    }
    free(carrier);
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  carrier->budget = options->budget;
  carrier->reservation = reservation;
  carrier->backend = *backend;
  carrier->max_owners = options->max_owners;
  carrier->max_flows = options->max_flows;
  carrier->max_pending_messages = options->max_pending_messages;
  carrier->max_pending_bytes = options->max_pending_bytes;
  carrier->control_reserve_messages = options->control_reserve_messages;
  carrier->control_reserve_bytes = options->control_reserve_bytes;
  carrier->connection_credit_bytes = options->connection_credit_bytes;
  carrier->control_credit_bytes = options->control_credit_bytes;
  carrier->max_work_per_round = options->max_work_per_round;
  carrier->accepting = 1;
  carrier->prefer_control = 1;
  carrier->next_generation = 1u;
  carrier->generation = 1u;
  for (index = carrier->max_pending_messages; index != 0u; index--) {
    size_t slot = index - 1u;
    carrier->messages[slot].slot = slot;
    carrier->messages[slot].free_next = carrier->free_messages;
    carrier->free_messages = &carrier->messages[slot];
  }
  *out = carrier;
  return FTUN_OK;
}

ftun_status_t ftun_carrier_owner_open(
  ftun_carrier_t *carrier, const ftun_carrier_owner_options_t *options,
  ftun_carrier_owner_token_t *out)
{
  ftun_budget_t *return_budget = NULL;
  ftun_operation_queue_usage_t queue_usage;
  bool same_root = false;
  size_t index;
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (carrier == NULL || options == NULL || out == NULL ||
      options->return_operations == NULL ||
      options->max_pending_messages == 0u ||
      options->max_pending_messages > carrier->max_pending_messages ||
      options->max_pending_bytes == 0u ||
      options->max_pending_bytes > carrier->max_pending_bytes) {
    return FTUN_E_INVALID;
  }
  if (!carrier->accepting) return carrier->failed
    ? carrier->terminal_error.status : FTUN_E_CANCELLED;
  status = ftun_operation_queue_budget(options->return_operations,
                                       &return_budget);
  if (status == FTUN_OK) {
    status = ftun_budget_same_root(carrier->budget, return_budget, &same_root);
  }
  if (status != FTUN_OK) return status;
  if (!same_root) return FTUN_E_REJECTED;
  status = ftun_operation_queue_get_usage(options->return_operations,
                                          &queue_usage);
  if (status != FTUN_OK) return status;
  if (!queue_usage.accepting || queue_usage.control_reserve == 0u) {
    return FTUN_E_REJECTED;
  }
  for (index = 0u; index < carrier->max_owners; index++) {
    if (carrier->owners[index].carrier != NULL &&
        carrier->owners[index].owner_id == options->owner_id) {
      return FTUN_E_REJECTED;
    }
  }
  for (index = 0u; index < carrier->max_owners; index++) {
    ftun_carrier_owner_t *owner = &carrier->owners[index];
    if (owner->carrier != NULL) continue;
    memset(owner, 0, sizeof(*owner));
    owner->carrier = carrier;
    owner->return_operations = options->return_operations;
    owner->return_ready = options->return_ready;
    owner->return_ready_user = options->return_ready_user;
    owner->owner_id = options->owner_id;
    owner->slot = index;
    owner->generation = ftun_carrier_next_generation(carrier);
    owner->max_pending_messages = options->max_pending_messages;
    owner->max_pending_bytes = options->max_pending_bytes;
    owner->accepting = 1;
    carrier->active_owners++;
    out->carrier = carrier;
    out->slot = index;
    out->generation = owner->generation;
    return FTUN_OK;
  }
  return FTUN_E_LIMIT;
}

ftun_status_t ftun_carrier_flow_open(
  ftun_carrier_owner_token_t owner_token,
  const ftun_carrier_flow_options_t *options,
  ftun_carrier_flow_token_t *out)
{
  ftun_carrier_owner_t *owner = ftun_carrier_owner_resolve(owner_token);
  ftun_carrier_t *carrier;
  size_t index;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (owner == NULL || options == NULL || out == NULL ||
      (options->kind != FTUN_CARRIER_FLOW_STREAM &&
       options->kind != FTUN_CARRIER_FLOW_DATAGRAM) ||
      options->credit_bytes == 0u ||
      options->max_pending_messages == 0u ||
      options->max_pending_bytes == 0u ||
      options->max_pending_messages > owner->max_pending_messages ||
      options->max_pending_bytes > owner->max_pending_bytes) {
    return FTUN_E_INVALID;
  }
  carrier = owner->carrier;
  if (!carrier->accepting || !owner->accepting) return carrier->failed
    ? carrier->terminal_error.status : FTUN_E_CANCELLED;
  for (index = 0u; index < carrier->max_flows; index++) {
    if (carrier->flows[index].carrier == carrier &&
        carrier->flows[index].owner_slot == owner->slot &&
        carrier->flows[index].owner_generation == owner->generation &&
        carrier->flows[index].flow_id == options->flow_id) {
      return FTUN_E_REJECTED;
    }
  }
  for (index = 0u; index < carrier->max_flows; index++) {
    ftun_carrier_flow_t *flow = &carrier->flows[index];
    if (flow->carrier != NULL) continue;
    memset(flow, 0, sizeof(*flow));
    flow->carrier = carrier;
    flow->flow_id = options->flow_id;
    flow->slot = index;
    flow->generation = ftun_carrier_next_generation(carrier);
    flow->owner_slot = owner->slot;
    flow->owner_generation = owner->generation;
    flow->kind = options->kind;
    flow->credit_bytes = options->credit_bytes;
    flow->max_pending_messages = options->max_pending_messages;
    flow->max_pending_bytes = options->max_pending_bytes;
    flow->accepting = 1;
    owner->active_flows++;
    carrier->active_flows++;
    out->carrier = carrier;
    out->slot = index;
    out->generation = flow->generation;
    return FTUN_OK;
  }
  return FTUN_E_LIMIT;
}

static ftun_status_t ftun_carrier_message_submit(
  ftun_carrier_owner_t *owner, ftun_carrier_flow_t *flow,
  ftun_carrier_send_kind_t kind, const ftun_buffer_slice_t *payload,
  ftun_completion_fn completion, void *completion_user,
  ftun_operation_t **out_operation)
{
  ftun_carrier_t *carrier;
  ftun_carrier_message_t *message;
  ftun_bytes_t bytes;
  ftun_budget_t *payload_budget = NULL;
  bool same_root = false;
  ftun_status_t status;
  size_t normal_message_limit;
  size_t normal_byte_limit;
  if (out_operation != NULL) *out_operation = NULL;
  if (owner == NULL || payload == NULL || completion == NULL ||
      out_operation == NULL) return FTUN_E_INVALID;
  carrier = owner->carrier;
  status = ftun_buffer_slice_data(payload, &bytes);
  if (status != FTUN_OK) return status;
  status = ftun_buffer_slice_budget(payload, &payload_budget);
  if (status == FTUN_OK) {
    status = ftun_budget_same_root(carrier->budget, payload_budget, &same_root);
  }
  if (status != FTUN_OK) return status;
  if (!same_root) return FTUN_E_REJECTED;
  if ((kind == FTUN_CARRIER_SEND_STREAM ||
       kind == FTUN_CARRIER_SEND_CONTROL) && bytes.length == 0u) {
    return FTUN_E_INVALID;
  }
  if (!carrier->accepting || !owner->accepting ||
      (flow != NULL && !flow->accepting)) return carrier->failed
    ? carrier->terminal_error.status : FTUN_E_CANCELLED;
  if ((kind == FTUN_CARRIER_SEND_CONTROL &&
       bytes.length > carrier->control_credit_bytes) ||
      (kind == FTUN_CARRIER_SEND_DATAGRAM &&
       (bytes.length > carrier->connection_credit_bytes ||
        bytes.length > flow->credit_bytes))) {
    ftun_carrier_count(&carrier->rejected_messages);
    return FTUN_E_LIMIT;
  }
  if (owner->pending_messages >= owner->max_pending_messages ||
      bytes.length > owner->max_pending_bytes - owner->pending_bytes) {
    ftun_carrier_count(&carrier->rejected_messages);
    return FTUN_E_LIMIT;
  }
  if (flow != NULL &&
      (flow->pending_messages >= flow->max_pending_messages ||
       bytes.length > flow->max_pending_bytes - flow->pending_bytes)) {
    ftun_carrier_count(&carrier->rejected_messages);
    return FTUN_E_LIMIT;
  }
  if (carrier->pending_messages >= carrier->max_pending_messages ||
      bytes.length > carrier->max_pending_bytes - carrier->pending_bytes) {
    ftun_carrier_count(&carrier->rejected_messages);
    return FTUN_E_LIMIT;
  }
  normal_message_limit = carrier->max_pending_messages -
    carrier->control_reserve_messages;
  normal_byte_limit = carrier->max_pending_bytes -
    carrier->control_reserve_bytes;
  if (kind != FTUN_CARRIER_SEND_CONTROL &&
      (carrier->normal_pending_messages >= normal_message_limit ||
       bytes.length > normal_byte_limit - carrier->normal_pending_bytes)) {
    ftun_carrier_count(&carrier->rejected_messages);
    return FTUN_E_LIMIT;
  }
  message = carrier->free_messages;
  if (message == NULL) return FTUN_E_STATE_CORRUPT;
  carrier->free_messages = message->free_next;
  memset(message, 0, sizeof(*message));
  message->carrier = carrier;
  message->slot = (size_t)(message - carrier->messages);
  message->generation = ftun_carrier_next_generation(carrier);
  message->owner_slot = owner->slot;
  message->owner_generation = owner->generation;
  message->flow_slot = flow == NULL ? SIZE_MAX : flow->slot;
  message->flow_generation = flow == NULL ? 0u : flow->generation;
  message->kind = kind;
  message->completion = completion;
  message->completion_user = completion_user;
  status = ftun_buffer_slice_clone(payload, &message->payload);
  if (status != FTUN_OK) {
    ftun_carrier_message_release_unaccepted(message);
    return status;
  }
  if (kind == FTUN_CARRIER_SEND_CONTROL) {
    status = ftun_operation_accept_control(
      owner->return_operations, ftun_carrier_message_dispatched, message,
      &message->operation, &message->completion_token);
  } else {
    status = ftun_operation_accept(
      owner->return_operations, ftun_carrier_message_dispatched, message,
      &message->operation, &message->completion_token);
  }
  if (status != FTUN_OK) {
    ftun_carrier_message_release_unaccepted(message);
    return status;
  }
  status = ftun_operation_set_cancel_hook(message->operation,
                                          ftun_carrier_message_cancel,
                                          message);
  if (status != FTUN_OK) {
    (void)ftun_operation_reject(&message->operation);
    ftun_carrier_message_release_unaccepted(message);
    return status;
  }
  message->state = FTUN_CARRIER_MESSAGE_QUEUED;
  if (kind == FTUN_CARRIER_SEND_STREAM) {
    message->send_previous = flow->send_tail;
    if (flow->send_tail != NULL) {
      flow->send_tail->send_next = message;
    } else {
      flow->send_head = message;
    }
    flow->send_tail = message;
    message->send_linked = 1;
  }
  carrier->pending_messages++;
  carrier->pending_bytes += bytes.length;
  owner->pending_messages++;
  owner->pending_bytes += bytes.length;
  if (kind == FTUN_CARRIER_SEND_CONTROL) {
    carrier->control_pending_messages++;
    carrier->control_pending_bytes += bytes.length;
  } else {
    carrier->normal_pending_messages++;
    carrier->normal_pending_bytes += bytes.length;
    flow->pending_messages++;
    flow->pending_bytes += bytes.length;
  }
  ftun_carrier_pending_link(message);
  ftun_carrier_ready_insert(message);
  *out_operation = message->operation;
  return FTUN_OK;
}

ftun_status_t ftun_carrier_flow_send(
  ftun_carrier_flow_token_t flow_token,
  const ftun_buffer_slice_t *payload, ftun_completion_fn completion,
  void *completion_user, ftun_operation_t **out_operation)
{
  ftun_carrier_flow_t *flow = ftun_carrier_flow_resolve(flow_token);
  ftun_carrier_owner_t *owner;
  ftun_carrier_send_kind_t kind;
  if (out_operation != NULL) *out_operation = NULL;
  if (flow == NULL) return FTUN_E_STALE;
  owner = &flow->carrier->owners[flow->owner_slot];
  if (owner->carrier != flow->carrier ||
      owner->generation != flow->owner_generation) {
    return FTUN_E_STATE_CORRUPT;
  }
  kind = flow->kind == FTUN_CARRIER_FLOW_STREAM
    ? FTUN_CARRIER_SEND_STREAM : FTUN_CARRIER_SEND_DATAGRAM;
  return ftun_carrier_message_submit(owner, flow, kind, payload, completion,
                                     completion_user, out_operation);
}

ftun_status_t ftun_carrier_owner_send_control(
  ftun_carrier_owner_token_t owner_token,
  const ftun_buffer_slice_t *payload, ftun_completion_fn completion,
  void *completion_user, ftun_operation_t **out_operation)
{
  ftun_carrier_owner_t *owner = ftun_carrier_owner_resolve(owner_token);
  if (out_operation != NULL) *out_operation = NULL;
  if (owner == NULL) return FTUN_E_STALE;
  return ftun_carrier_message_submit(owner, NULL, FTUN_CARRIER_SEND_CONTROL,
                                     payload, completion, completion_user,
                                     out_operation);
}

static size_t ftun_carrier_message_available(
  ftun_carrier_message_t *message)
{
  ftun_carrier_t *carrier = message->carrier;
  ftun_carrier_flow_t *flow;
  size_t remaining = message->payload.length - message->offset;
  size_t connection_available;
  size_t flow_available;
  if (message->kind == FTUN_CARRIER_SEND_CONTROL) {
    if (carrier->control_inflight_bytes >= carrier->control_credit_bytes) {
      return 0u;
    }
    connection_available = carrier->control_credit_bytes -
      carrier->control_inflight_bytes;
    return remaining <= connection_available ? remaining : 0u;
  }
  flow = ftun_carrier_message_flow(message);
  if (flow == NULL ||
      carrier->connection_inflight_bytes >= carrier->connection_credit_bytes ||
      flow->inflight_bytes >= flow->credit_bytes) return 0u;
  connection_available = carrier->connection_credit_bytes -
    carrier->connection_inflight_bytes;
  flow_available = flow->credit_bytes - flow->inflight_bytes;
  if (remaining > connection_available) remaining = connection_available;
  if (remaining > flow_available) remaining = flow_available;
  if (message->kind == FTUN_CARRIER_SEND_DATAGRAM &&
      remaining != message->payload.length - message->offset) return 0u;
  return remaining;
}

static int ftun_carrier_message_eligible(ftun_carrier_message_t *message,
                                         int control)
{
  if (message->carrier == NULL ||
      message->state != FTUN_CARRIER_MESSAGE_QUEUED ||
      message->last_attempt_round == message->carrier->process_round) return 0;
  if ((message->kind == FTUN_CARRIER_SEND_CONTROL) != control) return 0;
  if (message->kind == FTUN_CARRIER_SEND_STREAM) {
    ftun_carrier_flow_t *flow = ftun_carrier_message_flow(message);
    if (flow == NULL || flow->send_head != message) return 0;
  }
  return ftun_carrier_message_available(message) != 0u ||
    (message->kind == FTUN_CARRIER_SEND_DATAGRAM &&
     message->payload.length == 0u);
}

static ftun_carrier_message_t *ftun_carrier_select(ftun_carrier_t *carrier, int control)
{
  ftun_carrier_message_t *root = carrier->ready[control];
  ftun_carrier_message_t *first;
  size_t first_owner;
  /* 整个连接credit耗尽时无需探测各候选；零长Datagram仍可独立推进。 */
  if (control && carrier->control_inflight_bytes >= carrier->control_credit_bytes) return NULL;
  if (!control && carrier->connection_inflight_bytes >= carrier->connection_credit_bytes &&
      carrier->ready_empty_datagrams == 0u) return NULL;
  first = ftun_carrier_ready_lower(carrier, root, carrier->owner_cursor, 0u);
  if (first == NULL) first = ftun_carrier_ready_lower(carrier, root, 0u, 0u);
  if (first == NULL) return NULL;
  first_owner = first->owner_slot;
  do {
    ftun_carrier_owner_t *owner = &carrier->owners[first->owner_slot];
    ftun_carrier_message_t *begin = ftun_carrier_ready_lower(carrier, root, owner->slot, owner->message_cursor);
    ftun_carrier_message_t *message;
    if (begin == NULL || begin->owner_slot != owner->slot) begin = first;
    message = begin;
    do {
      ftun_carrier_count(&carrier->last_selection_visits);
      if (ftun_carrier_message_eligible(message, control)) {
        owner->message_cursor = (message->slot + 1u) % carrier->max_pending_messages;
        carrier->owner_cursor = (owner->slot + 1u) % carrier->max_owners;
        message->last_attempt_round = carrier->process_round;
        return message;
      }
      message = ftun_carrier_ready_next(carrier, message);
      if (message == NULL || message->owner_slot != owner->slot) message = first;
    } while (message != begin);
    first = owner->slot + 1u < carrier->max_owners
      ? ftun_carrier_ready_lower(carrier, root, owner->slot + 1u, 0u) : NULL;
    if (first == NULL) first = ftun_carrier_ready_lower(carrier, root, 0u, 0u);
  } while (first->owner_slot != first_owner);
  return NULL;
}

static ftun_carrier_message_t *ftun_carrier_select_next(
  ftun_carrier_t *carrier)
{
  ftun_carrier_message_t *message;
  if (carrier->prefer_control) {
    message = ftun_carrier_select(carrier, 1);
    if (message != NULL) {
      carrier->prefer_control = 0;
      return message;
    }
    message = ftun_carrier_select(carrier, 0);
    if (message != NULL) carrier->prefer_control = 1;
    return message;
  }
  message = ftun_carrier_select(carrier, 0);
  if (message != NULL) {
    carrier->prefer_control = 1;
    return message;
  }
  message = ftun_carrier_select(carrier, 1);
  if (message != NULL) carrier->prefer_control = 0;
  return message;
}

static ftun_status_t ftun_carrier_start_message(
  ftun_carrier_message_t *message)
{
  ftun_carrier_t *carrier = message->carrier;
  ftun_carrier_owner_t *owner = ftun_carrier_message_owner(message);
  ftun_carrier_flow_t *flow = ftun_carrier_message_flow(message);
  ftun_status_t status;
  ftun_error_t error;
  size_t offered = ftun_carrier_message_available(message);
  size_t accepted = 0u;
  uint64_t fragment_generation;
  if (message->kind == FTUN_CARRIER_SEND_DATAGRAM &&
      message->payload.length == 0u) offered = 0u;
  if (owner == NULL ||
      (message->kind != FTUN_CARRIER_SEND_CONTROL && flow == NULL)) {
    return FTUN_E_STATE_CORRUPT;
  }
  message->offered = offered;
  fragment_generation = ftun_carrier_next_generation(carrier);
  message->fragment_generation = fragment_generation;
  ftun_carrier_ready_remove(message);
  message->state = FTUN_CARRIER_MESSAGE_STARTING;
  status = carrier->backend.send_start(
    carrier->backend.context, ftun_carrier_send_token(message), message->kind,
    owner->owner_id, flow == NULL ? 0u : flow->flow_id, offered, &accepted);
  if (status != FTUN_OK && accepted == 0u) {
    message->state = FTUN_CARRIER_MESSAGE_QUEUED;
    message->offered = 0u;
    message->fragment_generation = 0u;
    if (status == FTUN_E_AGAIN) { ftun_carrier_ready_insert(message); return FTUN_OK; }
    error = ftun_carrier_error(status);
    return ftun_carrier_message_finish(message, error);
  }
  if (status != FTUN_OK ||
      (message->kind == FTUN_CARRIER_SEND_STREAM &&
       (accepted == 0u || accepted > offered)) ||
      (message->kind != FTUN_CARRIER_SEND_STREAM && accepted != offered)) {
    /* 非法接纳值不能撤销已借出的视图；保留整次 offer，交由 fail 回收。 */
    accepted = offered;
    status = FTUN_E_STATE_CORRUPT;
  }
  message->accepted = accepted;
  message->state = FTUN_CARRIER_MESSAGE_INFLIGHT;
  if (message->kind == FTUN_CARRIER_SEND_CONTROL) {
    carrier->control_inflight_bytes += accepted;
  } else {
    carrier->connection_inflight_bytes += accepted;
    flow->inflight_bytes += accepted;
  }
  if (status == FTUN_OK && message->kind == FTUN_CARRIER_SEND_STREAM &&
      accepted == message->payload.length - message->offset) {
    ftun_carrier_send_unlink(message);
  }
  return status;
}

ftun_status_t ftun_carrier_process(ftun_carrier_t *carrier, size_t max_work,
                                   size_t *out_work)
{
  size_t limit;
  size_t work = 0u;
  ftun_status_t result = FTUN_OK;
  if (out_work != NULL) *out_work = 0u;
  if (carrier == NULL || max_work == 0u || out_work == NULL) {
    return FTUN_E_INVALID;
  }
  if (carrier->processing || carrier->cancelling || carrier->failing) return FTUN_E_AGAIN;
  ftun_carrier_work_begin(carrier);
  if (!carrier->accepting) return carrier->failed
    ? carrier->terminal_error.status : FTUN_E_CANCELLED;
  carrier->process_round++;
  carrier->processing = 1;
  if (carrier->process_round == 0u) {
    ftun_carrier_message_t *message;
    carrier->process_round = 1u;
    /* 仅清实际拥有项；空闲槽已在接纳/回收时清零，不扫描配置容量。 */
    for (message = carrier->pending.head; message != NULL; message = message->pending_next[0]) {
      message->last_attempt_round = 0u;
      ftun_carrier_count(&carrier->last_cleanup_visits);
    }
  }
  limit = max_work < carrier->max_work_per_round
    ? max_work : carrier->max_work_per_round;
  if (limit > carrier->max_pending_messages) {
    limit = carrier->max_pending_messages;
  }
  while (work < limit) {
    ftun_carrier_message_t *message = ftun_carrier_select_next(carrier);
    ftun_status_t status;
    if (message == NULL) break;
    status = ftun_carrier_start_message(message);
    work++;
    if (status != FTUN_OK) {
      if (status == FTUN_E_STATE_CORRUPT) {
        ftun_error_t error = ftun_carrier_error(status);
        (void)ftun_carrier_fail(carrier, error);
      }
      result = status;
      break;
    }
  }
  carrier->processing = 0;
  carrier->last_backend_attempts = work;
  ftun_carrier_work_end(carrier);
  *out_work = work;
  return result;
}

ftun_status_t ftun_carrier_send_view(
  ftun_carrier_send_token_t token, ftun_carrier_send_kind_t *kind,
  uint32_t *owner_id, uint64_t *flow_id, ftun_bytes_t *payload)
{
  ftun_carrier_message_t *message;
  ftun_carrier_owner_t *owner;
  ftun_carrier_flow_t *flow;
  ftun_bytes_t whole;
  ftun_status_t status;
  if (kind != NULL) *kind = 0;
  if (owner_id != NULL) *owner_id = 0u;
  if (flow_id != NULL) *flow_id = 0u;
  if (payload != NULL) memset(payload, 0, sizeof(*payload));
  if (token.carrier == NULL || kind == NULL || owner_id == NULL ||
      flow_id == NULL || payload == NULL) return FTUN_E_INVALID;
  message = ftun_carrier_message_resolve(token);
  if (message == NULL ||
      (message->state != FTUN_CARRIER_MESSAGE_STARTING &&
       message->state != FTUN_CARRIER_MESSAGE_INFLIGHT &&
       message->state != FTUN_CARRIER_MESSAGE_CANCELLING)) {
    return FTUN_E_STALE;
  }
  owner = ftun_carrier_message_owner(message);
  flow = ftun_carrier_message_flow(message);
  if (owner == NULL ||
      (message->kind != FTUN_CARRIER_SEND_CONTROL && flow == NULL)) {
    return FTUN_E_STATE_CORRUPT;
  }
  status = ftun_buffer_slice_data(&message->payload, &whole);
  if (status != FTUN_OK || message->offset > whole.length ||
      message->offered > whole.length - message->offset) {
    return FTUN_E_STATE_CORRUPT;
  }
  payload->data = whole.data + message->offset;
  payload->length = message->offered;
  *kind = message->kind;
  *owner_id = owner->owner_id;
  *flow_id = flow == NULL ? 0u : flow->flow_id;
  return FTUN_OK;
}

ftun_status_t ftun_carrier_send_complete(ftun_carrier_send_token_t token,
                                         ftun_error_t error)
{
  ftun_carrier_message_t *message;
  ftun_carrier_t *carrier;
  size_t accepted;
  if (token.carrier == NULL || token.generation == 0u ||
      token.fragment_generation == 0u || error.status == FTUN_E_AGAIN) {
    return FTUN_E_INVALID;
  }
  message = ftun_carrier_message_resolve(token);
  if (message == NULL) return FTUN_E_STALE;
  if (message->state == FTUN_CARRIER_MESSAGE_CANCELLING) return FTUN_E_AGAIN;
  if (message->state == FTUN_CARRIER_MESSAGE_STARTING) return FTUN_E_AGAIN;
  if (message->state != FTUN_CARRIER_MESSAGE_INFLIGHT) return FTUN_E_STALE;
  carrier = message->carrier;
  accepted = message->accepted;
  ftun_carrier_credit_release(message);
  if (carrier->failed) error = carrier->terminal_error;
  if (error.status == FTUN_OK) {
    if (accepted > message->payload.length - message->offset) {
      return FTUN_E_STATE_CORRUPT;
    }
    message->offset += accepted;
    if (message->offset < message->payload.length) {
      message->state = FTUN_CARRIER_MESSAGE_QUEUED;
      message->fragment_generation = 0u;
      ftun_carrier_ready_insert(message);
      return FTUN_OK;
    }
  }
  message->state = FTUN_CARRIER_MESSAGE_INFLIGHT;
  return ftun_carrier_message_finish(message, error);
}

static ftun_status_t ftun_carrier_cancel_matching(
  ftun_carrier_t *carrier, size_t owner_slot, uint64_t owner_generation,
  size_t flow_slot, uint64_t flow_generation, int match_flow)
{
  ftun_status_t result = FTUN_OK;
  ftun_carrier_pending_t *list;
  size_t lane, count, inspected;
  if (carrier->cancelling || carrier->failing) return FTUN_E_AGAIN;
  if (!carrier->processing) ftun_carrier_work_begin(carrier);
  carrier->cancelling = 1;
  lane = match_flow == 2 ? 0u : (match_flow ? 2u : 1u);
  list = lane == 0u ? &carrier->pending : lane == 1u
    ? &carrier->owners[owner_slot].pending : &carrier->flows[flow_slot].pending;
  count = lane == 0u ? carrier->pending_messages : lane == 1u
    ? carrier->owners[owner_slot].pending_messages : carrier->flows[flow_slot].pending_messages;
  for (inspected = 0u; inspected < count && list->head != NULL; inspected++) {
    ftun_carrier_message_t *message = list->head;
    ftun_status_t status;
    ftun_carrier_pending_rotate(list, lane);
    ftun_carrier_count(&carrier->last_cleanup_visits);
    if (message->carrier != carrier || (lane != 0u &&
        (message->owner_slot != owner_slot || message->owner_generation != owner_generation)) ||
        (lane == 2u && (message->flow_slot != flow_slot || message->flow_generation != flow_generation))) {
      result = FTUN_E_STATE_CORRUPT; break;
    }
    if (message->state == FTUN_CARRIER_MESSAGE_RETURNING || message->state == FTUN_CARRIER_MESSAGE_CALLBACK) continue;
    status = ftun_operation_cancel(message->operation);
    if (status == FTUN_OK) ftun_carrier_wake_owner(message);
    else if (status != FTUN_E_STALE && result == FTUN_OK) result = status;
  }
  carrier->cancelling = 0;
  if (!carrier->processing) ftun_carrier_work_end(carrier);
  return result;
}

ftun_status_t ftun_carrier_flow_stop(ftun_carrier_flow_token_t token)
{
  ftun_carrier_flow_t *flow = ftun_carrier_flow_resolve(token);
  if (flow == NULL) return FTUN_E_STALE;
  flow->accepting = 0;
  return ftun_carrier_cancel_matching(flow->carrier, flow->owner_slot,
                                      flow->owner_generation, flow->slot,
                                      flow->generation, 1);
}

ftun_status_t ftun_carrier_owner_stop(ftun_carrier_owner_token_t token)
{
  ftun_carrier_owner_t *owner = ftun_carrier_owner_resolve(token);
  ftun_carrier_t *carrier;
  if (owner == NULL) return FTUN_E_STALE;
  carrier = owner->carrier;
  owner->accepting = 0;
  return ftun_carrier_cancel_matching(carrier, owner->slot,
                                      owner->generation, 0u, 0u, 0);
}

ftun_status_t ftun_carrier_fail(ftun_carrier_t *carrier,
                                ftun_error_t error)
{
  ftun_status_t result = FTUN_OK;
  size_t inspected, count;
  if (carrier == NULL || error.status == FTUN_OK ||
      error.status == FTUN_E_AGAIN) return FTUN_E_INVALID;
  if (carrier->failing || carrier->cancelling) return FTUN_E_AGAIN;
  if (!carrier->processing) ftun_carrier_work_begin(carrier);
  carrier->failing = 1;
  if (!carrier->failed) {
    carrier->failed = 1;
    carrier->accepting = 0;
    carrier->terminal_error = error;
    carrier->generation = ftun_carrier_next_generation(carrier);
  }
  count = carrier->pending_messages;
  for (inspected = 0u; inspected < count && carrier->pending.head != NULL; inspected++) {
    ftun_carrier_message_t *message = carrier->pending.head;
    ftun_status_t status;
    ftun_carrier_pending_rotate(&carrier->pending, 0u);
    ftun_carrier_count(&carrier->last_cleanup_visits);
    if (message->carrier != carrier ||
        message->state == FTUN_CARRIER_MESSAGE_RETURNING ||
        message->state == FTUN_CARRIER_MESSAGE_CALLBACK) continue;
    if (message->state == FTUN_CARRIER_MESSAGE_INFLIGHT) {
      message->state = FTUN_CARRIER_MESSAGE_CANCELLING;
      ftun_carrier_count(&carrier->last_cleanup_visits);
      status = carrier->backend.send_cancel(
        carrier->backend.context, ftun_carrier_send_token(message));
      if (status != FTUN_OK) {
        message->state = FTUN_CARRIER_MESSAGE_INFLIGHT;
        if (result == FTUN_OK) result = status;
        continue;
      }
      ftun_carrier_credit_release(message);
      message->state = FTUN_CARRIER_MESSAGE_INFLIGHT;
    } else if (message->state != FTUN_CARRIER_MESSAGE_QUEUED) {
      if (result == FTUN_OK) result = FTUN_E_AGAIN;
      continue;
    }
    status = ftun_carrier_message_finish(message, carrier->terminal_error);
    if (status != FTUN_OK && result == FTUN_OK) result = status;
  }
  carrier->failing = 0;
  if (!carrier->processing) ftun_carrier_work_end(carrier);
  return result;
}

ftun_status_t ftun_carrier_stop(ftun_carrier_t *carrier)
{
  if (carrier == NULL) return FTUN_E_INVALID;
  if (carrier->failed) return ftun_carrier_fail(carrier, carrier->terminal_error);
  carrier->accepting = 0;
  return ftun_carrier_cancel_matching(carrier, 0u, 0u, 0u, 0u, 2);
}

ftun_status_t ftun_carrier_flow_close(ftun_carrier_flow_token_t *token)
{
  ftun_carrier_flow_t *flow;
  ftun_carrier_owner_t *owner;
  if (token == NULL) return FTUN_E_INVALID;
  if (token->carrier == NULL) return FTUN_OK;
  flow = ftun_carrier_flow_resolve(*token);
  if (flow == NULL) return FTUN_E_STALE;
  if ((flow->accepting && flow->carrier->accepting &&
       flow->carrier->owners[flow->owner_slot].accepting) || flow->pending_messages != 0u ||
      flow->pending_bytes != 0u || flow->inflight_bytes != 0u ||
      flow->send_head != NULL || flow->send_tail != NULL) {
    return FTUN_E_AGAIN;
  }
  owner = &flow->carrier->owners[flow->owner_slot];
  if (owner->carrier != flow->carrier ||
      owner->generation != flow->owner_generation ||
      owner->active_flows == 0u || flow->carrier->active_flows == 0u) {
    return FTUN_E_STATE_CORRUPT;
  }
  owner->active_flows--;
  flow->carrier->active_flows--;
  memset(flow, 0, sizeof(*flow));
  memset(token, 0, sizeof(*token));
  return FTUN_OK;
}

ftun_status_t ftun_carrier_owner_close(ftun_carrier_owner_token_t *token)
{
  ftun_carrier_owner_t *owner;
  ftun_carrier_t *carrier;
  if (token == NULL) return FTUN_E_INVALID;
  if (token->carrier == NULL) return FTUN_OK;
  owner = ftun_carrier_owner_resolve(*token);
  if (owner == NULL) return FTUN_E_STALE;
  if ((owner->accepting && owner->carrier->accepting) || owner->active_flows != 0u ||
      owner->pending_messages != 0u || owner->pending_bytes != 0u ||
      owner->in_callback) return FTUN_E_AGAIN;
  carrier = owner->carrier;
  if (carrier->active_owners == 0u) return FTUN_E_STATE_CORRUPT;
  carrier->active_owners--;
  memset(owner, 0, sizeof(*owner));
  memset(token, 0, sizeof(*token));
  return FTUN_OK;
}

ftun_status_t ftun_carrier_get_usage(const ftun_carrier_t *carrier,
                                     ftun_carrier_usage_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (carrier == NULL || out == NULL) return FTUN_E_INVALID;
  out->max_owners = carrier->max_owners;
  out->max_flows = carrier->max_flows;
  out->max_pending_messages = carrier->max_pending_messages;
  out->max_pending_bytes = carrier->max_pending_bytes;
  out->active_owners = carrier->active_owners;
  out->active_flows = carrier->active_flows;
  out->pending_messages = carrier->pending_messages;
  out->pending_bytes = carrier->pending_bytes;
  out->normal_pending_messages = carrier->normal_pending_messages;
  out->control_pending_messages = carrier->control_pending_messages;
  out->connection_credit_bytes = carrier->connection_credit_bytes;
  out->connection_inflight_bytes = carrier->connection_inflight_bytes;
  out->control_credit_bytes = carrier->control_credit_bytes;
  out->control_inflight_bytes = carrier->control_inflight_bytes;
  out->completed_messages = carrier->completed_messages;
  out->failed_messages = carrier->failed_messages;
  out->cancelled_messages = carrier->cancelled_messages;
  out->rejected_messages = carrier->rejected_messages;
  out->last_selection_visits = carrier->last_selection_visits;
  out->selection_visits = carrier->selection_visits;
  out->max_selection_visits = carrier->max_selection_visits;
  out->last_work = carrier->last_work;
  out->last_index_visits = carrier->last_index_visits;
  out->last_cleanup_visits = carrier->last_cleanup_visits;
  out->cleanup_visits = carrier->cleanup_visits;
  out->generation = carrier->generation;
  out->terminal_status = carrier->failed
    ? carrier->terminal_error.status
    : (carrier->accepting ? FTUN_OK : FTUN_E_CANCELLED);
  out->accepting = carrier->accepting != 0;
  out->failed = carrier->failed != 0;
  return FTUN_OK;
}

ftun_status_t ftun_carrier_owner_get_usage(
  ftun_carrier_owner_token_t token, ftun_carrier_owner_usage_t *out)
{
  ftun_carrier_owner_t *owner;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (out == NULL) return FTUN_E_INVALID;
  owner = ftun_carrier_owner_resolve(token);
  if (owner == NULL) return FTUN_E_STALE;
  out->owner_id = owner->owner_id;
  out->max_pending_messages = owner->max_pending_messages;
  out->max_pending_bytes = owner->max_pending_bytes;
  out->active_flows = owner->active_flows;
  out->pending_messages = owner->pending_messages;
  out->pending_bytes = owner->pending_bytes;
  out->accepting = owner->accepting && owner->carrier->accepting;
  out->in_callback = owner->in_callback != 0;
  return FTUN_OK;
}

ftun_status_t ftun_carrier_flow_get_usage(
  ftun_carrier_flow_token_t token, ftun_carrier_flow_usage_t *out)
{
  ftun_carrier_flow_t *flow;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (out == NULL) return FTUN_E_INVALID;
  flow = ftun_carrier_flow_resolve(token);
  if (flow == NULL) return FTUN_E_STALE;
  out->flow_id = flow->flow_id;
  out->kind = flow->kind;
  out->credit_bytes = flow->credit_bytes;
  out->inflight_bytes = flow->inflight_bytes;
  out->max_pending_messages = flow->max_pending_messages;
  out->max_pending_bytes = flow->max_pending_bytes;
  out->pending_messages = flow->pending_messages;
  out->pending_bytes = flow->pending_bytes;
  out->accepting = flow->accepting && flow->carrier->accepting &&
    flow->carrier->owners[flow->owner_slot].accepting;
  return FTUN_OK;
}

ftun_status_t ftun_carrier_destroy(ftun_carrier_t **carrier)
{
  ftun_carrier_t *owned;
  ftun_reservation_t *reservation;
  ftun_status_t status;
  if (carrier == NULL) return FTUN_E_INVALID;
  owned = *carrier;
  if (owned == NULL) return FTUN_OK;
  if (owned->accepting || owned->active_owners != 0u ||
      owned->active_flows != 0u || owned->pending_messages != 0u ||
      owned->pending_bytes != 0u || owned->connection_inflight_bytes != 0u ||
      owned->control_inflight_bytes != 0u) return FTUN_E_AGAIN;
  if (owned->pending.head != NULL || owned->pending.tail != NULL ||
      owned->ready[0] != NULL || owned->ready[1] != NULL) return FTUN_E_STATE_CORRUPT;
  reservation = owned->reservation;
  status = ftun_reservation_release(&reservation);
  if (status != FTUN_OK) return status;
  owned->reservation = NULL;
  owned->backend.destroy(owned->backend.context);
  free(owned->messages);
  free(owned->flows);
  free(owned->owners);
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *carrier = NULL;
  return FTUN_OK;
}
