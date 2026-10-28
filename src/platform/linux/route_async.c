#define _GNU_SOURCE 1
#include "route.h"
#include "core/budget.h"
#include "route_internal.h"
#include "event/event.h"
#include "uapi.h"
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>

#define FTUN_LINUX_ROUTE_ASYNC_MAGIC UINT32_C(0x46544152)

typedef enum {
  FTUN_ROUTE_ASYNC_PREFLIGHT = 1,
  FTUN_ROUTE_ASYNC_CHANGE,
  FTUN_ROUTE_ASYNC_RECONCILE
} ftun_route_async_step_t;

struct ftun_linux_route_async {
  uint32_t magic;
  ftun_linux_route_resource_t resources[FTUN_LINUX_ROUTE_PLAN_MAX_RESOURCES];
  bool active[FTUN_LINUX_ROUTE_PLAN_MAX_RESOURCES];
  size_t resource_count;
  size_t active_count;
  size_t cursor;
  size_t remove_cursor;
  ftun_linux_route_async_state_t state;
  ftun_route_async_step_t step;
  ftun_status_t result;
  ftun_status_t cleanup_result;
  ftun_status_t ambiguous_result;
  ftun_linux_route_async_io_t io;
  uint64_t step_timeout_ms;
  uint64_t total_deadline_ms;
  uint64_t pending_deadline_ms;
  uint32_t next_sequence;
  uint32_t pending_sequence;
  ftun_linux_route_request_kind_t pending_kind;
  size_t stale_replies;
  size_t timeouts;
  size_t cleanup_failures;
  bool has_current;
  bool request_sent;
  bool runnable;
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
  int descriptor;
  /* 同一路由表号的实例互斥锁；与 operation 同生命周期。 */
  int lock_descriptor;
  ftun_event_loop_t *loop;
  ftun_event_source_t *io_source;
  ftun_event_source_t *timer_source;
  ftun_linux_route_resource_t query_resource;
  bool query_present;
  bool io_ready;
  bool io_error;
};

size_t ftun_linux_route_async_allocation_size(void)
{
  return sizeof(ftun_linux_route_async_t);
}

static uint64_t ftun_route_async_add_deadline(uint64_t now_ms,
                                              uint64_t timeout_ms)
{
  return timeout_ms > UINT64_MAX - now_ms ? UINT64_MAX : now_ms + timeout_ms;
}

static uint64_t ftun_route_async_step_deadline(
  const ftun_linux_route_async_t *operation, uint64_t now_ms)
{
  uint64_t deadline = ftun_route_async_add_deadline(
    now_ms, operation->step_timeout_ms);
  if (deadline > operation->total_deadline_ms) {
    deadline = operation->total_deadline_ms;
  }
  return deadline;
}

static uint32_t ftun_route_async_next_sequence(
  ftun_linux_route_async_t *operation)
{
  uint32_t sequence = operation->next_sequence;
  operation->next_sequence++;
  if (operation->next_sequence == 0u) operation->next_sequence = 1u;
  return sequence;
}

static void ftun_route_async_io_ready(ftun_event_source_t *source,
                                      uint32_t events, void *user)
{
  ftun_linux_route_async_t *operation = (ftun_linux_route_async_t *)user;
  if (operation == NULL || operation->magic != FTUN_LINUX_ROUTE_ASYNC_MAGIC ||
      operation->io_source != source) return;
  if ((events & (FTUN_EVENT_READ | FTUN_EVENT_WRITE)) != 0u) {
    operation->io_ready = true;
    operation->runnable = true;
  }
  if ((events & FTUN_EVENT_ERROR) != 0u) {
    operation->io_error = true;
    operation->runnable = true;
  }
}

static void ftun_route_async_timer_ready(ftun_event_source_t *source,
                                         uint32_t events, void *user)
{
  ftun_linux_route_async_t *operation = (ftun_linux_route_async_t *)user;
  if (operation != NULL && operation->magic == FTUN_LINUX_ROUTE_ASYNC_MAGIC &&
      operation->timer_source == source &&
      (events & FTUN_EVENT_TIMER) != 0u) operation->runnable = true;
}

static ftun_status_t ftun_route_async_timer_cancel(
  ftun_linux_route_async_t *operation)
{
  if (!operation->system_io) return FTUN_OK;
  return ftun_event_source_cancel(&operation->timer_source);
}

static ftun_status_t ftun_route_async_timer_start(
  ftun_linux_route_async_t *operation, uint64_t deadline_ms)
{
  ftun_status_t status;
  if (!operation->system_io) return FTUN_OK;
  status = ftun_route_async_timer_cancel(operation);
  if (status != FTUN_OK) return status;
  return ftun_event_timer_start(operation->loop, deadline_ms,
    ftun_route_async_timer_ready, operation, &operation->timer_source);
}

static int ftun_netlink_attribute_next(const struct ftun_rtattr **attribute,
                                       size_t *remaining)
{
  size_t length;
  if (attribute == NULL || *attribute == NULL || remaining == NULL ||
      *remaining < sizeof(**attribute) ||
      (*attribute)->rta_len < sizeof(**attribute) ||
      (*attribute)->rta_len > *remaining) return 0;
  length = FTUN_RTA_ALIGN((*attribute)->rta_len);
  if (length > *remaining) return 0;
  *remaining -= length;
  *attribute = (const struct ftun_rtattr *)
    ((const uint8_t *)(*attribute) + length);
  return 1;
}

static int ftun_netlink_attribute_u32(const struct ftun_rtattr *attribute,
                                      uint32_t *out)
{
  if (attribute == NULL || out == NULL ||
      attribute->rta_len < FTUN_RTA_LENGTH(sizeof(*out))) return 0;
  memcpy(out, FTUN_RTA_DATA(attribute), sizeof(*out));
  return 1;
}

static int ftun_netlink_address_matches(
  const struct ftun_nlmsghdr *header,
  const ftun_linux_route_resource_t *resource)
{
  const struct ftun_ifaddrmsg *address;
  const struct ftun_rtattr *attribute;
  size_t remaining;
  unsigned int interface_index = if_nametoindex(resource->interface_name);
  bool local = false;
  bool peer = false;
  if (interface_index == 0u ||
      header->nlmsg_len < FTUN_NLMSG_LENGTH(sizeof(*address))) return 0;
  address = (const struct ftun_ifaddrmsg *)FTUN_NLMSG_DATA(header);
  if (address->ifa_family != AF_INET ||
      address->ifa_prefixlen != resource->prefix_length ||
      address->ifa_index != interface_index) return 0;
  remaining = header->nlmsg_len - FTUN_NLMSG_LENGTH(sizeof(*address));
  attribute = (const struct ftun_rtattr *)
    ((const uint8_t *)address + FTUN_NLMSG_ALIGN(sizeof(*address)));
  while (remaining >= sizeof(*attribute)) {
    size_t value_length;
    if (attribute->rta_len < sizeof(*attribute) ||
        attribute->rta_len > remaining) return 0;
    value_length = attribute->rta_len - FTUN_RTA_LENGTH(0u);
    if (value_length >= 4u && attribute->rta_type == FTUN_IFA_LOCAL &&
        memcmp(FTUN_RTA_DATA(attribute), resource->address, 4u) == 0) {
      local = true;
    }
    if (value_length >= 4u && attribute->rta_type == FTUN_IFA_ADDRESS &&
        memcmp(FTUN_RTA_DATA(attribute), resource->address, 4u) == 0) {
      peer = true;
    }
    if (!ftun_netlink_attribute_next(&attribute, &remaining)) break;
  }
  return local || peer;
}

static int ftun_netlink_route_matches(
  const struct ftun_nlmsghdr *header,
  const ftun_linux_route_resource_t *resource)
{
  const struct ftun_rtmsg *route;
  const struct ftun_rtattr *attribute;
  size_t remaining;
  uint32_t table;
  uint32_t output = 0u;
  uint32_t metric = 0u;
  unsigned int interface_index = 0u;
  bool destination = resource->prefix_length == 0u;
  bool unreachable = resource->kind == FTUN_LINUX_ROUTE_UNREACHABLE;
  if (!unreachable) {
    interface_index = if_nametoindex(resource->interface_name);
    if (interface_index == 0u) return 0;
  }
  if (header->nlmsg_len < FTUN_NLMSG_LENGTH(sizeof(*route))) return 0;
  route = (const struct ftun_rtmsg *)FTUN_NLMSG_DATA(header);
  if (route->rtm_family != AF_INET ||
      route->rtm_dst_len != resource->prefix_length ||
      route->rtm_protocol != resource->protocol ||
      route->rtm_scope != (unreachable ? FTUN_RT_SCOPE_UNIVERSE :
                                        FTUN_RT_SCOPE_LINK) ||
      route->rtm_type != (unreachable ? FTUN_RTN_UNREACHABLE :
                                      FTUN_RTN_UNICAST)) return 0;
  table = route->rtm_table;
  remaining = header->nlmsg_len - FTUN_NLMSG_LENGTH(sizeof(*route));
  attribute = (const struct ftun_rtattr *)
    ((const uint8_t *)route + FTUN_NLMSG_ALIGN(sizeof(*route)));
  while (remaining >= sizeof(*attribute)) {
    uint32_t value;
    if (attribute->rta_type == FTUN_RTA_TABLE &&
        ftun_netlink_attribute_u32(attribute, &value)) table = value;
    if (attribute->rta_type == FTUN_RTA_OIF &&
        ftun_netlink_attribute_u32(attribute, &value)) output = value;
    if (attribute->rta_type == FTUN_RTA_PRIORITY &&
        ftun_netlink_attribute_u32(attribute, &value)) metric = value;
    if (attribute->rta_type == FTUN_RTA_DST &&
        attribute->rta_len >= FTUN_RTA_LENGTH(4u) &&
        memcmp(FTUN_RTA_DATA(attribute), resource->address, 4u) == 0) {
      destination = true;
    }
    if (!ftun_netlink_attribute_next(&attribute, &remaining)) break;
  }
  return table == resource->table && destination &&
    (unreachable || output == interface_index) && metric == resource->metric;
}

static int ftun_netlink_rule_matches(
  const struct ftun_nlmsghdr *header,
  const ftun_linux_route_resource_t *resource)
{
  const struct ftun_fib_rule_hdr *rule;
  const struct ftun_rtattr *attribute;
  size_t remaining;
  uint32_t table;
  uint32_t priority = 0u;
  uint32_t mark = 0u;
  uint32_t mask = 0u;
  uint8_t protocol = 0u;
  const char *interface_name = NULL;
  size_t interface_length = 0u;
  bool destination = resource->prefix_length == 0u;
  uint8_t expected_action = resource->kind == FTUN_LINUX_ROUTE_BLOCK_IPV6 ?
    FTUN_FR_ACT_UNREACHABLE : FTUN_FR_ACT_TO_TBL;
  if (header->nlmsg_len < FTUN_NLMSG_LENGTH(sizeof(*rule))) return 0;
  rule = (const struct ftun_fib_rule_hdr *)FTUN_NLMSG_DATA(header);
  if (rule->family != resource->family || rule->action != expected_action ||
      rule->dst_len != resource->prefix_length) {
    return 0;
  }
  table = rule->table;
  remaining = header->nlmsg_len - FTUN_NLMSG_LENGTH(sizeof(*rule));
  attribute = (const struct ftun_rtattr *)
    ((const uint8_t *)rule + FTUN_NLMSG_ALIGN(sizeof(*rule)));
  while (remaining >= sizeof(*attribute)) {
    uint32_t value;
    size_t value_length;
    if (attribute->rta_len < FTUN_RTA_LENGTH(0u) ||
        attribute->rta_len > remaining) return 0;
    value_length = attribute->rta_len - FTUN_RTA_LENGTH(0u);
    if (attribute->rta_type == FTUN_FRA_TABLE &&
        ftun_netlink_attribute_u32(attribute, &value)) table = value;
    if (attribute->rta_type == FTUN_FRA_PRIORITY &&
        ftun_netlink_attribute_u32(attribute, &value)) priority = value;
    if (attribute->rta_type == FTUN_FRA_FWMARK &&
        ftun_netlink_attribute_u32(attribute, &value)) mark = value;
    if (attribute->rta_type == FTUN_FRA_FWMASK &&
        ftun_netlink_attribute_u32(attribute, &value)) mask = value;
    if (attribute->rta_type == FTUN_FRA_DST && value_length >= 4u &&
        memcmp(FTUN_RTA_DATA(attribute), resource->address, 4u) == 0) {
      destination = true;
    }
    if (attribute->rta_type == FTUN_FRA_PROTOCOL && value_length >= 1u) {
      memcpy(&protocol, FTUN_RTA_DATA(attribute), 1u);
    }
    if (attribute->rta_type == FTUN_FRA_IIFNAME && value_length != 0u) {
      interface_name = (const char *)FTUN_RTA_DATA(attribute);
      interface_length = value_length;
    }
    if (!ftun_netlink_attribute_next(&attribute, &remaining)) break;
  }
  if (priority != resource->priority || protocol != resource->protocol) return 0;
  if (resource->kind == FTUN_LINUX_ROUTE_MARK_RULE) {
    return table == resource->table && mark == resource->mark &&
      mask == resource->mark_mask;
  }
  if (resource->kind == FTUN_LINUX_ROUTE_PROTECT_RULE) {
    return table == resource->table && destination;
  }
  if (resource->kind != FTUN_LINUX_ROUTE_BLOCK_IPV6 &&
      table != resource->table) return 0;
  return interface_name != NULL && interface_length != 0u &&
    strnlen(interface_name, interface_length) + 1u == interface_length &&
    strcmp(interface_name, resource->interface_name) == 0;
}

static int ftun_netlink_resource_matches(
  const struct ftun_nlmsghdr *header,
  const ftun_linux_route_resource_t *resource)
{
  if (resource->kind == FTUN_LINUX_ROUTE_ADDRESS) {
    return header->nlmsg_type == FTUN_RTM_NEWADDR &&
      ftun_netlink_address_matches(header, resource);
  }
  if (resource->kind == FTUN_LINUX_ROUTE_DEFAULT ||
      resource->kind == FTUN_LINUX_ROUTE_OVERLAY ||
      resource->kind == FTUN_LINUX_ROUTE_UNREACHABLE) {
    return header->nlmsg_type == FTUN_RTM_NEWROUTE &&
      ftun_netlink_route_matches(header, resource);
  }
  return header->nlmsg_type == FTUN_RTM_NEWRULE &&
    ftun_netlink_rule_matches(header, resource);
}

static ftun_status_t ftun_netlink_query_build(
  ftun_netlink_message_t *message,
  const ftun_linux_route_resource_t *resource)
{
  memset(message, 0, sizeof(*message));
  message->header.nlmsg_flags = FTUN_NLM_F_REQUEST | FTUN_NLM_F_DUMP;
  if (resource->kind == FTUN_LINUX_ROUTE_ADDRESS) {
    struct ftun_ifaddrmsg *address;
    message->header.nlmsg_type = FTUN_RTM_GETADDR;
    message->header.nlmsg_len = FTUN_NLMSG_LENGTH(sizeof(*address));
    address = (struct ftun_ifaddrmsg *)FTUN_NLMSG_DATA(&message->header);
    memset(address, 0, sizeof(*address));
    address->ifa_family = (uint8_t)resource->family;
  } else if (resource->kind == FTUN_LINUX_ROUTE_DEFAULT ||
             resource->kind == FTUN_LINUX_ROUTE_OVERLAY ||
             resource->kind == FTUN_LINUX_ROUTE_UNREACHABLE) {
    struct ftun_rtmsg *route;
    message->header.nlmsg_type = FTUN_RTM_GETROUTE;
    message->header.nlmsg_len = FTUN_NLMSG_LENGTH(sizeof(*route));
    route = (struct ftun_rtmsg *)FTUN_NLMSG_DATA(&message->header);
    memset(route, 0, sizeof(*route));
    route->rtm_family = (uint8_t)resource->family;
  } else {
    struct ftun_fib_rule_hdr *rule;
    message->header.nlmsg_type = FTUN_RTM_GETRULE;
    message->header.nlmsg_len = FTUN_NLMSG_LENGTH(sizeof(*rule));
    rule = (struct ftun_fib_rule_hdr *)FTUN_NLMSG_DATA(&message->header);
    memset(rule, 0, sizeof(*rule));
    rule->family = (uint8_t)resource->family;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_system_route_async_submit(
  void *context, const ftun_linux_route_request_t *request)
{
  ftun_linux_route_async_t *operation = (ftun_linux_route_async_t *)context;
  ftun_netlink_message_t message;
  struct ftun_sockaddr_nl address;
  ftun_status_t status;
  ssize_t result;
  int error_code;
  if (operation == NULL || request == NULL) return FTUN_E_INVALID;
  if (request->kind == FTUN_LINUX_ROUTE_REQUEST_QUERY) {
    status = ftun_netlink_query_build(&message, &request->resource);
  } else {
    status = ftun_netlink_build(&message, &request->resource,
      request->kind == FTUN_LINUX_ROUTE_REQUEST_ADD);
  }
  if (status != FTUN_OK) return status;
  message.header.nlmsg_seq = request->sequence;
  memset(&address, 0, sizeof(address));
  address.nl_family = AF_NETLINK;
  do {
    result = sendto(operation->descriptor, &message.header,
      message.header.nlmsg_len, MSG_DONTWAIT,
      (struct sockaddr *)&address, sizeof(address));
  } while (result < 0 && errno == EINTR);
  if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
    (void)ftun_event_io_update(operation->io_source,
      FTUN_EVENT_READ | FTUN_EVENT_WRITE | FTUN_EVENT_ERROR);
    return FTUN_E_AGAIN;
  }
  if (result < 0 || (size_t)result != message.header.nlmsg_len) {
    error_code = result < 0 ? errno : EIO;
    return ftun_linux_route_errno(error_code,
      request->kind == FTUN_LINUX_ROUTE_REQUEST_REMOVE);
  }
  (void)ftun_event_io_update(operation->io_source,
    FTUN_EVENT_READ | FTUN_EVENT_ERROR);
  operation->io_ready = false;
  if (request->kind == FTUN_LINUX_ROUTE_REQUEST_QUERY) {
    operation->query_resource = request->resource;
    operation->query_present = false;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_system_route_async_receive(
  void *context, ftun_linux_route_reply_t *reply)
{
  ftun_linux_route_async_t *operation = (ftun_linux_route_async_t *)context;
  struct ftun_sockaddr_nl source;
  socklen_t source_length = (socklen_t)sizeof(source);
  _Alignas(struct ftun_nlmsghdr) uint8_t response[8192];
  struct ftun_nlmsghdr *header;
  ssize_t result;
  size_t remaining;
  if (operation == NULL || reply == NULL) return FTUN_E_INVALID;
  memset(reply, 0, sizeof(*reply));
  memset(&source, 0, sizeof(source));
  operation->io_ready = false;
  do {
    result = recvfrom(operation->descriptor, response, sizeof(response),
      MSG_DONTWAIT | MSG_TRUNC, (struct sockaddr *)&source, &source_length);
  } while (result < 0 && errno == EINTR);
  if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
    if (operation->io_error) {
      operation->io_error = false;
      return FTUN_E_IO;
    }
    return FTUN_E_AGAIN;
  }
  if (result < 0) return ftun_linux_route_errno(errno, false);
  if ((size_t)result > sizeof(response)) return FTUN_E_LIMIT;
  if (source_length < sizeof(source) || source.nl_pid != 0u) return FTUN_E_IO;
  operation->io_error = false;
  remaining = (size_t)result;
  header = (struct ftun_nlmsghdr *)response;
  while (remaining >= sizeof(*header)) {
    size_t aligned_length;
    if (header->nlmsg_len < sizeof(*header) ||
        header->nlmsg_len > remaining) return FTUN_E_IO;
    aligned_length = FTUN_NLMSG_ALIGN(header->nlmsg_len);
    if (aligned_length > remaining) return FTUN_E_IO;
    if (header->nlmsg_seq != operation->pending_sequence) goto next_header;
    if (header->nlmsg_type == FTUN_NLMSG_OVERRUN) return FTUN_E_LIMIT;
    if (header->nlmsg_type == FTUN_NLMSG_ERROR) {
      const struct ftun_nlmsgerr *error =
        (const struct ftun_nlmsgerr *)FTUN_NLMSG_DATA(header);
      if (header->nlmsg_len < FTUN_NLMSG_LENGTH(sizeof(*error))) {
        return FTUN_E_IO;
      }
      reply->sequence = header->nlmsg_seq;
      reply->status = error->error == 0 ? FTUN_OK :
        ftun_linux_route_errno(-error->error,
          operation->pending_kind == FTUN_LINUX_ROUTE_REQUEST_REMOVE);
      return FTUN_OK;
    }
    if (operation->pending_kind == FTUN_LINUX_ROUTE_REQUEST_QUERY) {
      if (ftun_netlink_resource_matches(header, &operation->query_resource)) {
        operation->query_present = true;
      }
      if (header->nlmsg_type == FTUN_NLMSG_DONE) {
        reply->sequence = header->nlmsg_seq;
        reply->status = (header->nlmsg_flags & FTUN_NLM_F_DUMP_INTR) != 0u ?
          FTUN_E_STATE_CORRUPT : FTUN_OK;
        reply->present = operation->query_present;
        return FTUN_OK;
      }
    }
next_header:
    remaining -= aligned_length;
    header = (struct ftun_nlmsghdr *)
      ((uint8_t *)header + aligned_length);
  }
  if (remaining != 0u) return FTUN_E_IO;
  operation->runnable = true;
  return FTUN_E_AGAIN;
}

static ftun_status_t ftun_route_async_pending_clear(
  ftun_linux_route_async_t *operation)
{
  ftun_status_t status = ftun_route_async_timer_cancel(operation);
  operation->request_sent = false;
  operation->pending_sequence = 0u;
  operation->pending_deadline_ms = 0u;
  operation->pending_kind = 0;
  return status;
}

static void ftun_route_async_finish_cleanup(
  ftun_linux_route_async_t *operation)
{
  operation->has_current = false;
  if (operation->active_count != 0u) {
    operation->state = FTUN_LINUX_ROUTE_ASYNC_CLEANUP_FAILED;
    if (operation->cleanup_result == FTUN_OK) {
      operation->cleanup_result = FTUN_E_STATE_CORRUPT;
    }
  } else if (operation->state == FTUN_LINUX_ROUTE_ASYNC_RELEASING) {
    operation->state = FTUN_LINUX_ROUTE_ASYNC_RELEASED;
  } else {
    operation->state = FTUN_LINUX_ROUTE_ASYNC_FAILED;
  }
  operation->runnable = false;
}

static void ftun_route_async_begin_cleanup(
  ftun_linux_route_async_t *operation, ftun_status_t result,
  bool releasing)
{
  if (operation->result == FTUN_OK) operation->result = result;
  operation->state = releasing ? FTUN_LINUX_ROUTE_ASYNC_RELEASING :
    FTUN_LINUX_ROUTE_ASYNC_COMPENSATING;
  operation->remove_cursor = operation->resource_count;
  operation->has_current = false;
  operation->step = FTUN_ROUTE_ASYNC_CHANGE;
  operation->runnable = true;
  if (operation->active_count == 0u) ftun_route_async_finish_cleanup(operation);
}

static void ftun_route_async_cleanup_failed(
  ftun_linux_route_async_t *operation, ftun_status_t status)
{
  if (operation->cleanup_result == FTUN_OK) operation->cleanup_result = status;
  operation->cleanup_failures++;
  operation->has_current = false;
  operation->step = FTUN_ROUTE_ASYNC_CHANGE;
  operation->runnable = true;
}

/* 修复失败不撤销事务：资源保持原所有权，回到 READY 等待下次对账。 */
static void ftun_route_async_repair_end(
  ftun_linux_route_async_t *operation, ftun_status_t status)
{
  operation->repairing = false;
  operation->repair_result = status;
  if (status != FTUN_OK) operation->repair_failures++;
  operation->has_current = false;
  operation->step = FTUN_ROUTE_ASYNC_PREFLIGHT;
  operation->state = FTUN_LINUX_ROUTE_ASYNC_READY;
  operation->runnable = false;
}

static void ftun_route_async_apply_failed(
  ftun_linux_route_async_t *operation, ftun_status_t status)
{
  if (operation->repairing && !operation->release_requested) {
    ftun_route_async_repair_end(operation, status);
    return;
  }
  ftun_route_async_begin_cleanup(operation, status, operation->release_requested);
}

static void ftun_route_async_removed(ftun_linux_route_async_t *operation)
{
  if (operation->active[operation->cursor]) {
    operation->active[operation->cursor] = false;
    operation->active_count--;
  }
  operation->has_current = false;
  operation->step = FTUN_ROUTE_ASYNC_CHANGE;
  operation->runnable = true;
}

static void ftun_route_async_applied(ftun_linux_route_async_t *operation)
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
  operation->runnable = true;
  if (operation->release_requested) {
    ftun_route_async_begin_cleanup(operation, FTUN_E_CANCELLED, true);
  }
}

static int ftun_route_async_prepare_current(
  ftun_linux_route_async_t *operation)
{
  if (operation->state == FTUN_LINUX_ROUTE_ASYNC_APPLYING) {
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
      operation->state = FTUN_LINUX_ROUTE_ASYNC_READY;
      operation->runnable = false;
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
  ftun_linux_route_async_t *operation,
  const ftun_linux_route_reply_t *reply)
{
  bool applying = operation->state == FTUN_LINUX_ROUTE_ASYNC_APPLYING;
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
    operation->runnable = true;
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
      operation->runnable = true;
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

static void ftun_route_async_timeout(ftun_linux_route_async_t *operation)
{
  bool applying = operation->state == FTUN_LINUX_ROUTE_ASYNC_APPLYING;
  operation->timeouts++;
  if (operation->sweeping) {
    ftun_route_async_apply_failed(operation, FTUN_E_TIMEOUT);
    return;
  }
  if (operation->step == FTUN_ROUTE_ASYNC_CHANGE) {
    operation->ambiguous_result = FTUN_E_TIMEOUT;
    operation->step = FTUN_ROUTE_ASYNC_RECONCILE;
    operation->runnable = true;
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

static ftun_linux_route_request_kind_t ftun_route_async_request_kind(
  const ftun_linux_route_async_t *operation)
{
  if (operation->sweeping) return FTUN_LINUX_ROUTE_REQUEST_REMOVE;
  if (operation->step != FTUN_ROUTE_ASYNC_CHANGE) {
    return FTUN_LINUX_ROUTE_REQUEST_QUERY;
  }
  return operation->state == FTUN_LINUX_ROUTE_ASYNC_APPLYING ?
    FTUN_LINUX_ROUTE_REQUEST_ADD : FTUN_LINUX_ROUTE_REQUEST_REMOVE;
}

static ftun_status_t ftun_route_async_allocate_plan(
  const ftun_linux_route_plan_t *plan, const ftun_linux_route_async_io_t *io,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  uint32_t initial_sequence, ftun_linux_route_async_t **out)
{
  ftun_linux_route_async_t *operation;
  if (out != NULL) *out = NULL;
  if (out == NULL || !ftun_linux_route_plan_valid(plan) || io == NULL ||
      io->submit == NULL || io->receive == NULL || step_timeout_ms == 0u ||
      total_deadline_ms <= now_ms || initial_sequence == 0u) {
    return FTUN_E_INVALID;
  }
  operation = (ftun_linux_route_async_t *)calloc(1u, sizeof(*operation));
  if (operation == NULL) return FTUN_E_LIMIT;
  operation->magic = FTUN_LINUX_ROUTE_ASYNC_MAGIC;
  operation->descriptor = -1;
  operation->lock_descriptor = -1;
  operation->io = *io;
  operation->step_timeout_ms = step_timeout_ms;
  operation->total_deadline_ms = total_deadline_ms;
  operation->next_sequence = initial_sequence;
  operation->state = FTUN_LINUX_ROUTE_ASYNC_APPLYING;
  operation->step = FTUN_ROUTE_ASYNC_PREFLIGHT;
  operation->result = FTUN_OK;
  operation->cleanup_result = FTUN_OK;
  operation->runnable = true;
  operation->resource_count = plan->resource_count;
  memcpy(operation->resources, plan->resources,
         plan->resource_count * sizeof(plan->resources[0]));
  operation->sweep = plan->sweep;
  operation->sweeping = plan->sweep;
  *out = operation;
  return FTUN_OK;
}

static ftun_status_t ftun_route_async_policy_plan(
  const ftun_route_policy_t *policy, ftun_linux_route_plan_t *out)
{
  ftun_route_transaction_t transaction;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (out == NULL || !ftun_route_policy_valid(policy)) return FTUN_E_INVALID;
  memset(&transaction, 0, sizeof(transaction));
  if (!ftun_route_build(policy, &transaction)) return FTUN_E_LIMIT;
  out->resource_count = transaction.resource_count;
  memcpy(out->resources, transaction.resources,
         transaction.resource_count * sizeof(transaction.resources[0]));
  return ftun_linux_route_plan_valid(out) ? FTUN_OK : FTUN_E_INVALID;
}

ftun_status_t ftun_linux_route_async_start_with_io(
  const ftun_route_policy_t *policy, const ftun_linux_route_async_io_t *io,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  uint32_t initial_sequence, ftun_linux_route_async_t **out)
{
  ftun_linux_route_plan_t plan;
  ftun_status_t status = ftun_route_async_policy_plan(policy, &plan);
  if (status != FTUN_OK) {
    if (out != NULL) *out = NULL;
    return status;
  }
  return ftun_route_async_allocate_plan(&plan, io, now_ms, step_timeout_ms,
    total_deadline_ms, initial_sequence, out);
}

ftun_status_t ftun_linux_route_async_start_plan_with_io(
  const ftun_linux_route_plan_t *plan, const ftun_linux_route_async_io_t *io,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  uint32_t initial_sequence, ftun_linux_route_async_t **out)
{
  return ftun_route_async_allocate_plan(plan, io, now_ms, step_timeout_ms,
    total_deadline_ms, initial_sequence, out);
}

static ftun_status_t ftun_route_async_start_system_plan(
  const ftun_linux_route_plan_t *plan, uint32_t lock_table,
  ftun_event_loop_t *loop,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  ftun_linux_route_async_t **out)
{
  ftun_linux_route_async_t *operation = NULL;
  ftun_linux_route_async_io_t io;
  struct ftun_sockaddr_nl address;
  ftun_status_t status;
  uint32_t sequence;
  int descriptor;
  if (out != NULL) *out = NULL;
  if (loop == NULL || out == NULL || !ftun_linux_route_plan_valid(plan)) {
    return FTUN_E_INVALID;
  }
  int lock_descriptor;
  status = ftun_linux_route_lock_table(lock_table, &lock_descriptor);
  if (status != FTUN_OK) return status;
  descriptor = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
                      FTUN_NETLINK_ROUTE);
  if (descriptor < 0) {
    int error_code = errno;
    if (lock_descriptor >= 0) (void)close(lock_descriptor);
    return ftun_linux_route_errno(error_code, false);
  }
  memset(&address, 0, sizeof(address));
  address.nl_family = AF_NETLINK;
  if (bind(descriptor, (struct sockaddr *)&address, sizeof(address)) < 0) {
    int error_code = errno;
    (void)close(descriptor);
    if (lock_descriptor >= 0) (void)close(lock_descriptor);
    return ftun_linux_route_errno(error_code, false);
  }
  sequence = (uint32_t)(now_ms ^ (uint64_t)(unsigned int)descriptor);
  if (sequence == 0u) sequence = 1u;
  memset(&io, 0, sizeof(io));
  io.submit = ftun_system_route_async_submit;
  io.receive = ftun_system_route_async_receive;
  status = ftun_route_async_allocate_plan(plan, &io, now_ms, step_timeout_ms,
    total_deadline_ms, sequence, &operation);
  if (status != FTUN_OK) {
    (void)close(descriptor);
    if (lock_descriptor >= 0) (void)close(lock_descriptor);
    return status;
  }
  operation->system_io = true;
  operation->descriptor = descriptor;
  operation->lock_descriptor = lock_descriptor;
  operation->loop = loop;
  operation->io.context = operation;
  status = ftun_event_io_start(loop,
    (ftun_native_socket_t)(unsigned int)descriptor,
    FTUN_EVENT_READ | FTUN_EVENT_ERROR, ftun_route_async_io_ready,
    operation, &operation->io_source);
  if (status != FTUN_OK) {
    operation->magic = 0u;
    (void)close(descriptor);
    if (lock_descriptor >= 0) (void)close(lock_descriptor);
    free(operation);
    return status;
  }
  *out = operation;
  return FTUN_OK;
}

ftun_status_t ftun_linux_route_async_start_plan(
  const ftun_linux_route_plan_t *plan, ftun_event_loop_t *loop,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  ftun_linux_route_async_t **out)
{
  return ftun_route_async_start_system_plan(plan, 0u, loop, now_ms,
    step_timeout_ms, total_deadline_ms, out);
}

ftun_status_t ftun_linux_route_async_start(
  const ftun_route_policy_t *policy, ftun_event_loop_t *loop,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  ftun_linux_route_async_t **out)
{
  ftun_linux_route_plan_t plan;
  ftun_status_t status;
  status = ftun_route_async_policy_plan(policy, &plan);
  if (status != FTUN_OK) {
    if (out != NULL) *out = NULL;
    return status;
  }
  /* 策略事务持有表互斥锁，同表同优先级的协议号 186 对象只能是遗留。 */
  plan.sweep = true;
  return ftun_route_async_start_system_plan(&plan, policy->route_table, loop,
    now_ms, step_timeout_ms, total_deadline_ms, out);
}

static ftun_status_t ftun_route_async_adopt_plan(
  ftun_route_transaction_t **source, ftun_linux_route_async_t **out,
  ftun_linux_route_plan_t *plan)
{
  ftun_linux_route_info_t info;
  size_t index, active = 0u;
  if (source == NULL || *source == NULL || out == NULL || *out != NULL) return FTUN_E_INVALID;
  if (ftun_linux_route_get_info(*source, &info) != FTUN_OK ||
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

static void ftun_route_async_adopt_commit(ftun_route_transaction_t **source,
  ftun_linux_route_async_t *operation, ftun_linux_route_async_t **out)
{
  ftun_route_transaction_t *owned = *source;
  ftun_reservation_t *reservation = owned->reservation;
  memcpy(operation->active, owned->active, owned->resource_count * sizeof(owned->active[0]));
  operation->active_count = owned->active_count;
  /* 表互斥锁随资源一起转交，关闭描述符才释放。 */
  if (owned->lock_descriptor >= 0 && operation->lock_descriptor < 0) {
    operation->lock_descriptor = owned->lock_descriptor;
    owned->lock_descriptor = -1;
  }
  operation->runnable = false;
  if (!owned->retiring && operation->active_count == operation->resource_count) {
    operation->state = FTUN_LINUX_ROUTE_ASYNC_READY;
  } else if (operation->active_count == 0u) {
    operation->state = FTUN_LINUX_ROUTE_ASYNC_RELEASED;
  } else {
    operation->state = FTUN_LINUX_ROUTE_ASYNC_CLEANUP_FAILED;
    operation->result = operation->cleanup_result = FTUN_E_STATE_CORRUPT;
  }
  memset(owned, 0, sizeof(*owned));
  free(owned);
  (void)ftun_reservation_release(&reservation);
  *source = NULL;
  *out = operation;
}

ftun_status_t ftun_linux_route_async_adopt_with_io(
  ftun_route_transaction_t **source, const ftun_linux_route_async_io_t *io,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  uint32_t initial_sequence, ftun_linux_route_async_t **out)
{
  ftun_linux_route_plan_t plan;
  ftun_linux_route_async_t *operation = NULL;
  ftun_status_t status = ftun_route_async_adopt_plan(source, out, &plan);
  if (status != FTUN_OK) return status;
  status = ftun_route_async_allocate_plan(&plan, io, now_ms, step_timeout_ms,
    total_deadline_ms, initial_sequence, &operation);
  if (status == FTUN_OK) ftun_route_async_adopt_commit(source, operation, out);
  return status;
}

ftun_status_t ftun_linux_route_async_adopt(
  ftun_route_transaction_t **source, ftun_event_loop_t *loop,
  uint64_t now_ms, uint64_t step_timeout_ms, uint64_t total_deadline_ms,
  ftun_linux_route_async_t **out)
{
  ftun_linux_route_plan_t plan;
  ftun_linux_route_async_t *operation = NULL;
  ftun_status_t status = ftun_route_async_adopt_plan(source, out, &plan);
  if (status != FTUN_OK) return status;
  status = ftun_route_async_start_system_plan(&plan, 0u, loop, now_ms,
    step_timeout_ms, total_deadline_ms, &operation);
  if (status == FTUN_OK) ftun_route_async_adopt_commit(source, operation, out);
  return status;
}

ftun_status_t ftun_linux_route_async_run(ftun_linux_route_async_t *operation,
                                         uint64_t now_ms, size_t max_work,
                                         size_t *out_work)
{
  size_t work = 0u;
  ftun_status_t return_status = FTUN_OK;
  if (out_work != NULL) *out_work = 0u;
  if (operation == NULL || operation->magic != FTUN_LINUX_ROUTE_ASYNC_MAGIC ||
      max_work == 0u || out_work == NULL) return FTUN_E_INVALID;
  if (operation->running) return FTUN_E_AGAIN;
  operation->running = true;
  if (now_ms >= operation->total_deadline_ms && operation->repairing &&
      !operation->release_requested &&
      operation->state == FTUN_LINUX_ROUTE_ASYNC_APPLYING) {
    /* 修复期限到达：已有资源不动，迟到回复按陈旧处理，下次对账重试。 */
    operation->timeouts++;
    return_status = ftun_route_async_pending_clear(operation);
    ftun_route_async_repair_end(operation, FTUN_E_TIMEOUT);
    work++;
  }
  if (now_ms >= operation->total_deadline_ms &&
      (operation->state == FTUN_LINUX_ROUTE_ASYNC_APPLYING ||
       operation->state == FTUN_LINUX_ROUTE_ASYNC_COMPENSATING ||
       operation->state == FTUN_LINUX_ROUTE_ASYNC_RELEASING)) {
    bool releasing = operation->state == FTUN_LINUX_ROUTE_ASYNC_RELEASING;
    /* 总期限优先于迟到回复。保留未决 ADD 的请求身份，新的 release
     * 先确认 ACK/reconcile，不能把明确拒绝的外部对象当作自己的资源。 */
    if (operation->state == FTUN_LINUX_ROUTE_ASYNC_APPLYING &&
        operation->has_current &&
        (operation->step == FTUN_ROUTE_ASYNC_RECONCILE ||
         (operation->request_sent && operation->pending_kind == FTUN_LINUX_ROUTE_REQUEST_ADD))) {
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
    operation->runnable = false;
    if (operation->active_count != 0u) {
      operation->cleanup_result = FTUN_E_TIMEOUT;
      operation->state = FTUN_LINUX_ROUTE_ASYNC_CLEANUP_FAILED;
    } else {
      operation->state = releasing ? FTUN_LINUX_ROUTE_ASYNC_RELEASED : FTUN_LINUX_ROUTE_ASYNC_FAILED;
    }
    work++;
  }
  while (work < max_work) {
    ftun_status_t status;
    if (operation->state == FTUN_LINUX_ROUTE_ASYNC_READY ||
        operation->state == FTUN_LINUX_ROUTE_ASYNC_FAILED ||
        operation->state == FTUN_LINUX_ROUTE_ASYNC_CLEANUP_FAILED ||
        operation->state == FTUN_LINUX_ROUTE_ASYNC_RELEASED) break;
    if (!operation->has_current && !ftun_route_async_prepare_current(operation)) {
      break;
    }
    if (!operation->request_sent) {
      ftun_linux_route_request_t request;
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
        operation->runnable = false;
        /* 即使首个报文还未写入，也必须有总期限唤醒。 */
        return_status = ftun_route_async_timer_start(operation, operation->total_deadline_ms);
        break;
      }
      if (status == FTUN_E_STALE && request.kind == FTUN_LINUX_ROUTE_REQUEST_REMOVE &&
          operation->state != FTUN_LINUX_ROUTE_ASYNC_APPLYING) {
        /* 构造请求时对象所属接口已不存在：资源已随接口消失，无需发送。 */
        ftun_route_async_removed(operation);
        work++;
        continue;
      }
      if (status != FTUN_OK) {
        if (operation->state == FTUN_LINUX_ROUTE_ASYNC_APPLYING) {
          ftun_route_async_apply_failed(operation, status);
        } else {
          ftun_route_async_cleanup_failed(operation, status);
        }
        work++;
        continue;
      }
      operation->pending_sequence = request.sequence;
      operation->pending_kind = request.kind;
      operation->pending_deadline_ms =
        ftun_route_async_step_deadline(operation, now_ms);
      operation->request_sent = true;
      operation->runnable = false;
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
        operation->runnable = true;
      }
      work++;
      continue;
    }
    {
      ftun_linux_route_reply_t reply;
      operation->runnable = false;
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
        if (operation->runnable) {
          work++;
          continue;
        }
        break;
      }
      if (status != FTUN_OK) {
        ftun_linux_route_request_kind_t kind = operation->pending_kind;
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
          operation->runnable = true;
        } else if (operation->state == FTUN_LINUX_ROUTE_ASYNC_APPLYING) {
          ftun_route_async_apply_failed(operation, status);
        } else {
          ftun_route_async_cleanup_failed(operation, status);
        }
        work++;
        continue;
      }
      work++;
      if (reply.sequence != operation->pending_sequence) {
        operation->stale_replies++;
        operation->runnable = true;
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
      (operation->state == FTUN_LINUX_ROUTE_ASYNC_READY ||
       operation->state == FTUN_LINUX_ROUTE_ASYNC_FAILED ||
       operation->state == FTUN_LINUX_ROUTE_ASYNC_CLEANUP_FAILED ||
       operation->state == FTUN_LINUX_ROUTE_ASYNC_RELEASED)) {
    /* 终态只保留资源责任；迟到 ACK 不应在共享 loop 上持续触发 READ。 */
    ftun_status_t status = ftun_event_source_cancel(&operation->io_source);
    if (return_status == FTUN_OK) return_status = status;
  }
  *out_work = work;
  return return_status;
}

ftun_status_t ftun_linux_route_async_next_deadline(
  const ftun_linux_route_async_t *operation, uint64_t *out_deadline,
  bool *out_present)
{
  if (out_deadline != NULL) *out_deadline = 0u;
  if (out_present != NULL) *out_present = false;
  if (operation == NULL || operation->magic != FTUN_LINUX_ROUTE_ASYNC_MAGIC ||
      out_deadline == NULL || out_present == NULL) return FTUN_E_INVALID;
  if (operation->state != FTUN_LINUX_ROUTE_ASYNC_APPLYING &&
      operation->state != FTUN_LINUX_ROUTE_ASYNC_COMPENSATING &&
      operation->state != FTUN_LINUX_ROUTE_ASYNC_RELEASING) return FTUN_OK;
  if (operation->request_sent) {
    *out_deadline = operation->pending_deadline_ms;
    *out_present = true;
  } else if (operation->state == FTUN_LINUX_ROUTE_ASYNC_APPLYING ||
             operation->state == FTUN_LINUX_ROUTE_ASYNC_COMPENSATING ||
             operation->state == FTUN_LINUX_ROUTE_ASYNC_RELEASING) {
    *out_deadline = operation->total_deadline_ms;
    *out_present = true;
  }
  return FTUN_OK;
}

ftun_status_t ftun_linux_route_async_get_info(
  const ftun_linux_route_async_t *operation,
  ftun_linux_route_async_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (operation == NULL || operation->magic != FTUN_LINUX_ROUTE_ASYNC_MAGIC ||
      out == NULL) return FTUN_E_INVALID;
  out->resource_count = operation->resource_count;
  out->active_count = operation->active_count;
  out->state = operation->state;
  out->result = operation->result;
  out->cleanup_result = operation->cleanup_result;
  out->pending_sequence = operation->pending_sequence;
  out->stale_replies = operation->stale_replies;
  out->timeouts = operation->timeouts;
  out->cleanup_failures = operation->cleanup_failures;
  out->runnable = operation->runnable;
  out->repairing = operation->repairing;
  out->repair_result = operation->repair_result;
  out->repair_runs = operation->repair_runs;
  out->repairs = operation->repairs;
  out->repair_failures = operation->repair_failures;
  out->strays_removed = operation->strays_removed;
  return FTUN_OK;
}

ftun_status_t ftun_linux_route_async_repair(
  ftun_linux_route_async_t *operation, uint64_t now_ms,
  uint64_t total_deadline_ms)
{
  ftun_status_t status;
  if (operation == NULL || operation->magic != FTUN_LINUX_ROUTE_ASYNC_MAGIC ||
      total_deadline_ms <= now_ms) return FTUN_E_INVALID;
  if (operation->running || operation->repairing) return FTUN_E_AGAIN;
  if (operation->state != FTUN_LINUX_ROUTE_ASYNC_READY ||
      operation->release_requested) return FTUN_E_INVALID;
  if (operation->system_io && operation->io_source == NULL) {
    status = ftun_event_io_start(operation->loop,
      (ftun_native_socket_t)(unsigned int)operation->descriptor,
      FTUN_EVENT_READ | FTUN_EVENT_ERROR, ftun_route_async_io_ready,
      operation, &operation->io_source);
    if (status != FTUN_OK) return status;
  }
  operation->repairing = true;
  operation->repair_runs++;
  operation->repair_result = FTUN_OK;
  operation->total_deadline_ms = total_deadline_ms;
  operation->state = FTUN_LINUX_ROUTE_ASYNC_APPLYING;
  operation->step = FTUN_ROUTE_ASYNC_PREFLIGHT;
  operation->cursor = 0u;
  operation->has_current = false;
  operation->runnable = true;
  return FTUN_OK;
}

ftun_status_t ftun_linux_route_async_release(
  ftun_linux_route_async_t *operation, uint64_t now_ms,
  uint64_t total_deadline_ms)
{
  ftun_status_t status;
  if (operation == NULL || operation->magic != FTUN_LINUX_ROUTE_ASYNC_MAGIC ||
      total_deadline_ms <= now_ms) return FTUN_E_INVALID;
  if (operation->running) return FTUN_E_AGAIN;
  if (operation->state == FTUN_LINUX_ROUTE_ASYNC_RELEASED) return FTUN_OK;
  if (operation->system_io && operation->io_source == NULL) {
    status = ftun_event_io_start(operation->loop,
      (ftun_native_socket_t)(unsigned int)operation->descriptor,
      FTUN_EVENT_READ | FTUN_EVENT_ERROR, ftun_route_async_io_ready,
      operation, &operation->io_source);
    if (status != FTUN_OK) return status;
  }
  if (operation->state == FTUN_LINUX_ROUTE_ASYNC_COMPENSATING ||
      operation->state == FTUN_LINUX_ROUTE_ASYNC_RELEASING ||
      operation->release_requested) {
    if (operation->state != FTUN_LINUX_ROUTE_ASYNC_CLEANUP_FAILED) return FTUN_E_AGAIN;
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
    operation->state = FTUN_LINUX_ROUTE_ASYNC_APPLYING;
    operation->runnable = true;
    return FTUN_OK;
  }
  /* ADD 发出后须先消费 ACK 或完成 reconcile。直接清除 pending 会丢失
   * 已生效资源，盲目删除又可能误删 CREATE|EXCL 拒绝的外部对象。 */
  if (operation->state == FTUN_LINUX_ROUTE_ASYNC_APPLYING &&
      operation->has_current &&
      ((operation->request_sent && operation->pending_kind == FTUN_LINUX_ROUTE_REQUEST_ADD) ||
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
  if (operation->state == FTUN_LINUX_ROUTE_ASYNC_FAILED &&
      operation->active_count == 0u) {
    operation->state = FTUN_LINUX_ROUTE_ASYNC_RELEASED;
    operation->runnable = false;
    return FTUN_OK;
  }
  ftun_route_async_begin_cleanup(operation,
    operation->state == FTUN_LINUX_ROUTE_ASYNC_APPLYING ?
      FTUN_E_CANCELLED : operation->result, true);
  return FTUN_OK;
}

ftun_status_t ftun_linux_route_async_destroy(
  ftun_linux_route_async_t **operation)
{
  ftun_linux_route_async_t *owned;
  ftun_status_t status;
  if (operation == NULL) return FTUN_E_INVALID;
  owned = *operation;
  if (owned == NULL) return FTUN_OK;
  if (owned->magic != FTUN_LINUX_ROUTE_ASYNC_MAGIC) return FTUN_E_INVALID;
  if (owned->running || owned->active_count != 0u ||
      (owned->state != FTUN_LINUX_ROUTE_ASYNC_FAILED &&
       owned->state != FTUN_LINUX_ROUTE_ASYNC_RELEASED)) return FTUN_E_AGAIN;
  status = ftun_route_async_timer_cancel(owned);
  if (status != FTUN_OK) return status;
  if (owned->system_io) {
    int descriptor;
    status = ftun_event_source_cancel(&owned->io_source);
    if (status != FTUN_OK) return status;
    descriptor = owned->descriptor;
    owned->descriptor = -1;
    if (descriptor >= 0 && close(descriptor) != 0) return FTUN_E_IO;
    /* 关闭描述符即释放 flock。 */
    if (owned->lock_descriptor >= 0) {
      descriptor = owned->lock_descriptor;
      owned->lock_descriptor = -1;
      if (close(descriptor) != 0) return FTUN_E_IO;
    }
  }
  owned->magic = 0u;
  memset(&owned->io, 0, sizeof(owned->io));
  free(owned);
  *operation = NULL;
  return FTUN_OK;
}
