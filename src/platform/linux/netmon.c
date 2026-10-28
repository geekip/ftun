#define _GNU_SOURCE 1
#include "platform/linux/netmon.h"
#include "platform/linux/uapi.h"
#include "util/time.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define FTUN_NETMON_BUFFER_BYTES 16384u

struct ftun_netmon {
  ftun_event_loop_t *loop;
  int descriptor;
  ftun_event_source_t *io;
  ftun_event_source_t *timer;
  uint64_t debounce_ms;
  ftun_network_change_t pending;
  bool timer_armed;
  bool ready;
  /* 频率监视：窗口起点和窗口内的批次数。 */
  uint64_t window_start_ms;
  uint64_t window_batches;
  ftun_netmon_stats_t stats;
};

static void ftun_netmon_note_interface(ftun_network_change_t *change, uint32_t index)
{
  size_t position;
  if (index == 0u) return;
  for (position = 0u; position < change->interface_count; position++) {
    if (change->interfaces[position] == index) return;
  }
  if (change->interface_count < FTUN_NETWORK_CHANGE_INTERFACES) {
    change->interfaces[change->interface_count++] = index;
  }
}

/* 路由消息里的出接口（RTA_OIF）。 */
static uint32_t ftun_netmon_route_interface(const struct ftun_nlmsghdr *header)
{
  const struct ftun_rtmsg *route;
  const struct ftun_rtattr *attribute;
  size_t remaining;
  if (header->nlmsg_len < FTUN_NLMSG_LENGTH(sizeof(*route))) return 0u;
  route = (const struct ftun_rtmsg *)FTUN_NLMSG_DATA(header);
  remaining = header->nlmsg_len - FTUN_NLMSG_LENGTH(sizeof(*route));
  attribute = (const struct ftun_rtattr *)
    ((const uint8_t *)route + FTUN_NLMSG_ALIGN(sizeof(*route)));
  while (remaining >= sizeof(*attribute) && attribute->rta_len >= sizeof(*attribute) &&
         attribute->rta_len <= remaining) {
    if (attribute->rta_type == FTUN_RTA_OIF &&
        attribute->rta_len >= FTUN_RTA_LENGTH(4u)) {
      uint32_t value;
      memcpy(&value, FTUN_RTA_DATA(attribute), sizeof(value));
      return value;
    }
    remaining -= FTUN_RTA_ALIGN(attribute->rta_len) < remaining
      ? FTUN_RTA_ALIGN(attribute->rta_len) : remaining;
    attribute = (const struct ftun_rtattr *)
      ((const uint8_t *)attribute + FTUN_RTA_ALIGN(attribute->rta_len));
  }
  return 0u;
}

size_t ftun_netmon_parse(const uint8_t *data, size_t length,
                         ftun_network_change_t *change)
{
  const struct ftun_nlmsghdr *header = (const struct ftun_nlmsghdr *)data;
  size_t remaining = length;
  size_t messages = 0u;
  if (data == NULL || change == NULL) return 0u;
  for (; FTUN_NLMSG_OK(header, remaining); header = FTUN_NLMSG_NEXT(header, remaining)) {
    switch (header->nlmsg_type) {
      case FTUN_RTM_NEWLINK:
      case FTUN_RTM_DELLINK:
        change->mask |= FTUN_NETWORK_CHANGE_LINK;
        if (header->nlmsg_len >= FTUN_NLMSG_LENGTH(sizeof(struct ftun_ifinfomsg))) {
          const struct ftun_ifinfomsg *info =
            (const struct ftun_ifinfomsg *)FTUN_NLMSG_DATA(header);
          ftun_netmon_note_interface(change, (uint32_t)info->ifi_index);
        }
        break;
      case FTUN_RTM_NEWADDR:
      case FTUN_RTM_DELADDR:
        change->mask |= FTUN_NETWORK_CHANGE_ADDRESS;
        if (header->nlmsg_len >= FTUN_NLMSG_LENGTH(sizeof(struct ftun_ifaddrmsg))) {
          const struct ftun_ifaddrmsg *info =
            (const struct ftun_ifaddrmsg *)FTUN_NLMSG_DATA(header);
          ftun_netmon_note_interface(change, info->ifa_index);
        }
        break;
      case FTUN_RTM_NEWROUTE:
      case FTUN_RTM_DELROUTE:
        change->mask |= FTUN_NETWORK_CHANGE_ROUTE;
        ftun_netmon_note_interface(change, ftun_netmon_route_interface(header));
        break;
      case FTUN_RTM_NEWRULE:
      case FTUN_RTM_DELRULE:
        change->mask |= FTUN_NETWORK_CHANGE_RULE;
        break;
      default:
        continue;
    }
    change->events++;
    messages++;
  }
  return messages;
}

static void ftun_netmon_timer_ready(ftun_event_source_t *source, uint32_t events,
                                    void *user)
{
  ftun_netmon_t *netmon = (ftun_netmon_t *)user;
  (void)source;
  (void)events;
  /* 一次性计时器触发后源仍占着额度，由 take/arm/destroy 撤销，不能在这里丢掉句柄。 */
  netmon->timer_armed = false;
  netmon->ready = true;
}

static void ftun_netmon_arm(ftun_netmon_t *netmon)
{
  uint64_t now_ms = 0u;
  if (netmon->timer_armed || netmon->ready) return;
  (void)ftun_event_source_cancel(&netmon->timer);
  if (ftun_monotonic_now(&now_ms) != FTUN_OK) {
    netmon->ready = true;
    return;
  }
  /* 窗口内后续的变化只合并，不再延长窗口。 */
  if (ftun_event_timer_start(netmon->loop, now_ms + netmon->debounce_ms,
        ftun_netmon_timer_ready, netmon, &netmon->timer) == FTUN_OK) {
    netmon->timer_armed = true;
  } else {
    netmon->ready = true;
  }
}

static void ftun_netmon_io_ready(ftun_event_source_t *source, uint32_t events,
                                 void *user)
{
  ftun_netmon_t *netmon = (ftun_netmon_t *)user;
  uint8_t buffer[FTUN_NETMON_BUFFER_BYTES];
  size_t drained;
  (void)source;
  (void)events;
  for (drained = 0u; drained < 64u; drained++) {
    ssize_t received = recv(netmon->descriptor, buffer, sizeof(buffer), MSG_DONTWAIT);
    if (received < 0) {
      if (errno == EINTR) continue;
      if (errno == ENOBUFS) {
        /* 事件丢失：按“全部可能已经变化”处理，由消费方做一次全量核验。 */
        netmon->pending.mask |= FTUN_NETWORK_CHANGE_ALL;
        netmon->stats.overflows++;
        ftun_netmon_arm(netmon);
        continue;
      }
      break;
    }
    if (received == 0) break;
    {
      size_t messages = ftun_netmon_parse(buffer, (size_t)received, &netmon->pending);
      netmon->stats.events += messages;
      if (messages != 0u) ftun_netmon_arm(netmon);
    }
  }
}

ftun_status_t ftun_netmon_create(ftun_event_loop_t *loop, uint64_t debounce_ms,
                                 ftun_netmon_t **out)
{
  struct ftun_sockaddr_nl address;
  ftun_netmon_t *netmon;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (loop == NULL || out == NULL) return FTUN_E_INVALID;
  netmon = (ftun_netmon_t *)calloc(1u, sizeof(*netmon));
  if (netmon == NULL) return FTUN_E_LIMIT;
  netmon->loop = loop;
  netmon->debounce_ms = debounce_ms == 0u ? FTUN_NETMON_DEBOUNCE_MS : debounce_ms;
  netmon->descriptor = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
                              FTUN_NETLINK_ROUTE);
  if (netmon->descriptor < 0) {
    free(netmon);
    return FTUN_E_UNSUPPORTED;
  }
  memset(&address, 0, sizeof(address));
  address.nl_family = AF_NETLINK;
  address.nl_groups = FTUN_RTMGRP_LINK | FTUN_RTMGRP_IPV4_IFADDR |
                      FTUN_RTMGRP_IPV4_ROUTE | FTUN_RTMGRP_IPV4_RULE;
  if (bind(netmon->descriptor, (struct sockaddr *)&address, sizeof(address)) < 0) {
    (void)close(netmon->descriptor);
    free(netmon);
    return FTUN_E_UNSUPPORTED;
  }
  status = ftun_event_io_start(loop, (ftun_native_socket_t)(unsigned int)netmon->descriptor,
    FTUN_EVENT_READ | FTUN_EVENT_ERROR, ftun_netmon_io_ready, netmon, &netmon->io);
  if (status != FTUN_OK) {
    (void)close(netmon->descriptor);
    free(netmon);
    return status;
  }
  *out = netmon;
  return FTUN_OK;
}

ftun_status_t ftun_netmon_destroy(ftun_netmon_t **out)
{
  ftun_netmon_t *netmon;
  ftun_status_t status;
  if (out == NULL) return FTUN_E_INVALID;
  netmon = *out;
  if (netmon == NULL) return FTUN_OK;
  status = ftun_event_source_cancel(&netmon->io);
  if (status != FTUN_OK) return status;
  status = ftun_event_source_cancel(&netmon->timer);
  if (status != FTUN_OK) return status;
  (void)close(netmon->descriptor);
  free(netmon);
  *out = NULL;
  return FTUN_OK;
}

ftun_status_t ftun_netmon_take(ftun_netmon_t *netmon, uint64_t now_ms,
                               ftun_network_change_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (netmon == NULL || out == NULL) return FTUN_E_INVALID;
  if (!netmon->ready) return FTUN_E_AGAIN;
  *out = netmon->pending;
  memset(&netmon->pending, 0, sizeof(netmon->pending));
  netmon->ready = false;
  (void)ftun_event_source_cancel(&netmon->timer);
  netmon->stats.batches++;
  if (now_ms - netmon->window_start_ms >= FTUN_NETMON_STORM_WINDOW_MS) {
    netmon->window_start_ms = now_ms;
    netmon->window_batches = 0u;
  }
  netmon->window_batches++;
  if (netmon->window_batches > FTUN_NETMON_STORM_BATCHES) {
    out->storm = true;
    netmon->stats.storms++;
  }
  /* 取走期间到达的新事件会重新开一个窗口。 */
  if (netmon->pending.mask != 0u) ftun_netmon_arm(netmon);
  return FTUN_OK;
}

ftun_status_t ftun_netmon_get_stats(const ftun_netmon_t *netmon,
                                    ftun_netmon_stats_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (netmon == NULL || out == NULL) return FTUN_E_INVALID;
  *out = netmon->stats;
  return FTUN_OK;
}
