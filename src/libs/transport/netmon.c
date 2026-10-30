#define _GNU_SOURCE 1
#include "libs/transport/netmon.h"
#include "platform/iface.h"
#include "platform/socket.h"
#include "platform/clock.h"
#include <stdlib.h>
#include <string.h>

#define FTUN_NETMON_BUFFER_BYTES 16384u

struct ftun_netmon {
  ftun_event_loop_t *loop;
  ftun_handle_t descriptor;
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
    size_t received = 0u;
    ftun_status_t status = ftun_iface_receive(netmon->descriptor, buffer, sizeof(buffer), &received);
    if (status == FTUN_E_LIMIT) {
      /* 内核队列丢失事件，上层重新核验全部网络状态。 */
      netmon->pending.mask |= FTUN_NETWORK_CHANGE_ALL;
      netmon->stats.overflows++;
      ftun_netmon_arm(netmon);
      continue;
    }
    if (status != FTUN_OK) break;
    if (received == 0u) continue;
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
  ftun_netmon_t *netmon;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (loop == NULL || out == NULL) return FTUN_E_INVALID;
  netmon = (ftun_netmon_t *)calloc(1u, sizeof(*netmon));
  if (netmon == NULL) return FTUN_E_LIMIT;
  netmon->loop = loop;
  netmon->debounce_ms = debounce_ms == 0u ? FTUN_NETMON_DEBOUNCE_MS : debounce_ms;
  status = ftun_iface_subscribe(&netmon->descriptor);
  if (status != FTUN_OK) { free(netmon); return status; }
  status = ftun_event_io_start(loop, (ftun_native_socket_t)netmon->descriptor,
    FTUN_EVENT_READ | FTUN_EVENT_ERROR, ftun_netmon_io_ready, netmon, &netmon->io);
  if (status != FTUN_OK) {
    (void)ftun_socket_close((ftun_native_socket_t)netmon->descriptor);
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
  (void)ftun_socket_close((ftun_native_socket_t)netmon->descriptor);
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
