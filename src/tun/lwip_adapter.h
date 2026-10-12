#ifndef FTUN_TUN_LWIP_ADAPTER_H
#define FTUN_TUN_LWIP_ADAPTER_H

#include "internal/contracts.h"
#include "transport/datagram.h"

#define FTUN_LWIP_MIN_MTU 576u
#define FTUN_LWIP_MAX_MTU 65535u

typedef struct ftun_lwip_tcp ftun_lwip_tcp_t;
typedef struct ftun_lwip_udp ftun_lwip_udp_t;

typedef enum {
  FTUN_LWIP_TCP_READABLE = 1,
  FTUN_LWIP_TCP_PEER_FIN,
  FTUN_LWIP_TCP_WRITABLE,
  FTUN_LWIP_TCP_CLOSED
} ftun_lwip_tcp_event_t;

typedef struct {
  const uint8_t *data;
  size_t length;
} ftun_lwip_segment_t;

typedef ftun_status_t (*ftun_lwip_output_fn)(void *user, ftun_bytes_t packet);
typedef ftun_status_t (*ftun_lwip_accept_fn)(void *user, ftun_lwip_tcp_t *flow,
                                             const ftun_endpoint_t *source,
                                             const ftun_endpoint_t *target);
typedef void (*ftun_lwip_tcp_event_fn)(void *user, ftun_lwip_tcp_t *flow,
                                       ftun_lwip_tcp_event_t event,
                                       ftun_status_t status);
typedef void (*ftun_lwip_tcp_write_done_fn)(void *user,
                                            ftun_lwip_tcp_t *flow,
                                            void *token,
                                            ftun_status_t status);
typedef ftun_status_t (*ftun_lwip_udp_accept_fn)(
  void *user, ftun_lwip_udp_t *flow, const ftun_endpoint_t *source,
  const ftun_endpoint_t *target);
typedef ftun_status_t (*ftun_lwip_udp_receive_fn)(
  void *user, ftun_lwip_udp_t *flow, const ftun_packet_t *packet);

typedef struct {
  ftun_budget_t *budget;
  uint32_t mtu;
  uint64_t now_ms;
  ftun_lwip_output_fn output;
  ftun_lwip_accept_fn accept;
  ftun_lwip_tcp_event_fn tcp_event;
  ftun_lwip_tcp_write_done_fn tcp_write_done;
  ftun_lwip_udp_accept_fn udp_accept;
  ftun_lwip_udp_receive_fn udp_receive;
  uint32_t packet_source_id;
  void *user;
} ftun_lwip_spec_t;

typedef struct {
  size_t allocated_bytes;
  size_t allocated_blocks;
  size_t tcp_flows;
  size_t udp_flows;
  size_t received_bytes;
  size_t retained_send_bytes;
  uint64_t tcp_timer_ticks;
  uint64_t reassembly_timer_ticks;
} ftun_lwip_usage_t;

/* lwIP raw API 移植。
 * 需求 REQ-CORE-001；任务 TASK-TUN-002；目标 0.2.0；验收 TEST-TUN-002。
 * 单个实例由同一个 owner loop 串行调用。输入同步借用 packet，并把 slice 的
 * 独立引用交给 pbuf；输出回调中的字节只在回调期间有效。
 * 接收 pbuf 在 consume 前保留，且只对真实消费字节调用 tcp_recved。
 * write_ref 使用无复制 tcp_write，slice 保留至 ACK 或 flow 终止。
 */
ftun_status_t ftun_lwip_create(const ftun_lwip_spec_t *spec, ftun_lwip_t **out);
ftun_status_t ftun_lwip_input(ftun_lwip_t *stack, ftun_packet_t *packet);
ftun_status_t ftun_lwip_tick(ftun_lwip_t *stack, uint64_t now_ms);
/* Reload identity affects only packets/flows accepted after the owner-loop
 * commit; existing bridge metadata remains pinned to its original Runtime. */
ftun_status_t ftun_lwip_set_packet_source(ftun_lwip_t *stack,
                                          uint32_t packet_source_id);
ftun_status_t ftun_lwip_get_usage(const ftun_lwip_t *stack,
                                  ftun_lwip_usage_t *out);
ftun_status_t ftun_lwip_destroy(ftun_lwip_t **stack);

/* peek 返回的段只借用到下一次该 flow 操作；consume 才推进接收窗口。 */
ftun_status_t ftun_lwip_tcp_peek(ftun_lwip_tcp_t *flow,
                                 ftun_lwip_segment_t *segments,
                                 size_t segment_capacity, size_t *segment_count,
                                 size_t *available, bool *peer_finished);
ftun_status_t ftun_lwip_tcp_consume(ftun_lwip_tcp_t *flow, size_t bytes);
ftun_status_t ftun_lwip_tcp_ready(const ftun_lwip_tcp_t *flow,
                                  bool *readable, bool *writable);
ftun_status_t ftun_lwip_tcp_write_ref(ftun_lwip_tcp_t *flow,
                                      const ftun_buffer_slice_t *slice,
                                      size_t *accepted);
/* token 只在整段 ACK 或 flow 终止时通过 tcp_write_done 返回一次。 */
ftun_status_t ftun_lwip_tcp_write_ref_with_token(
  ftun_lwip_tcp_t *flow, const ftun_buffer_slice_t *slice, void *token,
  size_t *accepted);
ftun_status_t ftun_lwip_tcp_shutdown_write(ftun_lwip_tcp_t *flow);
ftun_status_t ftun_lwip_tcp_close(ftun_lwip_tcp_t **flow);

/* UDP flow 由 transparent listener 按四元组创建。receive 中的 Packet
 * 同步借用；send 同步复制 payload 并输出完整 IPv4 包。 */
ftun_status_t ftun_lwip_udp_send(ftun_lwip_udp_t *flow,
                                 const ftun_packet_t *packet);
ftun_status_t ftun_lwip_udp_close(ftun_lwip_udp_t **flow);

#endif
