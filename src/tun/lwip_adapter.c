#include "lwip_adapter.h"
#include "core/budget.h"

#include <lwip/init.h>
#include <lwip/ip.h>
#include <lwip/ip4_addr.h>
#include <lwip/ip4_frag.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/priv/tcp_priv.h>
#include <lwip/tcp.h>
#include <lwip/udp.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define FTUN_LWIP_ALLOC_MAGIC UINT64_C(0x4654554e4c574950)
#define FTUN_LWIP_MAX_TIMER_CATCHUP 4096u
#define FTUN_LWIP_INPUT_POOL_CAPACITY 1024u
#define FTUN_LWIP_SEND_POOL_CAPACITY 1024u
#define FTUN_LWIP_PACKET_POOL_BYTES (2u * 1024u * 1024u)
#define FTUN_LWIP_PACKET_POOL_BUFFERS 64u

/* TASK-TUN-002 / TEST-TUN-002，目标 0.2.0：NO_SYS raw IPv4、显式计时、
 * Budget allocator，以及 ftun_lwip_input 的 pbuf/ACK 所有权边界。 */

typedef union {
  struct {
    uint64_t magic;
    ftun_lwip_t *stack;
    ftun_reservation_t *reservation;
    size_t charge;
  } value;
  long double long_double_alignment;
  void *pointer_alignment;
} ftun_lwip_alloc_header_t;

typedef struct ftun_lwip_send_ref {
  struct ftun_lwip_send_ref *next;
  struct ftun_lwip_send_ref *free_next;
  ftun_buffer_slice_t slice;
  void *token;
} ftun_lwip_send_ref_t;

typedef struct ftun_lwip_input_pbuf {
  struct pbuf_custom custom;
  struct ftun_lwip_input_pbuf *free_next;
  ftun_lwip_t *stack;
  ftun_buffer_slice_t slice;
} ftun_lwip_input_pbuf_t;

struct ftun_lwip_tcp {
  ftun_lwip_t *stack;
  ftun_lwip_tcp_t *next;
  struct tcp_pcb *pcb;
  struct pbuf *received;
  ftun_lwip_send_ref_t *send_head;
  ftun_lwip_send_ref_t *send_tail;
  size_t received_bytes;
  size_t retained_send_bytes;
  bool peer_finished;
  bool linked;
};

struct ftun_lwip_udp {
  ftun_lwip_t *stack;
  ftun_lwip_udp_t *next;
  struct udp_pcb *pcb;
  ftun_endpoint_t source;
  ftun_endpoint_t target;
  ftun_status_t reject_status;
  bool linked;
};

struct ftun_lwip {
  ftun_budget_t *budget;
  ftun_reservation_t *reservation;
  ftun_reservation_t *wrapper_reservation;
  ftun_buffer_pool_t *packet_pool;
  struct netif netif;
  struct tcp_pcb *listener;
  struct udp_pcb *udp_listener;
  ftun_lwip_tcp_t *flows;
  ftun_lwip_udp_t *udp_flows;
  ftun_lwip_input_pbuf_t *input_storage;
  ftun_lwip_input_pbuf_t *input_free;
  ftun_lwip_send_ref_t *send_storage;
  ftun_lwip_send_ref_t *send_free;
  uint8_t *output_buffer;
  uint32_t mtu;
  uint64_t last_ms;
  uint64_t next_tcp_ms;
  uint64_t next_reassembly_ms;
  uint64_t tcp_timer_ticks;
  uint64_t reassembly_timer_ticks;
  size_t allocated_bytes;
  size_t allocated_blocks;
  size_t flow_count;
  size_t udp_flow_count;
  size_t received_bytes;
  size_t retained_send_bytes;
  size_t input_active;
  size_t send_active;
  uint32_t random_state;
  ftun_lwip_output_fn output;
  ftun_lwip_accept_fn accept;
  ftun_lwip_tcp_event_fn tcp_event;
  ftun_lwip_tcp_write_done_fn tcp_write_done;
  ftun_lwip_udp_accept_fn udp_accept;
  ftun_lwip_udp_receive_fn udp_receive;
  ftun_status_t input_status;
  uint32_t packet_source_id;
  void *user;
  bool netif_added;
  bool destroying;
  bool corrupt;
};

static ftun_lwip_t *ftun_lwip_active;

static ftun_lwip_input_pbuf_t *ftun_lwip_input_acquire(ftun_lwip_t *stack)
{
  ftun_lwip_input_pbuf_t *input;
  if (stack == NULL || stack->input_free == NULL) return NULL;
  input = stack->input_free;
  stack->input_free = input->free_next;
  memset(input, 0, sizeof(*input));
  input->stack = stack;
  stack->input_active++;
  return input;
}

static void ftun_lwip_input_release(ftun_lwip_input_pbuf_t *input)
{
  ftun_lwip_t *stack;
  if (input == NULL || input->stack == NULL) return;
  stack = input->stack;
  (void)ftun_buffer_slice_release(&input->slice);
  if (stack->input_active == 0u) {
    stack->corrupt = true;
    return;
  }
  stack->input_active--;
  memset(input, 0, sizeof(*input));
  input->free_next = stack->input_free;
  stack->input_free = input;
}

static ftun_lwip_send_ref_t *ftun_lwip_send_acquire(ftun_lwip_t *stack)
{
  ftun_lwip_send_ref_t *reference;
  if (stack == NULL || stack->send_free == NULL) return NULL;
  reference = stack->send_free;
  stack->send_free = reference->free_next;
  memset(reference, 0, sizeof(*reference));
  stack->send_active++;
  return reference;
}

static void ftun_lwip_send_release(ftun_lwip_t *stack,
                                   ftun_lwip_send_ref_t *reference)
{
  if (stack == NULL || reference == NULL || stack->send_active == 0u) {
    if (stack != NULL) stack->corrupt = true;
    return;
  }
  (void)ftun_buffer_slice_release(&reference->slice);
  stack->send_active--;
  memset(reference, 0, sizeof(*reference));
  reference->free_next = stack->send_free;
  stack->send_free = reference;
}

static ftun_status_t ftun_lwip_from_err(err_t error)
{
  switch (error) {
    case ERR_OK: return FTUN_OK;
    case ERR_MEM:
    case ERR_BUF: return FTUN_E_LIMIT;
    case ERR_TIMEOUT: return FTUN_E_TIMEOUT;
    case ERR_WOULDBLOCK:
    case ERR_INPROGRESS:
    case ERR_ALREADY: return FTUN_E_AGAIN;
    case ERR_USE: return FTUN_E_REJECTED;
    case ERR_VAL:
    case ERR_ARG: return FTUN_E_INVALID;
    case ERR_ABRT:
    case ERR_RST:
    case ERR_CLSD:
    case ERR_CONN:
    case ERR_RTE:
    case ERR_IF: return FTUN_E_IO;
    default: return FTUN_E_PROTOCOL;
  }
}

void *ftun_lwip_port_malloc(size_t size)
{
  ftun_lwip_alloc_header_t *header;
  ftun_reservation_t *reservation = NULL;
  ftun_lwip_t *stack = ftun_lwip_active;
  size_t charge;
  if (stack == NULL || size == 0u || size > SIZE_MAX - sizeof(*header)) return NULL;
  charge = sizeof(*header) + size;
  if (ftun_budget_reserve(stack->budget, charge, &reservation) != FTUN_OK) return NULL;
  header = (ftun_lwip_alloc_header_t *)malloc(charge);
  if (header == NULL) {
    (void)ftun_reservation_release(&reservation);
    return NULL;
  }
  memset(header, 0, sizeof(*header));
  header->value.magic = FTUN_LWIP_ALLOC_MAGIC;
  header->value.stack = stack;
  header->value.reservation = reservation;
  header->value.charge = charge;
  stack->allocated_bytes += charge;
  stack->allocated_blocks++;
  return (void *)(header + 1);
}

void *ftun_lwip_port_calloc(size_t count, size_t size)
{
  void *pointer;
  size_t total;
  if (count == 0u || size == 0u || count > SIZE_MAX / size) return NULL;
  total = count * size;
  pointer = ftun_lwip_port_malloc(total);
  if (pointer != NULL) memset(pointer, 0, total);
  return pointer;
}

void ftun_lwip_port_free(void *pointer)
{
  ftun_lwip_alloc_header_t *header;
  ftun_lwip_t *stack;
  ftun_reservation_t *reservation;
  size_t charge;
  if (pointer == NULL) return;
  header = (ftun_lwip_alloc_header_t *)pointer - 1;
  if (header->value.magic != FTUN_LWIP_ALLOC_MAGIC || header->value.stack == NULL) return;
  stack = header->value.stack;
  reservation = header->value.reservation;
  charge = header->value.charge;
  if (stack->allocated_blocks == 0u || stack->allocated_bytes < charge ||
      ftun_reservation_release(&reservation) != FTUN_OK) {
    stack->corrupt = true;
    return;
  }
  stack->allocated_blocks--;
  stack->allocated_bytes -= charge;
  memset(header, 0, sizeof(*header));
  free(header);
}

unsigned int ftun_lwip_port_rand(void)
{
  uint32_t value;
  if (ftun_lwip_active == NULL) return 0x9e3779b9u;
  value = ftun_lwip_active->random_state;
  value ^= value << 13;
  value ^= value >> 17;
  value ^= value << 5;
  if (value == 0u) value = 0x9e3779b9u;
  ftun_lwip_active->random_state = value;
  return value;
}

static void ftun_lwip_notify(ftun_lwip_tcp_t *flow, ftun_lwip_tcp_event_t event,
                             ftun_status_t status)
{
  ftun_lwip_t *stack = flow->stack;
  if (!stack->destroying && stack->tcp_event != NULL) {
    stack->tcp_event(stack->user, flow, event, status);
  }
}

static void ftun_lwip_write_done(ftun_lwip_tcp_t *flow, void *token,
                                 ftun_status_t status)
{
  ftun_lwip_t *stack = flow->stack;
  if (!stack->destroying && token != NULL && stack->tcp_write_done != NULL) {
    stack->tcp_write_done(stack->user, flow, token, status);
  }
}

static void ftun_lwip_release_send_refs(ftun_lwip_tcp_t *flow,
                                        ftun_status_t status)
{
  while (flow->send_head != NULL) {
    ftun_lwip_send_ref_t *reference = flow->send_head;
    size_t bytes = reference->slice.length;
    void *token = reference->token;
    flow->send_head = reference->next;
    if (flow->retained_send_bytes < bytes ||
        flow->stack->retained_send_bytes < bytes) {
      flow->stack->corrupt = true;
      flow->retained_send_bytes = 0u;
      flow->stack->retained_send_bytes = 0u;
    } else {
      flow->retained_send_bytes -= bytes;
      flow->stack->retained_send_bytes -= bytes;
    }
    ftun_lwip_send_release(flow->stack, reference);
    ftun_lwip_write_done(flow, token, status);
  }
  flow->send_tail = NULL;
}

static void ftun_lwip_release_received(ftun_lwip_tcp_t *flow)
{
  if (flow->received != NULL) pbuf_free(flow->received);
  flow->received = NULL;
  if (flow->stack->received_bytes < flow->received_bytes) {
    flow->stack->received_bytes = 0u;
    flow->stack->corrupt = true;
  } else {
    flow->stack->received_bytes -= flow->received_bytes;
  }
  flow->received_bytes = 0u;
}

static void ftun_lwip_unlink_flow(ftun_lwip_tcp_t *flow)
{
  ftun_lwip_tcp_t **cursor;
  ftun_lwip_t *stack = flow->stack;
  if (!flow->linked) return;
  for (cursor = &stack->flows; *cursor != NULL; cursor = &(*cursor)->next) {
    if (*cursor == flow) {
      *cursor = flow->next;
      flow->next = NULL;
      flow->linked = false;
      if (stack->flow_count == 0u) stack->corrupt = true;
      else stack->flow_count--;
      return;
    }
  }
  stack->corrupt = true;
}

static void ftun_lwip_dispose_flow(ftun_lwip_tcp_t *flow, bool abort_pcb)
{
  if (flow->pcb != NULL) {
    struct tcp_pcb *pcb = flow->pcb;
    flow->pcb = NULL;
    tcp_arg(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_sent(pcb, NULL);
    tcp_err(pcb, NULL);
    if (abort_pcb) tcp_abort(pcb);
  }
  ftun_lwip_release_received(flow);
  ftun_lwip_release_send_refs(flow, FTUN_E_CANCELLED);
  ftun_lwip_unlink_flow(flow);
  flow->stack = NULL;
  ftun_lwip_port_free(flow);
}

static err_t ftun_lwip_tcp_received(void *argument, struct tcp_pcb *pcb,
                                    struct pbuf *buffer, err_t error)
{
  ftun_lwip_tcp_t *flow = (ftun_lwip_tcp_t *)argument;
  (void)pcb;
  if (flow == NULL) {
    if (buffer != NULL) pbuf_free(buffer);
    return ERR_ARG;
  }
  if (error != ERR_OK) {
    if (buffer != NULL) pbuf_free(buffer);
    return error;
  }
  if (buffer == NULL) {
    flow->peer_finished = true;
    ftun_lwip_notify(flow, FTUN_LWIP_TCP_PEER_FIN, FTUN_OK);
    return ERR_OK;
  }
  if (SIZE_MAX - flow->received_bytes < buffer->tot_len ||
      SIZE_MAX - flow->stack->received_bytes < buffer->tot_len) {
    pbuf_free(buffer);
    return ERR_MEM;
  }
  if (flow->received == NULL) flow->received = buffer;
  else pbuf_cat(flow->received, buffer);
  flow->received_bytes += buffer->tot_len;
  flow->stack->received_bytes += buffer->tot_len;
  ftun_lwip_notify(flow, FTUN_LWIP_TCP_READABLE, FTUN_OK);
  return ERR_OK;
}

static err_t ftun_lwip_tcp_sent(void *argument, struct tcp_pcb *pcb, u16_t length)
{
  ftun_lwip_tcp_t *flow = (ftun_lwip_tcp_t *)argument;
  size_t remaining = length;
  (void)pcb;
  if (flow == NULL) return ERR_ARG;
  while (remaining != 0u && flow->send_head != NULL) {
    ftun_lwip_send_ref_t *reference = flow->send_head;
    size_t consumed = reference->slice.length < remaining
      ? reference->slice.length : remaining;
    reference->slice.offset += consumed;
    reference->slice.length -= consumed;
    remaining -= consumed;
    flow->retained_send_bytes -= consumed;
    flow->stack->retained_send_bytes -= consumed;
    if (reference->slice.length == 0u) {
      void *token = reference->token;
      flow->send_head = reference->next;
      if (flow->send_head == NULL) flow->send_tail = NULL;
      ftun_lwip_send_release(flow->stack, reference);
      ftun_lwip_write_done(flow, token, FTUN_OK);
    }
  }
  if (remaining != 0u) flow->stack->corrupt = true;
  ftun_lwip_notify(flow, FTUN_LWIP_TCP_WRITABLE,
                   flow->stack->corrupt ? FTUN_E_STATE_CORRUPT : FTUN_OK);
  return ERR_OK;
}

static void ftun_lwip_tcp_error(void *argument, err_t error)
{
  ftun_lwip_tcp_t *flow = (ftun_lwip_tcp_t *)argument;
  if (flow == NULL) return;
  flow->pcb = NULL;
  ftun_lwip_release_received(flow);
  ftun_lwip_release_send_refs(flow, ftun_lwip_from_err(error));
  ftun_lwip_notify(flow, FTUN_LWIP_TCP_CLOSED, ftun_lwip_from_err(error));
}

static void ftun_lwip_endpoint(ftun_endpoint_t *endpoint, const ip_addr_t *address,
                               uint16_t port)
{
  memset(endpoint, 0, sizeof(*endpoint));
  endpoint->kind = FTUN_ADDRESS_IPV4;
  memcpy(endpoint->address, &ip_2_ip4(address)->addr, 4u);
  endpoint->port = port;
}

static void ftun_lwip_udp_unlink(ftun_lwip_udp_t *flow)
{
  ftun_lwip_udp_t **cursor;
  ftun_lwip_t *stack = flow->stack;
  if (!flow->linked) return;
  for (cursor = &stack->udp_flows; *cursor != NULL;
       cursor = &(*cursor)->next) {
    if (*cursor == flow) {
      *cursor = flow->next;
      flow->next = NULL;
      flow->linked = false;
      if (stack->udp_flow_count == 0u) stack->corrupt = true;
      else stack->udp_flow_count--;
      return;
    }
  }
  stack->corrupt = true;
}

static void ftun_lwip_udp_dispose(ftun_lwip_udp_t *flow)
{
  if (flow->pcb != NULL) {
    struct udp_pcb *pcb = flow->pcb;
    flow->pcb = NULL;
    udp_recv(pcb, NULL, NULL);
    udp_remove(pcb);
  }
  ftun_lwip_udp_unlink(flow);
  flow->stack = NULL;
  ftun_lwip_port_free(flow);
}

static void ftun_lwip_udp_drop(void *argument, struct udp_pcb *pcb,
                               struct pbuf *buffer, const ip_addr_t *address,
                               u16_t port)
{
  ftun_lwip_t *stack = (ftun_lwip_t *)argument;
  (void)address;
  (void)port;
  if (buffer != NULL) pbuf_free(buffer);
  if (stack != NULL && stack->input_status == FTUN_OK) {
    stack->input_status = FTUN_E_LIMIT;
  }
  udp_recv(pcb, NULL, NULL);
  udp_remove(pcb);
}

static void ftun_lwip_udp_received(void *argument, struct udp_pcb *pcb,
                                   struct pbuf *buffer,
                                   const ip_addr_t *address, u16_t port)
{
  ftun_lwip_udp_t *flow = (ftun_lwip_udp_t *)argument;
  ftun_lwip_t *stack;
  ftun_buffer_t *owned = NULL;
  ftun_buffer_slice_t slice = {0};
  ftun_packet_t packet = {{0}, 0u};
  uint8_t *data = NULL;
  size_t capacity = 0u;
  size_t length;
  ftun_status_t status;
  (void)pcb;
  (void)address;
  (void)port;
  if (flow == NULL || flow->stack == NULL || buffer == NULL) {
    if (buffer != NULL) pbuf_free(buffer);
    return;
  }
  stack = flow->stack;
  if (flow->reject_status != FTUN_OK) {
    status = flow->reject_status;
    pbuf_free(buffer);
    if (stack->input_status == FTUN_OK) stack->input_status = status;
    ftun_lwip_udp_dispose(flow);
    return;
  }
  length = buffer->tot_len;
  status = ftun_buffer_pool_acquire(stack->packet_pool,
                                    length == 0u ? 1u : length, &owned);
  if (status == FTUN_OK) status = ftun_buffer_data(owned, &data, &capacity);
  if (status == FTUN_OK && capacity < length) status = FTUN_E_STATE_CORRUPT;
  if (status == FTUN_OK && length != 0u &&
      pbuf_copy_partial(buffer, data, (u16_t)length, 0u) != length) {
    status = FTUN_E_STATE_CORRUPT;
  }
  if (status == FTUN_OK) status = ftun_buffer_slice(owned, 0u, length, &slice);
  if (status == FTUN_OK) {
    status = ftun_packet_init(&packet, &slice, stack->packet_source_id);
  }
  (void)ftun_buffer_slice_release(&slice);
  (void)ftun_buffer_release(&owned);
  pbuf_free(buffer);
  if (status == FTUN_OK) {
    status = stack->udp_receive(stack->user, flow, &packet);
    (void)ftun_packet_release(&packet);
  }
  if (status != FTUN_OK && stack->input_status == FTUN_OK) {
    stack->input_status = status;
  }
}

static void ftun_lwip_udp_accept(void *argument, struct udp_pcb *pcb,
                                 struct pbuf *buffer,
                                 const ip_addr_t *address, u16_t port)
{
  ftun_lwip_t *stack = (ftun_lwip_t *)argument;
  ftun_lwip_udp_t *flow;
  ftun_status_t status;
  (void)buffer; /* transparent accept 的首轮回调不得消费该 pbuf。 */
  if (stack == NULL || pcb == NULL || address == NULL || stack->destroying) {
    if (pcb != NULL) udp_recv(pcb, ftun_lwip_udp_drop, stack);
    return;
  }
  flow = (ftun_lwip_udp_t *)ftun_lwip_port_calloc(1u, sizeof(*flow));
  if (flow == NULL) {
    udp_recv(pcb, ftun_lwip_udp_drop, stack);
    return;
  }
  flow->stack = stack;
  flow->pcb = pcb;
  flow->next = stack->udp_flows;
  flow->linked = true;
  stack->udp_flows = flow;
  stack->udp_flow_count++;
  ftun_lwip_endpoint(&flow->source, &pcb->remote_ip, pcb->remote_port);
  ftun_lwip_endpoint(&flow->target, address, port);
  udp_recv(pcb, ftun_lwip_udp_received, flow);
  status = stack->udp_accept(stack->user, flow, &flow->source,
                             &flow->target);
  if (status != FTUN_OK) flow->reject_status = status;
}

static err_t ftun_lwip_tcp_accept(void *argument, struct tcp_pcb *pcb, err_t error)
{
  ftun_lwip_t *stack = (ftun_lwip_t *)argument;
  ftun_lwip_tcp_t *flow;
  ftun_endpoint_t source;
  ftun_endpoint_t target;
  ftun_status_t status;
  if (stack == NULL || pcb == NULL || error != ERR_OK || stack->destroying) {
    if (pcb != NULL) tcp_abort(pcb);
    return ERR_ABRT;
  }
  flow = (ftun_lwip_tcp_t *)ftun_lwip_port_calloc(1u, sizeof(*flow));
  if (flow == NULL) {
    tcp_abort(pcb);
    return ERR_ABRT;
  }
  flow->stack = stack;
  flow->pcb = pcb;
  flow->next = stack->flows;
  flow->linked = true;
  stack->flows = flow;
  stack->flow_count++;
  tcp_arg(pcb, flow);
  tcp_recv(pcb, ftun_lwip_tcp_received);
  tcp_sent(pcb, ftun_lwip_tcp_sent);
  tcp_err(pcb, ftun_lwip_tcp_error);
  tcp_backlog_accepted(pcb);
  ftun_lwip_endpoint(&source, &pcb->remote_ip, pcb->remote_port);
  ftun_lwip_endpoint(&target, &pcb->local_ip, pcb->local_port);
  status = stack->accept(stack->user, flow, &source, &target);
  if (status != FTUN_OK) {
    ftun_lwip_dispose_flow(flow, true);
    return ERR_ABRT;
  }
  return ERR_OK;
}

static err_t ftun_lwip_netif_output(struct netif *netif, struct pbuf *buffer,
                                    const ip4_addr_t *destination)
{
  ftun_lwip_t *stack = (ftun_lwip_t *)netif->state;
  ftun_bytes_t packet;
  ftun_status_t status;
  u16_t copied;
  (void)destination;
  if (stack == NULL || stack->destroying || buffer == NULL ||
      buffer->tot_len == 0u || buffer->tot_len > stack->mtu) return ERR_IF;
  copied = pbuf_copy_partial(buffer, stack->output_buffer, buffer->tot_len, 0u);
  if (copied != buffer->tot_len) return ERR_IF;
  packet.data = stack->output_buffer;
  packet.length = copied;
  status = stack->output(stack->user, packet);
  if (status == FTUN_OK) return ERR_OK;
  if (status == FTUN_E_AGAIN) return ERR_WOULDBLOCK;
  if (status == FTUN_E_LIMIT) return ERR_MEM;
  return ERR_IF;
}

static err_t ftun_lwip_netif_init(struct netif *netif)
{
  netif->output = ftun_lwip_netif_output;
  netif->mtu = (u16_t)((ftun_lwip_t *)netif->state)->mtu;
  netif->name[0] = 'f';
  netif->name[1] = 't';
  return ERR_OK;
}

static void ftun_lwip_input_pbuf_free(struct pbuf *buffer)
{
  ftun_lwip_input_pbuf_t *owned = (ftun_lwip_input_pbuf_t *)buffer;
  ftun_lwip_input_release(owned);
}

static ftun_status_t ftun_lwip_cleanup_create(ftun_lwip_t *stack)
{
  ftun_lwip_t *owned = stack;
  return ftun_lwip_destroy(&owned);
}

ftun_status_t ftun_lwip_create(const ftun_lwip_spec_t *spec, ftun_lwip_t **out)
{
  ftun_lwip_t *stack;
  ftun_reservation_t *reservation = NULL;
  struct tcp_pcb *listener = NULL;
  struct udp_pcb *udp_listener = NULL;
  ip4_addr_t loopback;
  ip4_addr_t any;
  err_t error;
  ftun_status_t pool_status;
  size_t index;
  size_t wrapper_charge;
  if (out != NULL) *out = NULL;
  if (spec == NULL || out == NULL || spec->budget == NULL || spec->output == NULL ||
      (spec->accept == NULL && spec->udp_accept == NULL) ||
      ((spec->udp_accept == NULL) != (spec->udp_receive == NULL)) ||
      spec->mtu < FTUN_LWIP_MIN_MTU ||
      spec->mtu > FTUN_LWIP_MAX_MTU || spec->now_ms > UINT64_MAX - IP_TMR_INTERVAL ||
      ftun_lwip_active != NULL) return FTUN_E_INVALID;
  if (ftun_budget_reserve(spec->budget, sizeof(*stack), &reservation) != FTUN_OK) {
    return FTUN_E_LIMIT;
  }
  stack = (ftun_lwip_t *)calloc(1u, sizeof(*stack));
  if (stack == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  stack->budget = spec->budget;
  stack->reservation = reservation;
  stack->mtu = spec->mtu;
  stack->last_ms = spec->now_ms;
  stack->next_tcp_ms = spec->now_ms + TCP_TMR_INTERVAL;
  stack->next_reassembly_ms = spec->now_ms + IP_TMR_INTERVAL;
  stack->random_state = (uint32_t)(spec->now_ms ^ (spec->now_ms >> 32)) ^ 0xa5a5f00du;
  stack->output = spec->output;
  stack->accept = spec->accept;
  stack->tcp_event = spec->tcp_event;
  stack->tcp_write_done = spec->tcp_write_done;
  stack->udp_accept = spec->udp_accept;
  stack->udp_receive = spec->udp_receive;
  stack->packet_source_id = spec->packet_source_id;
  stack->user = spec->user;
  stack->allocated_bytes = sizeof(*stack);
  stack->allocated_blocks = 1u;
  ftun_lwip_active = stack;
  lwip_init();
  wrapper_charge = FTUN_LWIP_INPUT_POOL_CAPACITY *
      sizeof(*stack->input_storage) +
    FTUN_LWIP_SEND_POOL_CAPACITY * sizeof(*stack->send_storage);
  pool_status = ftun_budget_reserve(stack->budget, wrapper_charge,
                                    &stack->wrapper_reservation);
  if (pool_status == FTUN_OK) {
    stack->input_storage = (ftun_lwip_input_pbuf_t *)calloc(
      FTUN_LWIP_INPUT_POOL_CAPACITY, sizeof(*stack->input_storage));
    stack->send_storage = (ftun_lwip_send_ref_t *)calloc(
      FTUN_LWIP_SEND_POOL_CAPACITY, sizeof(*stack->send_storage));
    if (stack->input_storage == NULL || stack->send_storage == NULL) {
      pool_status = FTUN_E_LIMIT;
    }
  }
  for (index = 0u; pool_status == FTUN_OK &&
       index < FTUN_LWIP_INPUT_POOL_CAPACITY; index++) {
    stack->input_storage[index].free_next = stack->input_free;
    stack->input_free = &stack->input_storage[index];
  }
  for (index = 0u; pool_status == FTUN_OK &&
       index < FTUN_LWIP_SEND_POOL_CAPACITY; index++) {
    stack->send_storage[index].free_next = stack->send_free;
    stack->send_free = &stack->send_storage[index];
  }
  if (pool_status == FTUN_OK) {
    pool_status = ftun_buffer_pool_create(stack->budget,
      FTUN_LWIP_PACKET_POOL_BYTES, FTUN_LWIP_PACKET_POOL_BUFFERS,
      &stack->packet_pool);
  }
  if (pool_status != FTUN_OK) {
    (void)ftun_lwip_cleanup_create(stack);
    return pool_status;
  }
  stack->output_buffer = (uint8_t *)ftun_lwip_port_malloc(stack->mtu);
  if (stack->output_buffer == NULL) {
    (void)ftun_lwip_cleanup_create(stack);
    return FTUN_E_LIMIT;
  }
  if (netif_add_noaddr(&stack->netif, stack, ftun_lwip_netif_init, ip_input) == NULL) {
    (void)ftun_lwip_cleanup_create(stack);
    return FTUN_E_LIMIT;
  }
  stack->netif_added = true;
  ip4_addr_set_loopback(&loopback);
  ip4_addr_set_any(&any);
  netif_set_addr(&stack->netif, &loopback, &any, &any);
  netif_set_up(&stack->netif);
  netif_set_link_up(&stack->netif);
  netif_set_default(&stack->netif);
  netif_set_flags(&stack->netif,
                  (spec->accept != NULL ? NETIF_FLAG_PRETEND_TCP : 0u) |
                  (spec->udp_accept != NULL ? NETIF_FLAG_PRETEND_UDP : 0u));
  if (spec->accept != NULL) {
    listener = tcp_new_ip_type(IPADDR_TYPE_V4);
    if (listener == NULL) {
      (void)ftun_lwip_cleanup_create(stack);
      return FTUN_E_LIMIT;
    }
    tcp_bind_netif(listener, &stack->netif);
    error = tcp_bind(listener, NULL, 0u);
    if (error != ERR_OK) {
      tcp_abort(listener);
      (void)ftun_lwip_cleanup_create(stack);
      return ftun_lwip_from_err(error);
    }
    {
      struct tcp_pcb *listening = tcp_listen_with_backlog_and_err(
        listener, TCP_DEFAULT_LISTEN_BACKLOG, &error);
      if (listening == NULL || error != ERR_OK) {
        tcp_abort(listener);
        (void)ftun_lwip_cleanup_create(stack);
        return error == ERR_OK ? FTUN_E_LIMIT : ftun_lwip_from_err(error);
      }
      listener = listening;
    }
    stack->listener = listener;
    tcp_arg(listener, stack);
    tcp_accept(listener, ftun_lwip_tcp_accept);
  }
  if (spec->udp_accept != NULL) {
    udp_listener = udp_new_ip_type(IPADDR_TYPE_V4);
    if (udp_listener == NULL) {
      (void)ftun_lwip_cleanup_create(stack);
      return FTUN_E_LIMIT;
    }
    udp_bind_netif(udp_listener, &stack->netif);
    error = udp_bind(udp_listener, NULL, 0u);
    if (error != ERR_OK) {
      udp_remove(udp_listener);
      (void)ftun_lwip_cleanup_create(stack);
      return ftun_lwip_from_err(error);
    }
    stack->udp_listener = udp_listener;
    udp_recv(udp_listener, ftun_lwip_udp_accept, stack);
  }
  *out = stack;
  return FTUN_OK;
}

ftun_status_t ftun_lwip_input(ftun_lwip_t *stack, ftun_packet_t *packet)
{
  ftun_lwip_input_pbuf_t *input;
  ftun_bytes_t bytes;
  struct pbuf *buffer;
  err_t error;
  ftun_status_t status;
  if (stack == NULL || packet == NULL || stack != ftun_lwip_active ||
      stack->destroying) return FTUN_E_INVALID;
  status = ftun_packet_view(packet, &bytes);
  if (status != FTUN_OK) return status;
  if (bytes.length < 20u || bytes.length > stack->mtu || bytes.length > UINT16_MAX ||
      (bytes.data[0] >> 4) != 4u) return FTUN_E_PROTOCOL;
  input = ftun_lwip_input_acquire(stack);
  if (input == NULL) return FTUN_E_LIMIT;
  status = ftun_buffer_slice_clone(&packet->payload, &input->slice);
  if (status != FTUN_OK) {
    ftun_lwip_input_release(input);
    return status;
  }
  input->custom.custom_free_function = ftun_lwip_input_pbuf_free;
  buffer = pbuf_alloced_custom(PBUF_RAW, (u16_t)bytes.length, PBUF_REF,
                               &input->custom, (void *)bytes.data,
                               (u16_t)bytes.length);
  if (buffer == NULL) {
    ftun_lwip_input_release(input);
    return FTUN_E_LIMIT;
  }
  stack->input_status = FTUN_OK;
  error = stack->netif.input(buffer, &stack->netif);
  if (error != ERR_OK) pbuf_free(buffer);
  if (stack->corrupt) return FTUN_E_STATE_CORRUPT;
  if (error == ERR_OK && stack->input_status != FTUN_OK) {
    return stack->input_status;
  }
  return ftun_lwip_from_err(error);
}

ftun_status_t ftun_lwip_tick(ftun_lwip_t *stack, uint64_t now_ms)
{
  unsigned int catchup = 0u;
  if (stack == NULL || stack != ftun_lwip_active || stack->destroying ||
      now_ms < stack->last_ms) return FTUN_E_INVALID;
  stack->last_ms = now_ms;
  while (now_ms >= stack->next_tcp_ms) {
    if (catchup++ == FTUN_LWIP_MAX_TIMER_CATCHUP) return FTUN_E_LIMIT;
    tcp_tmr();
    stack->tcp_timer_ticks++;
    if (stack->next_tcp_ms > UINT64_MAX - TCP_TMR_INTERVAL) {
      stack->next_tcp_ms = UINT64_MAX;
      break;
    }
    stack->next_tcp_ms += TCP_TMR_INTERVAL;
  }
  catchup = 0u;
  while (now_ms >= stack->next_reassembly_ms) {
    if (catchup++ == FTUN_LWIP_MAX_TIMER_CATCHUP) return FTUN_E_LIMIT;
    ip_reass_tmr();
    stack->reassembly_timer_ticks++;
    if (stack->next_reassembly_ms > UINT64_MAX - IP_TMR_INTERVAL) {
      stack->next_reassembly_ms = UINT64_MAX;
      break;
    }
    stack->next_reassembly_ms += IP_TMR_INTERVAL;
  }
  return stack->corrupt ? FTUN_E_STATE_CORRUPT : FTUN_OK;
}

ftun_status_t ftun_lwip_set_packet_source(ftun_lwip_t *stack,
                                          uint32_t packet_source_id)
{
  if (stack == NULL || stack != ftun_lwip_active || packet_source_id == 0u ||
      stack->destroying || stack->corrupt) return FTUN_E_INVALID;
  stack->packet_source_id = packet_source_id;
  return FTUN_OK;
}

ftun_status_t ftun_lwip_get_usage(const ftun_lwip_t *stack,
                                  ftun_lwip_usage_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (stack == NULL || out == NULL) return FTUN_E_INVALID;
  out->allocated_bytes = stack->allocated_bytes;
  out->allocated_blocks = stack->allocated_blocks;
  out->tcp_flows = stack->flow_count;
  out->udp_flows = stack->udp_flow_count;
  out->received_bytes = stack->received_bytes;
  out->retained_send_bytes = stack->retained_send_bytes;
  out->tcp_timer_ticks = stack->tcp_timer_ticks;
  out->reassembly_timer_ticks = stack->reassembly_timer_ticks;
  return stack->corrupt ? FTUN_E_STATE_CORRUPT : FTUN_OK;
}

ftun_status_t ftun_lwip_tcp_peek(ftun_lwip_tcp_t *flow,
                                 ftun_lwip_segment_t *segments,
                                 size_t segment_capacity, size_t *segment_count,
                                 size_t *available, bool *peer_finished)
{
  struct pbuf *buffer;
  size_t count = 0u;
  if (segment_count != NULL) *segment_count = 0u;
  if (available != NULL) *available = 0u;
  if (peer_finished != NULL) *peer_finished = false;
  if (flow == NULL || segment_count == NULL || available == NULL ||
      peer_finished == NULL || (segment_capacity != 0u && segments == NULL) ||
      flow->stack == NULL) return FTUN_E_INVALID;
  for (buffer = flow->received; buffer != NULL && count < segment_capacity;
       buffer = buffer->next) {
    segments[count].data = (const uint8_t *)buffer->payload;
    segments[count].length = buffer->len;
    count++;
  }
  *segment_count = count;
  *available = flow->received_bytes;
  *peer_finished = flow->peer_finished;
  return FTUN_OK;
}

ftun_status_t ftun_lwip_tcp_consume(ftun_lwip_tcp_t *flow, size_t bytes)
{
  size_t remaining = bytes;
  if (flow == NULL || flow->stack == NULL || bytes == 0u ||
      bytes > flow->received_bytes) return FTUN_E_INVALID;
  while (remaining != 0u) {
    u16_t chunk = remaining > UINT16_MAX ? UINT16_MAX : (u16_t)remaining;
    flow->received = pbuf_free_header(flow->received, chunk);
    if (flow->pcb != NULL) tcp_recved(flow->pcb, chunk);
    remaining -= chunk;
  }
  flow->received_bytes -= bytes;
  flow->stack->received_bytes -= bytes;
  return flow->stack->corrupt ? FTUN_E_STATE_CORRUPT : FTUN_OK;
}

ftun_status_t ftun_lwip_tcp_ready(const ftun_lwip_tcp_t *flow,
                                  bool *readable, bool *writable)
{
  if (readable != NULL) *readable = false;
  if (writable != NULL) *writable = false;
  if (flow == NULL || flow->stack == NULL || readable == NULL ||
      writable == NULL) return FTUN_E_INVALID;
  *readable = flow->received_bytes != 0u || flow->peer_finished;
  *writable = flow->pcb != NULL && tcp_sndbuf(flow->pcb) != 0u &&
              flow->stack->send_free != NULL;
  return flow->stack->corrupt ? FTUN_E_STATE_CORRUPT : FTUN_OK;
}

ftun_status_t ftun_lwip_tcp_write_ref_with_token(
  ftun_lwip_tcp_t *flow, const ftun_buffer_slice_t *slice, void *token,
  size_t *accepted)
{
  ftun_lwip_send_ref_t *reference;
  ftun_bytes_t bytes;
  size_t length;
  err_t error;
  ftun_status_t status;
  if (accepted != NULL) *accepted = 0u;
  if (flow == NULL || slice == NULL || accepted == NULL || flow->stack == NULL ||
      flow->pcb == NULL) return FTUN_E_INVALID;
  status = ftun_buffer_slice_data(slice, &bytes);
  if (status != FTUN_OK || bytes.length == 0u) return FTUN_E_INVALID;
  length = tcp_sndbuf(flow->pcb);
  if (length > bytes.length) length = bytes.length;
  if (length > UINT16_MAX) length = UINT16_MAX;
  if (length == 0u) return FTUN_E_AGAIN;
  reference = ftun_lwip_send_acquire(flow->stack);
  if (reference == NULL) return FTUN_E_LIMIT;
  status = ftun_buffer_slice_clone(slice, &reference->slice);
  if (status != FTUN_OK) {
    ftun_lwip_send_release(flow->stack, reference);
    return status;
  }
  reference->slice.length = length;
  reference->token = token;
  error = tcp_write(flow->pcb, bytes.data, (u16_t)length, 0u);
  if (error != ERR_OK) {
    ftun_lwip_send_release(flow->stack, reference);
    return error == ERR_MEM ? FTUN_E_AGAIN : ftun_lwip_from_err(error);
  }
  if (flow->send_tail != NULL) flow->send_tail->next = reference;
  else flow->send_head = reference;
  flow->send_tail = reference;
  flow->retained_send_bytes += length;
  flow->stack->retained_send_bytes += length;
  *accepted = length;
  (void)tcp_output(flow->pcb);
  return FTUN_OK;
}

ftun_status_t ftun_lwip_tcp_write_ref(ftun_lwip_tcp_t *flow,
                                      const ftun_buffer_slice_t *slice,
                                      size_t *accepted)
{
  return ftun_lwip_tcp_write_ref_with_token(flow, slice, NULL, accepted);
}

ftun_status_t ftun_lwip_tcp_shutdown_write(ftun_lwip_tcp_t *flow)
{
  if (flow == NULL || flow->stack == NULL || flow->pcb == NULL) {
    return FTUN_E_INVALID;
  }
  return ftun_lwip_from_err(tcp_shutdown(flow->pcb, 0, 1));
}

ftun_status_t ftun_lwip_tcp_close(ftun_lwip_tcp_t **flow)
{
  ftun_lwip_tcp_t *owned;
  ftun_lwip_t *stack;
  if (flow == NULL) return FTUN_E_INVALID;
  owned = *flow;
  if (owned == NULL) return FTUN_OK;
  if (owned->stack == NULL || owned->stack != ftun_lwip_active) {
    return FTUN_E_STALE;
  }
  stack = owned->stack;
  *flow = NULL;
  ftun_lwip_dispose_flow(owned, true);
  return stack->corrupt ? FTUN_E_STATE_CORRUPT : FTUN_OK;
}

ftun_status_t ftun_lwip_udp_send(ftun_lwip_udp_t *flow,
                                 const ftun_packet_t *packet)
{
  ftun_bytes_t bytes;
  struct pbuf *buffer;
  err_t error;
  ftun_status_t status;
  if (flow == NULL || packet == NULL || flow->stack == NULL ||
      flow->stack != ftun_lwip_active || flow->pcb == NULL ||
      flow->stack->destroying) return FTUN_E_INVALID;
  status = ftun_packet_view(packet, &bytes);
  if (status != FTUN_OK) return status;
  if (bytes.length > UINT16_MAX || bytes.length + 28u > flow->stack->mtu) {
    return FTUN_E_LIMIT;
  }
  buffer = pbuf_alloc(PBUF_TRANSPORT, (u16_t)bytes.length, PBUF_RAM);
  if (buffer == NULL) return FTUN_E_LIMIT;
  if (bytes.length != 0u && pbuf_take(buffer, bytes.data,
                                      (u16_t)bytes.length) != ERR_OK) {
    pbuf_free(buffer);
    return FTUN_E_STATE_CORRUPT;
  }
  error = udp_send(flow->pcb, buffer);
  pbuf_free(buffer);
  if (flow->stack->corrupt) return FTUN_E_STATE_CORRUPT;
  return ftun_lwip_from_err(error);
}

ftun_status_t ftun_lwip_udp_close(ftun_lwip_udp_t **flow)
{
  ftun_lwip_udp_t *owned;
  ftun_lwip_t *stack;
  if (flow == NULL) return FTUN_E_INVALID;
  owned = *flow;
  if (owned == NULL) return FTUN_OK;
  if (owned->stack == NULL || owned->stack != ftun_lwip_active) {
    return FTUN_E_STALE;
  }
  stack = owned->stack;
  *flow = NULL;
  ftun_lwip_udp_dispose(owned);
  return stack->corrupt ? FTUN_E_STATE_CORRUPT : FTUN_OK;
}

ftun_status_t ftun_lwip_destroy(ftun_lwip_t **stack)
{
  ftun_lwip_t *owned;
  ftun_reservation_t *reservation;
  bool corrupt;
  if (stack == NULL) return FTUN_E_INVALID;
  owned = *stack;
  if (owned == NULL) return FTUN_OK;
  if (owned != ftun_lwip_active) return FTUN_E_STALE;
  owned->destroying = true;
  if (owned->listener != NULL) {
    struct tcp_pcb *listener = owned->listener;
    err_t error;
    owned->listener = NULL;
    tcp_arg(listener, NULL);
    tcp_accept(listener, NULL);
    error = tcp_close(listener);
    if (error != ERR_OK) tcp_abort(listener);
  }
  while (owned->flows != NULL) ftun_lwip_dispose_flow(owned->flows, true);
  if (owned->udp_listener != NULL) {
    struct udp_pcb *listener = owned->udp_listener;
    owned->udp_listener = NULL;
    udp_recv(listener, NULL, NULL);
    udp_remove(listener);
  }
  while (owned->udp_flows != NULL) {
    ftun_lwip_udp_dispose(owned->udp_flows);
  }
  udp_fini();
  ip_reass_fini();
  if (owned->netif_added) {
    netif_remove(&owned->netif);
    owned->netif_added = false;
  }
  ftun_lwip_port_free(owned->output_buffer);
  owned->output_buffer = NULL;
  if (owned->input_active != 0u || owned->send_active != 0u) {
    owned->corrupt = true;
  }
  if (owned->packet_pool != NULL &&
      ftun_buffer_pool_destroy(&owned->packet_pool) != FTUN_OK) {
    owned->corrupt = true;
  }
  free(owned->input_storage);
  free(owned->send_storage);
  owned->input_storage = NULL;
  owned->send_storage = NULL;
  owned->input_free = NULL;
  owned->send_free = NULL;
  if (ftun_reservation_release(&owned->wrapper_reservation) != FTUN_OK) {
    owned->corrupt = true;
  }
  if (owned->allocated_blocks != 1u || owned->allocated_bytes != sizeof(*owned)) {
    owned->corrupt = true;
  }
  corrupt = owned->corrupt;
  reservation = owned->reservation;
  if (ftun_reservation_release(&reservation) != FTUN_OK) return FTUN_E_STATE_CORRUPT;
  owned->reservation = NULL;
  owned->allocated_blocks = 0u;
  owned->allocated_bytes = 0u;
  ftun_lwip_active = NULL;
  free(owned);
  *stack = NULL;
  return corrupt ? FTUN_E_STATE_CORRUPT : FTUN_OK;
}
