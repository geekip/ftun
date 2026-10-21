#ifndef FTUN_TUN_INTERNAL_H
#define FTUN_TUN_INTERNAL_H

#include "tun/service.h"

#define FTUN_TUN_IPV4_MIN_MTU 68u
#define FTUN_TUN_FEEDBACK_BURST 4u
#define FTUN_TUN_FEEDBACK_PROGRESS 64u

typedef struct {
  ftun_buffer_t *buffer;
  size_t length;
  uint64_t lease_generation;
  uint64_t path_generation;
} ftun_tun_service_packet_t;

typedef struct ftun_tun_service_consumer {
  ftun_tun_consumer_t consumer;
  ftun_tun_route_t route;
  ftun_tun_path_t path;
  ftun_tun_lease_t lease;
  ftun_tun_service_packet_t *input;
  ftun_tun_service_packet_t *output;
  size_t input_head;
  size_t input_count;
  size_t input_bytes;
  size_t output_head;
  size_t output_count;
  size_t output_bytes;
  size_t packets_received;
  size_t packets_written;
  size_t packets_dropped;
  size_t malformed_packets;
  size_t oversized_packets;
  size_t fragments_rejected;
  size_t sources_rejected;
  size_t feedback_sent;
  size_t feedback_suppressed;
  size_t feedback_progress;
  uint64_t path_generation;
  uint32_t inner_mtu;
  uint8_t feedback_tokens;
  bool blocked;
  bool dispatch_ready;
} ftun_tun_service_consumer_t;

typedef struct {
  size_t header_length;
  uint16_t fragment;
  uint8_t protocol;
  uint8_t source[4];
  uint8_t destination[4];
  bool dont_fragment;
  bool fragmented;
} ftun_tun_ipv4_t;

struct ftun_tun_service {
  ftun_core_t *core;
  ftun_budget_t *budget;
  ftun_reservation_t *reservation;
  ftun_event_loop_t *loop;
  ftun_buffer_pool_t *buffers;
  ftun_tun_device_ops_t ops;
  ftun_packet_port_t *port;
  ftun_event_source_t *source;
  ftun_packet_port_info_t info;
  ftun_tun_service_consumer_t *consumers;
  ftun_tun_service_packet_t *input_entries;
  ftun_tun_service_packet_t *output_entries;
  uint8_t *input;
  char device_name[FTUN_PACKET_PORT_NAME_BYTES];
  uint32_t mtu;
  size_t consumer_capacity;
  size_t input_capacity;
  size_t output_capacity;
  size_t consumer_quota;
  size_t read_quota;
  size_t write_quota;
  size_t active_leases;
  size_t queued_inputs;
  size_t queued_input_bytes;
  size_t queued_outputs;
  size_t queued_output_bytes;
  size_t dispatch_cursor;
  size_t output_cursor;
  size_t packets_read;
  size_t packets_written;
  size_t packets_dropped;
  size_t packet_errors;
  size_t feedback_sent;
  size_t feedback_suppressed;
  uint64_t device_generation;
  uint64_t next_lease_generation;
  uint32_t events;
  bool accepting;
};

ftun_tun_service_consumer_t *ftun_tun_service_lease_consumer(
  const ftun_tun_service_t *service, ftun_tun_lease_t lease);
ftun_status_t ftun_tun_service_interests(ftun_tun_service_t *service);
ftun_status_t ftun_tun_service_consumer_clear(
  ftun_tun_service_t *service, ftun_tun_service_consumer_t *consumer);

uint32_t ftun_tun_service_ipv4_value(const uint8_t address[4]);
ftun_tun_service_consumer_t *ftun_tun_service_route(
  ftun_tun_service_t *service, ftun_bytes_t packet);

int ftun_tun_service_path_valid(
  const ftun_tun_service_t *service, const ftun_tun_route_t *route,
  const ftun_tun_path_t *path, uint32_t *inner_mtu);
int ftun_tun_service_path_equal(const ftun_tun_path_t *left,
                                const ftun_tun_path_t *right);
ftun_status_t ftun_tun_service_check_packet(
  ftun_tun_service_t *service, ftun_tun_service_consumer_t *consumer,
  ftun_tun_packet_direction_t direction, ftun_bytes_t packet, bool *drop);
void ftun_tun_service_packet_progress(ftun_tun_service_consumer_t *consumer);

void ftun_tun_service_drop(ftun_tun_service_t *service,
                           ftun_tun_service_consumer_t *consumer);
void ftun_tun_service_increment(size_t *value);
void ftun_tun_service_broadcast(ftun_tun_service_t *service,
                                ftun_tun_service_event_t event,
                                ftun_status_t status);

#endif
