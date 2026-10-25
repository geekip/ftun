#include "transport/control_channel.h"
#include "util/time.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "control datagram failed %d: %s\n", __LINE__, #x); return 1; } } while (0)

typedef struct {
  ftun_datagram_t *datagram;
  ftun_datagram_send_token_t pending;
  ftun_path_t *path;
  ftun_path_completion_fn completion;
  void *user;
  unsigned int cancelled, destroyed, resumed, sent;
  bool hold, physical;
} fixture_t;
static fixture_t fixture;

static ftun_status_t send_packet(void *user, ftun_datagram_send_token_t token,
  const ftun_endpoint_t *target, const ftun_packet_t *packet)
{
  (void)user;
  fixture.sent++;
  if (fixture.hold) {
    fixture.pending = token;
    return FTUN_OK;
  }
  if (ftun_datagram_deliver(fixture.datagram, target, packet) != FTUN_OK) {
    return FTUN_E_AGAIN;
  }
  return ftun_datagram_send_complete(token, (ftun_error_t){FTUN_OK, 0u, 0});
}

static ftun_status_t cancel_packet(void *user, ftun_datagram_send_token_t token)
{
  (void)user;
  (void)token;
  fixture.cancelled++;
  return FTUN_E_AGAIN;
}

static void destroy(void *user)
{
  (void)user;
  fixture.destroyed++;
}

static ftun_status_t resume(void *user)
{
  (void)user;
  fixture.resumed++;
  return FTUN_OK;
}

static void opened(ftun_operation_t *operation, ftun_error_t error, void *user)
{
  fixture_t *state = user;
  state->completion(operation, error, state->path, state->user);
}

ftun_status_t __real_ftun_socket_path_open(void *context, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *spec,
  ftun_operation_t **out);

ftun_status_t __wrap_ftun_socket_path_open(void *context, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *spec,
  ftun_operation_t **out)
{
  ftun_datagram_options_t options = request->datagram;
  ftun_datagram_backend_t backend = {0};
  ftun_path_spec_t result = *spec;
  ftun_datagram_t *datagram = NULL;
  ftun_operation_token_t token;
  ftun_status_t status;
  if (fixture.physical) {
    return __real_ftun_socket_path_open(context, core, request, spec, out);
  }
  if (request->dial.transport != FTUN_DIAL_UDP ||
      spec->configuration_generation != 7u ||
      spec->purpose != FTUN_DIAL_PURPOSE_PROBE ||
      options.max_pending_packets != 1u) return FTUN_E_INVALID;
  backend.send_start = send_packet;
  backend.send_cancel = cancel_packet;
  backend.destroy = destroy;
  options.budget = request->dial.budget;
  status = ftun_datagram_create(&options, &backend, &datagram);
  if (status != FTUN_OK) return status;
  fixture.datagram = datagram;
  result.driver.resume = resume;
  status = ftun_path_adopt_datagram(&result, &datagram, &fixture.path);
  if (status != FTUN_OK) return status;
  fixture.completion = request->completion;
  fixture.user = request->user;
  status = ftun_operation_accept(request->dial.operations, opened, &fixture,
    out, &token);
  if (status != FTUN_OK) return status;
  return ftun_operation_complete(token, (ftun_error_t){FTUN_OK, 0u, 0});
}

static ftun_status_t receive(ftun_control_channel_t *channel,
  ftun_endpoint_t *source, uint8_t *data, size_t capacity, size_t *length)
{
  for (;;) {
    ftun_status_t status = ftun_control_channel_receive(channel, source, data,
      capacity, length);
    if (status != FTUN_E_AGAIN) return status;
    status = ftun_control_channel_wait(channel);
    if (status != FTUN_OK) return status;
  }
}

static int run(bool hold, unsigned int port)
{
  ftun_budget_t *budget = NULL;
  ftun_control_channel_t *channel = NULL;
  ftun_endpoint_t peer = {0}, source;
  ftun_budget_usage_t before, after;
  ftun_reservation_t *pressure = NULL;
  uint64_t now;
  uint8_t data[4] = {0};
  size_t length = 99u;
  memset(&fixture, 0, sizeof(fixture));
  fixture.hold = hold;
  fixture.physical = port != 0u;
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 128u, &budget) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &before) == FTUN_OK);
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  CHECK(ftun_control_channel_create(budget, 7u, now + (hold ? 20u : 1500u), &channel) == FTUN_OK);
  peer.kind = FTUN_ADDRESS_IPV4;
  peer.address[0] = 127u;
  peer.address[3] = 1u;
  peer.port = (uint16_t)(port == 0u ? 53u : port);
  CHECK(ftun_control_channel_connect_datagram(channel, &peer, 0u, FTUN_DIAL_PURPOSE_PROBE) == FTUN_OK);
  CHECK(ftun_control_channel_read(channel, data, sizeof(data), &length) == FTUN_E_INVALID);
  CHECK(ftun_control_channel_receive(channel, &source, data, sizeof(data), &length) == FTUN_E_AGAIN && length == 0u);
  CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK);
  CHECK(ftun_budget_reserve(budget, after.normal_available, &pressure) == FTUN_OK);
  CHECK(ftun_control_channel_send(channel, &peer, (const uint8_t *)"pressure", 8u) == FTUN_E_LIMIT);
  CHECK(ftun_reservation_release(&pressure) == FTUN_OK && fixture.sent == 0u);
  CHECK(ftun_control_channel_send(channel, &peer, data, 65537u) == FTUN_E_LIMIT);
  CHECK(ftun_control_channel_send(channel, &peer, (const uint8_t *)"abc", 3u) == (hold ? FTUN_E_TIMEOUT : FTUN_OK));
  if (hold) {
    CHECK(ftun_control_channel_close(&channel) == FTUN_E_AGAIN && channel != NULL);
    CHECK(fixture.cancelled != 0u && fixture.destroyed == 0u && fixture.sent == 1u);
    CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK && after.used != 0u);
    CHECK(ftun_datagram_send_complete(fixture.pending, (ftun_error_t){FTUN_E_CANCELLED, 0u, 0}) == FTUN_OK);
  } else {
    CHECK(receive(channel, &source, data, sizeof(data), &length) == FTUN_OK);
    CHECK(length == 3u && memcmp(data, "abc", 3u) == 0);
    CHECK(source.kind == peer.kind && source.port == peer.port && memcmp(source.address, peer.address, 4u) == 0);
    CHECK(ftun_control_channel_send(channel, &peer, NULL, 0u) == FTUN_OK);
    CHECK(receive(channel, &source, data, sizeof(data), &length) == FTUN_OK && length == 0u);
    CHECK(ftun_control_channel_send(channel, &peer, (const uint8_t *)"oversize", 8u) == FTUN_OK);
    memset(data, 0xa5, sizeof(data));
    CHECK(receive(channel, &source, data, sizeof(data), &length) == FTUN_E_LIMIT && length == 0u);
    CHECK(data[0] == 0xa5u && source.port == 0u);
    CHECK(ftun_control_channel_send(channel, &peer, (const uint8_t *)"next", 4u) == FTUN_OK);
    CHECK(receive(channel, &source, data, sizeof(data), &length) == FTUN_OK && length == 4u && memcmp(data, "next", 4u) == 0);
    if (!fixture.physical) {
      CHECK(fixture.sent == 4u && fixture.resumed == 4u);
      /* 保留未消费的接收引用，验证 close 仍能回收整个预算。 */
      CHECK(ftun_control_channel_send(channel, &peer, (const uint8_t *)"held", 4u) == FTUN_OK);
      CHECK(ftun_control_channel_send(channel, &peer, (const uint8_t *)"drop", 4u) == FTUN_E_AGAIN);
    } else {
      unsigned int index;
      CHECK(ftun_control_channel_send(channel, &peer, (const uint8_t *)"burst", 5u) == FTUN_OK);
      for (index = 0u; index < 3u; index++) {
        CHECK(receive(channel, &source, data, sizeof(data), &length) == FTUN_OK);
        CHECK(length == 1u && data[0] == (uint8_t)index);
      }
      CHECK(receive(channel, &source, data, sizeof(data), &length) == FTUN_E_TIMEOUT && length == 0u);
    }
  }
  CHECK(ftun_control_channel_close(&channel) == FTUN_OK && channel == NULL);
  CHECK(fixture.physical || fixture.destroyed == 1u);
  CHECK(ftun_budget_get_usage(budget, &after) == FTUN_OK);
  CHECK(after.used == before.used && after.metadata_bytes == before.metadata_bytes && after.used_resources.descriptors == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

int main(int argc, char **argv)
{
  if (argc == 2) return run(false, (unsigned int)strtoul(argv[1], NULL, 10));
  CHECK(argc == 1);
  CHECK(run(false, 0u) == 0);
  CHECK(run(true, 0u) == 0);
  puts("control datagram memory and cancellation tests passed");
  return 0;
}
