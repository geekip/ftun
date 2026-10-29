#include "proxy/protocol/socks5.h"
#include "proxy/protocol/socks5_client.h"

typedef struct { ftun_socks5_client_t client; ftun_endpoint_t peer; } state_t;

static ftun_status_t init(void *state, const ftun_transport_protocol_options_t *options)
{
  state_t *owned = state;
  ftun_socks5_client_options_t request = {0};
  owned->peer = options->peer;
  request.username = options->username;
  request.password = options->password;
  request.target = options->target;
  request.command = options->datagram ? FTUN_SOCKS5_COMMAND_UDP_ASSOCIATE : FTUN_SOCKS5_COMMAND_CONNECT;
  return ftun_socks5_client_init(&owned->client, &request);
}
static bool wants_output(const void *state) { return ftun_socks5_client_wants_output(&((const state_t *)state)->client); }
static ftun_status_t output(const void *state, uint8_t *buffer, size_t capacity, size_t *length)
{ return ftun_socks5_client_output(&((const state_t *)state)->client, buffer, capacity, length); }
static ftun_status_t output_done(void *state) { return ftun_socks5_client_output_done(&((state_t *)state)->client); }
static size_t needed(const void *state) { return ftun_socks5_client_needed(&((const state_t *)state)->client); }
static ftun_status_t input(void *state, ftun_bytes_t wire, size_t *consumed, ftun_endpoint_t *bound)
{
  state_t *owned = state;
  ftun_socks5_client_result_t result;
  ftun_status_t status = ftun_socks5_client_input(&owned->client, wire, consumed, &result);
  if (status == FTUN_OK) {
    *bound = result.bound;
    if (owned->client.options.command == FTUN_SOCKS5_COMMAND_UDP_ASSOCIATE &&
        bound->kind == FTUN_ADDRESS_IPV4 && bound->address[0] == 0u &&
        bound->address[1] == 0u && bound->address[2] == 0u && bound->address[3] == 0u) {
      size_t i;
      for (i = 0u; i < 4u; i++) bound->address[i] = owned->peer.address[i];
    }
  }
  return status;
}
static ftun_status_t decode_datagram(ftun_bytes_t wire, ftun_transport_datagram_t *out, size_t *consumed)
{
  ftun_socks5_udp_datagram_t datagram;
  ftun_status_t status = ftun_socks5_decode_udp_datagram(wire, &datagram, consumed);
  if (status == FTUN_OK) { out->endpoint = datagram.endpoint; out->payload = datagram.payload; }
  return status;
}
static ftun_status_t run(const ftun_transport_protocol_options_t *options,
  const ftun_transport_protocol_io_t *io)
{
  state_t state;
  ftun_socks5_client_result_t result;
  ftun_socks5_client_io_t transport = {io->write_all, io->read_exact, io->context};
  ftun_status_t status = init(&state, options);
  if (status == FTUN_OK) status = ftun_socks5_client_run(&state.client, &transport, &result);
  return status;
}
const ftun_transport_protocol_t ftun_socks5_protocol = {
  sizeof(state_t), init, wants_output, output, output_done, needed, input,
  ftun_socks5_encode_udp_datagram, decode_datagram, run
};
