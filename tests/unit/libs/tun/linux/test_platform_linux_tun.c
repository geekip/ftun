#define _GNU_SOURCE 1
#include "platform/linux/tun.h"
#include "libs/tun/port.h"
#include "platform/linux/uapi.h"
#include "core/limits.h"
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "linux tun contract failed: %s\n", #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  int open_device_calls;
  int open_control_calls;
  int ioctl_calls;
  int read_calls;
  int write_calls;
  int close_calls;
  int device_close_calls;
  int control_close_calls;
  int fail_stage;
  int fail_error;
  int eintr_stage;
  int eintr_done;
  int device_flags;
  int control_domain;
  int control_type;
  unsigned long requests[8];
  short tun_flags;
  short up_flags;
  int configured_mtu;
  int read_error;
  int read_eintr_once;
  ptrdiff_t read_result;
  uint8_t read_data[64];
  int write_error;
  int write_eintr_once;
  ptrdiff_t write_result;
  uint8_t written[64];
  size_t written_length;
} mock_state_t;

static int mock_should_fail(mock_state_t *state, int stage, int *error_code)
{
  if (state->eintr_stage == stage && !state->eintr_done) {
    state->eintr_done = 1;
    *error_code = EINTR;
    return 1;
  }
  if (state->fail_stage == stage) {
    *error_code = state->fail_error;
    return 1;
  }
  return 0;
}

static int mock_open_device(void *context, const char *path, int flags,
                            int *error_code)
{
  mock_state_t *state = (mock_state_t *)context;
  state->open_device_calls++;
  if (strcmp(path, "/dev/net/tun") != 0) {
    *error_code = ENOENT;
    return -1;
  }
  state->device_flags = flags;
  if (mock_should_fail(state, 1, error_code)) return -1;
  return 41;
}

static int mock_open_control(void *context, int domain, int type, int protocol,
                             int *error_code)
{
  mock_state_t *state = (mock_state_t *)context;
  (void)protocol;
  state->open_control_calls++;
  state->control_domain = domain;
  state->control_type = type;
  if (mock_should_fail(state, 3, error_code)) return -1;
  return 42;
}

static int mock_ioctl(void *context, int descriptor, unsigned long request,
                      void *argument, int *error_code)
{
  mock_state_t *state = (mock_state_t *)context;
  struct ifreq *interface_request = (struct ifreq *)argument;
  int stage;
  (void)descriptor;
  if (state->ioctl_calls >= (int)(sizeof(state->requests) /
                                  sizeof(state->requests[0]))) {
    *error_code = EIO;
    return -1;
  }
  state->requests[state->ioctl_calls] = request;
  state->ioctl_calls++;
  if (request == FTUN_TUNSETIFF) {
    stage = 2;
    state->tun_flags = interface_request->ifr_flags;
  } else if (request == SIOCSIFMTU) {
    stage = 4;
    state->configured_mtu = interface_request->ifr_mtu;
  } else if (request == SIOCGIFFLAGS) {
    stage = 5;
    interface_request->ifr_flags = (short)IFF_MULTICAST;
  } else if (request == SIOCSIFFLAGS) {
    stage = 6;
    state->up_flags = interface_request->ifr_flags;
  } else {
    *error_code = EINVAL;
    return -1;
  }
  if (mock_should_fail(state, stage, error_code)) return -1;
  return 0;
}

static ptrdiff_t mock_read(void *context, int descriptor, void *buffer,
                           size_t capacity, int *error_code)
{
  mock_state_t *state = (mock_state_t *)context;
  (void)descriptor;
  state->read_calls++;
  if (state->read_eintr_once) {
    state->read_eintr_once = 0;
    *error_code = EINTR;
    return -1;
  }
  if (state->read_error != 0) {
    *error_code = state->read_error;
    return -1;
  }
  if (state->read_result > 0 && (size_t)state->read_result <= capacity &&
      (size_t)state->read_result <= sizeof(state->read_data)) {
    memcpy(buffer, state->read_data, (size_t)state->read_result);
  }
  return state->read_result;
}

static ptrdiff_t mock_write(void *context, int descriptor, const void *packet,
                            size_t length, int *error_code)
{
  mock_state_t *state = (mock_state_t *)context;
  (void)descriptor;
  state->write_calls++;
  if (state->write_eintr_once) {
    state->write_eintr_once = 0;
    *error_code = EINTR;
    return -1;
  }
  if (state->write_error != 0) {
    *error_code = state->write_error;
    return -1;
  }
  state->written_length = length < sizeof(state->written) ? length : 0u;
  if (state->written_length != 0u) {
    memcpy(state->written, packet, state->written_length);
  }
  return state->write_result >= 0 ? state->write_result : (ptrdiff_t)length;
}

static int mock_close(void *context, int descriptor, int *error_code)
{
  mock_state_t *state = (mock_state_t *)context;
  state->close_calls++;
  if (descriptor == 41) state->device_close_calls++;
  if (descriptor == 42) state->control_close_calls++;
  if ((descriptor == 42 && state->fail_stage == 7) ||
      (descriptor == 41 && state->fail_stage == 8)) {
    *error_code = state->fail_error;
    return -1;
  }
  return 0;
}

static ftun_platform_tun_io_t mock_io(mock_state_t *state)
{
  ftun_platform_tun_io_t io;
  io.open_device = mock_open_device;
  io.open_control = mock_open_control;
  io.ioctl_call = mock_ioctl;
  io.read_call = mock_read;
  io.write_call = mock_write;
  io.close_call = mock_close;
  io.context = state;
  return io;
}

static ftun_tun_spec_t test_spec(const char *name, uint32_t mtu)
{
  ftun_tun_spec_t spec;
  spec.name.data = name;
  spec.name.length = name == NULL ? 0u : strlen(name);
  spec.mtu = mtu;
  return spec;
}

static int check_open_failures(void)
{
  int stage;
  for (stage = 1; stage <= 7; stage++) {
    mock_state_t state;
    ftun_platform_tun_io_t io;
    ftun_tun_spec_t spec = test_spec("ftun0", 1500u);
    ftun_packet_port_t *port = (ftun_packet_port_t *)(uintptr_t)1;
    memset(&state, 0, sizeof(state));
    state.fail_stage = stage;
    state.fail_error = EIO;
    io = mock_io(&state);
    CHECK(ftun_tun_port_open_with_io(&spec, &io, &port) == FTUN_E_IO);
    CHECK(port == NULL);
    if (stage == 1) {
      CHECK(state.close_calls == 0);
    } else if (stage <= 3) {
      CHECK(state.device_close_calls == 1 && state.control_close_calls == 0);
    } else {
      CHECK(state.device_close_calls == 1 && state.control_close_calls == 1);
    }
  }
  return 0;
}

static int real_smoke(void)
{
  ftun_tun_spec_t spec = test_spec("ftun-contract0", 1400u);
  ftun_packet_port_t *port = NULL;
  ftun_tun_port_info_t info;
  struct ifreq request;
  int control;
  int status_flags;
  int descriptor_flags;
  CHECK(ftun_tun_port_open(&spec, &port) == FTUN_OK && port != NULL);
  CHECK(ftun_tun_port_get_info(port, &info) == FTUN_OK);
  CHECK(strcmp(info.name, "ftun-contract0") == 0 && info.mtu == 1400u);
  status_flags = fcntl((int)info.descriptor, F_GETFL);
  descriptor_flags = fcntl((int)info.descriptor, F_GETFD);
  CHECK(status_flags >= 0 && (status_flags & O_NONBLOCK) != 0);
  CHECK(descriptor_flags >= 0 && (descriptor_flags & FD_CLOEXEC) != 0);
  control = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  CHECK(control >= 0);
  memset(&request, 0, sizeof(request));
  memcpy(request.ifr_name, info.name, strlen(info.name) + 1u);
  CHECK(ioctl(control, SIOCGIFMTU, &request) == 0 && request.ifr_mtu == 1400);
  memset(&request, 0, sizeof(request));
  memcpy(request.ifr_name, info.name, strlen(info.name) + 1u);
  CHECK(ioctl(control, SIOCGIFFLAGS, &request) == 0 &&
        (request.ifr_flags & IFF_UP) != 0);
  CHECK(ftun_tun_port_close(&port) == FTUN_OK && port == NULL);
  memset(&request, 0, sizeof(request));
  memcpy(request.ifr_name, info.name, strlen(info.name) + 1u);
  errno = 0;
  CHECK(ioctl(control, SIOCGIFINDEX, &request) < 0 && errno == ENODEV);
  CHECK(close(control) == 0);
  return 0;
}

/* 权限、MTU、整包 I/O 和关闭。 */
static int budget_admission(void)
{
  ftun_budget_options_t options = {0};
  ftun_budget_t *budget = NULL;
  ftun_budget_usage_t usage;
  ftun_tun_spec_t spec = test_spec("ftun0", 1500u);
  ftun_packet_port_t *port = NULL;
  mock_state_t state = {0};
  ftun_platform_tun_io_t io = mock_io(&state);
  int stage;
  options.limit = (ftun_budget_resources_t){65536u, 1u, 1u};
  CHECK(ftun_budget_create_resources(NULL, &options, &budget) == FTUN_OK);
  CHECK(ftun_tun_port_open_with_io_and_budget(budget, &spec, &io, &port) == FTUN_E_LIMIT && port == NULL);
  CHECK(state.open_device_calls == 0 && state.open_control_calls == 0);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  options.limit.descriptors = 2u;
  CHECK(ftun_budget_create_resources(NULL, &options, &budget) == FTUN_OK);
  CHECK(ftun_tun_port_open_with_io_and_budget(budget, &spec, &io, &port) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK &&
    usage.used_resources.memory_bytes > 0u && usage.used_resources.descriptors == 1u &&
    usage.high_watermarks.descriptors == 2u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_E_AGAIN);
  CHECK(ftun_tun_port_close(&port) == FTUN_OK);
  for (stage = 1; stage <= 7; stage++) {
    memset(&state, 0, sizeof(state));
    state.fail_stage = stage;
    state.fail_error = EIO;
    CHECK(ftun_tun_port_open_with_io_and_budget(budget, &spec, &io, &port) == FTUN_E_IO && port == NULL);
    CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK &&
      usage.used_resources.memory_bytes == 0u && usage.used_resources.descriptors == 0u);
  }
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

int main(int argc, char **argv)
{
  mock_state_t state;
  ftun_platform_tun_io_t io;
  ftun_platform_tun_io_t incomplete;
  ftun_tun_spec_t spec = test_spec("ftun0", 1500u);
  ftun_packet_port_t *port = NULL;
  ftun_tun_port_info_t info;
  uint8_t packet[1500];
  size_t length = 99u;
  int stage;
  ftun_status_t status;

  if (argc == 2 && strcmp(argv[1], "--real") == 0) return real_smoke();
  CHECK(argc == 1);
  CHECK(budget_admission() == 0);

  memset(&state, 0, sizeof(state));
  io = mock_io(&state);
  status = ftun_tun_port_open_with_io(&spec, &io, &port);
  if (status != FTUN_OK) {
    fprintf(stderr, "open failed: %s, ioctls=%d closes=%d\n",
            ftun_status_name(status), state.ioctl_calls, state.close_calls);
  }
  CHECK(status == FTUN_OK && port != NULL);
  CHECK(state.open_device_calls == 1 && state.open_control_calls == 1 &&
        state.ioctl_calls == 4 && state.control_close_calls == 1);
  CHECK((state.device_flags & (O_RDWR | O_NONBLOCK | O_CLOEXEC)) ==
        (O_RDWR | O_NONBLOCK | O_CLOEXEC));
  CHECK(state.control_domain == AF_INET &&
        (state.control_type & (SOCK_DGRAM | SOCK_CLOEXEC)) ==
        (SOCK_DGRAM | SOCK_CLOEXEC));
  CHECK(state.requests[0] == FTUN_TUNSETIFF &&
        state.requests[1] == SIOCSIFMTU &&
        state.requests[2] == SIOCGIFFLAGS && state.requests[3] == SIOCSIFFLAGS);
  CHECK((state.tun_flags & (FTUN_IFF_TUN | FTUN_IFF_NO_PI |
                            FTUN_IFF_TUN_EXCL)) ==
        (FTUN_IFF_TUN | FTUN_IFF_NO_PI | FTUN_IFF_TUN_EXCL));
  CHECK(state.configured_mtu == 1500 && (state.up_flags & IFF_UP) != 0);
  CHECK(ftun_tun_port_get_info(port, &info) == FTUN_OK);
  CHECK(strcmp(info.name, "ftun0") == 0 && info.mtu == 1500u &&
        info.descriptor == 41);

  memset(packet, 0, sizeof(packet));
  state.read_eintr_once = 1;
  state.read_result = 20;
  memset(state.read_data, 0x45, 20u);
  CHECK(ftun_tun_port_read(port, packet, sizeof(packet), &length) == FTUN_OK);
  CHECK(length == 20u && state.read_calls == 2 && packet[0] == 0x45u);
  CHECK(ftun_tun_port_read(port, packet, sizeof(packet) - 1u, &length) ==
        FTUN_E_LIMIT && length == 0u && state.read_calls == 2);
  state.read_error = EAGAIN;
  CHECK(ftun_tun_port_read(port, packet, sizeof(packet), &length) ==
        FTUN_E_AGAIN && length == 0u);
  state.read_error = 0;
  state.read_result = 0;
  CHECK(ftun_tun_port_read(port, packet, sizeof(packet), &length) ==
        FTUN_E_EOF && length == 0u);
  state.read_result = 1501;
  CHECK(ftun_tun_port_read(port, packet, sizeof(packet), &length) ==
        FTUN_E_PROTOCOL && length == 0u);

  memset(packet, 0x5a, 32u);
  state.write_eintr_once = 1;
  state.write_result = -1;
  CHECK(ftun_tun_port_write(port, packet, 32u) == FTUN_OK);
  CHECK(state.write_calls == 2 && state.written_length == 32u &&
        state.written[0] == 0x5au);
  state.write_result = 16;
  CHECK(ftun_tun_port_write(port, packet, 32u) == FTUN_E_IO);
  state.write_error = EAGAIN;
  CHECK(ftun_tun_port_write(port, packet, 32u) == FTUN_E_AGAIN);
  state.write_error = 0;
  CHECK(ftun_tun_port_write(port, packet, 0u) == FTUN_E_INVALID);
  CHECK(ftun_tun_port_write(port, packet, sizeof(packet) + 1u) == FTUN_E_LIMIT);
  CHECK(ftun_tun_port_close(&port) == FTUN_OK && port == NULL);
  CHECK(state.device_close_calls == 1);
  CHECK(ftun_tun_port_close(&port) == FTUN_OK);

  CHECK(check_open_failures() == 0);
  for (stage = 1; stage <= 6; stage++) {
    memset(&state, 0, sizeof(state));
    state.eintr_stage = stage;
    io = mock_io(&state);
    CHECK(ftun_tun_port_open_with_io(&spec, &io, &port) == FTUN_OK);
    CHECK(state.eintr_done == 1);
    CHECK(ftun_tun_port_close(&port) == FTUN_OK);
  }

  memset(&state, 0, sizeof(state));
  state.fail_stage = 2;
  state.fail_error = EPERM;
  io = mock_io(&state);
  CHECK(ftun_tun_port_open_with_io(&spec, &io, &port) == FTUN_E_REJECTED &&
        port == NULL && state.device_close_calls == 1);
  memset(&state, 0, sizeof(state));
  state.fail_stage = 1;
  state.fail_error = ENODEV;
  io = mock_io(&state);
  CHECK(ftun_tun_port_open_with_io(&spec, &io, &port) == FTUN_E_UNSUPPORTED);
  memset(&state, 0, sizeof(state));
  state.fail_stage = 1;
  state.fail_error = EMFILE;
  io = mock_io(&state);
  CHECK(ftun_tun_port_open_with_io(&spec, &io, &port) == FTUN_E_LIMIT);

  memset(&state, 0, sizeof(state));
  io = mock_io(&state);
  state.fail_stage = 8;
  state.fail_error = EIO;
  CHECK(ftun_tun_port_open_with_io(&spec, &io, &port) == FTUN_OK);
  CHECK(ftun_tun_port_close(&port) == FTUN_E_IO && port == NULL);

  spec = test_spec("", 1500u);
  CHECK(ftun_tun_port_open_with_io(&spec, &io, &port) == FTUN_E_INVALID);
  spec = test_spec(".", 1500u);
  CHECK(ftun_tun_port_open_with_io(&spec, &io, &port) == FTUN_E_INVALID);
  spec = test_spec("bad/name", 1500u);
  CHECK(ftun_tun_port_open_with_io(&spec, &io, &port) == FTUN_E_INVALID);
  spec = test_spec("bad:name", 1500u);
  CHECK(ftun_tun_port_open_with_io(&spec, &io, &port) == FTUN_E_INVALID);
  spec = test_spec("name too long!!", 1500u);
  CHECK(ftun_tun_port_open_with_io(&spec, &io, &port) == FTUN_E_INVALID);
  spec = test_spec("0123456789abcdef", 1500u);
  CHECK(ftun_tun_port_open_with_io(&spec, &io, &port) == FTUN_E_INVALID);
  spec = test_spec("ftun0", FTUN_LINUX_TUN_MIN_MTU - 1u);
  CHECK(ftun_tun_port_open_with_io(&spec, &io, &port) == FTUN_E_INVALID);
  spec = test_spec("ftun0", FTUN_LINUX_TUN_MAX_MTU + 1u);
  CHECK(ftun_tun_port_open_with_io(&spec, &io, &port) == FTUN_E_INVALID);
  spec = test_spec("ftun0", 1500u);
  incomplete = io;
  incomplete.ioctl_call = NULL;
  port = (ftun_packet_port_t *)(uintptr_t)1;
  CHECK(ftun_tun_port_open_with_io(&spec, &incomplete, &port) ==
        FTUN_E_INVALID && port == NULL);
  CHECK(ftun_tun_port_open_with_io(NULL, &io, &port) == FTUN_E_INVALID &&
        port == NULL);
  CHECK(ftun_tun_port_open_with_io(&spec, &io, NULL) == FTUN_E_INVALID);
  CHECK(ftun_tun_port_get_info(NULL, &info) == FTUN_E_INVALID);
  CHECK(info.name[0] == '\0' && info.mtu == 0u && info.descriptor == 0);
  CHECK(ftun_tun_port_read(NULL, packet, sizeof(packet), &length) ==
        FTUN_E_INVALID && length == 0u);
  CHECK(ftun_tun_port_close(NULL) == FTUN_E_INVALID);
  return 0;
}
