#define _GNU_SOURCE 1
#include "platform/linux/socket_protect.h"
#include <limits.h>
#include <linux/if.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "linux socket protect contract failed: %s\n", #x); \
    return 1; \
  } \
} while (0)

enum {
  EVENT_GET_DEVICE = 1,
  EVENT_GET_MARK,
  EVENT_SET_DEVICE,
  EVENT_SET_MARK
};

typedef struct {
  uint32_t mark;
  char device[FTUN_LINUX_SOCKET_DEVICE_BYTES];
  int events[24];
  size_t event_count;
  size_t fail_call;
  ftun_status_t fail_status;
  size_t second_fail_call;
  ftun_status_t second_fail_status;
  bool ignore_mark_set;
  bool ignore_device_set;
} protect_mock_t;

static ftun_status_t mock_event(protect_mock_t *mock, int event)
{
  if (mock->event_count < sizeof(mock->events) / sizeof(mock->events[0])) {
    mock->events[mock->event_count] = event;
  }
  mock->event_count++;
  if (mock->fail_call == mock->event_count) return mock->fail_status;
  if (mock->second_fail_call == mock->event_count) {
    return mock->second_fail_status;
  }
  return FTUN_OK;
}

static ftun_status_t mock_get_mark(void *context, int descriptor, uint32_t *out)
{
  protect_mock_t *mock = (protect_mock_t *)context;
  ftun_status_t status;
  (void)descriptor;
  status = mock_event(mock, EVENT_GET_MARK);
  if (status == FTUN_OK) *out = mock->mark;
  return status;
}

static ftun_status_t mock_set_mark(void *context, int descriptor, uint32_t mark)
{
  protect_mock_t *mock = (protect_mock_t *)context;
  ftun_status_t status;
  (void)descriptor;
  status = mock_event(mock, EVENT_SET_MARK);
  if (status == FTUN_OK && !mock->ignore_mark_set) mock->mark = mark;
  return status;
}

static ftun_status_t mock_get_device(
  void *context, int descriptor, char out[FTUN_LINUX_SOCKET_DEVICE_BYTES])
{
  protect_mock_t *mock = (protect_mock_t *)context;
  ftun_status_t status;
  (void)descriptor;
  status = mock_event(mock, EVENT_GET_DEVICE);
  if (status == FTUN_OK) memcpy(out, mock->device, sizeof(mock->device));
  return status;
}

static ftun_status_t mock_set_device(void *context, int descriptor,
                                     const char *interface_name)
{
  protect_mock_t *mock = (protect_mock_t *)context;
  ftun_status_t status;
  (void)descriptor;
  status = mock_event(mock, EVENT_SET_DEVICE);
  if (status == FTUN_OK && !mock->ignore_device_set) {
    memset(mock->device, 0, sizeof(mock->device));
    memcpy(mock->device, interface_name, strlen(interface_name));
  }
  return status;
}

static ftun_linux_socket_io_t mock_io(protect_mock_t *mock)
{
  ftun_linux_socket_io_t io;
  io.get_mark = mock_get_mark;
  io.set_mark = mock_set_mark;
  io.get_device = mock_get_device;
  io.set_device = mock_set_device;
  io.context = mock;
  return io;
}

static ftun_socket_policy_t protect_policy(const char *device)
{
  ftun_socket_policy_t policy;
  policy.mark = UINT32_C(0x46000001);
  policy.interface_name.data = device;
  policy.interface_name.length = device == NULL ? 0u : strlen(device);
  return policy;
}

static int check_real_socket(int type, bool with_device)
{
  ftun_socket_policy_t policy = protect_policy(with_device ? "lo" : NULL);
  ftun_socket_policy_t conflict = policy;
  char device[FTUN_LINUX_SOCKET_DEVICE_BYTES];
  uint32_t mark = 0u;
  socklen_t length;
  int descriptor = socket(AF_INET, type | SOCK_CLOEXEC, 0);
  CHECK(descriptor >= 0);
  CHECK(ftun_linux_socket_protect((ftun_native_socket_t)descriptor, &policy) ==
        FTUN_OK);
  length = (socklen_t)sizeof(mark);
  CHECK(getsockopt(descriptor, SOL_SOCKET, SO_MARK, &mark, &length) == 0 &&
        mark == policy.mark);
  memset(device, 0, sizeof(device));
  length = (socklen_t)sizeof(device);
  CHECK(getsockopt(descriptor, SOL_SOCKET, SO_BINDTODEVICE, device, &length) == 0);
  CHECK((with_device && strcmp(device, "lo") == 0) ||
        (!with_device && device[0] == '\0'));
  CHECK(ftun_linux_socket_protect((ftun_native_socket_t)descriptor, &policy) ==
        FTUN_OK);
  conflict.mark++;
  CHECK(ftun_linux_socket_protect((ftun_native_socket_t)descriptor, &conflict) ==
        FTUN_E_REJECTED);
  if (with_device) {
    conflict = policy;
    conflict.interface_name.data = "fake0";
    conflict.interface_name.length = strlen(conflict.interface_name.data);
    CHECK(ftun_linux_socket_protect((ftun_native_socket_t)descriptor,
                                    &conflict) == FTUN_E_REJECTED);
  }
  CHECK(close(descriptor) == 0);
  return 0;
}

static int real_smoke(void)
{
  CHECK(check_real_socket(SOCK_STREAM, true) == 0);
  CHECK(check_real_socket(SOCK_DGRAM, false) == 0);
  return 0;
}

/* TASK-PLATFORM-003 / TEST-PLATFORM-003：冲突、失败回滚和真实 socket 选项。 */
int main(int argc, char **argv)
{
  protect_mock_t mock;
  ftun_linux_socket_io_t io;
  ftun_linux_socket_io_t incomplete;
  ftun_socket_policy_t policy = protect_policy("eth0");

  if (argc == 2 && strcmp(argv[1], "--real") == 0) return real_smoke();
  CHECK(argc == 1);
  memset(&mock, 0, sizeof(mock));
  io = mock_io(&mock);
  CHECK(ftun_linux_socket_protect_with_io(7u, &policy, &io) == FTUN_OK);
  CHECK(mock.mark == policy.mark && strcmp(mock.device, "eth0") == 0);
  CHECK(mock.event_count == 6u &&
        mock.events[0] == EVENT_GET_DEVICE && mock.events[1] == EVENT_GET_MARK &&
        mock.events[2] == EVENT_SET_DEVICE && mock.events[3] == EVENT_SET_MARK &&
        mock.events[4] == EVENT_GET_DEVICE && mock.events[5] == EVENT_GET_MARK);
  mock.event_count = 0u;
  CHECK(ftun_linux_socket_protect_with_io(7u, &policy, &io) == FTUN_OK);
  CHECK(mock.event_count == 4u && mock.events[0] == EVENT_GET_DEVICE &&
        mock.events[1] == EVENT_GET_MARK &&
        mock.events[2] == EVENT_GET_DEVICE && mock.events[3] == EVENT_GET_MARK);

  memset(&mock, 0, sizeof(mock));
  memcpy(mock.device, "other0", 7u);
  io = mock_io(&mock);
  CHECK(ftun_linux_socket_protect_with_io(7u, &policy, &io) == FTUN_E_REJECTED);
  CHECK(mock.event_count == 2u && mock.mark == 0u &&
        strcmp(mock.device, "other0") == 0);
  memset(&mock, 0, sizeof(mock));
  mock.mark = policy.mark + 1u;
  io = mock_io(&mock);
  CHECK(ftun_linux_socket_protect_with_io(7u, &policy, &io) == FTUN_E_REJECTED);
  CHECK(mock.event_count == 2u && mock.device[0] == '\0');

  memset(&mock, 0, sizeof(mock));
  mock.fail_call = 3u;
  mock.fail_status = FTUN_E_REJECTED;
  io = mock_io(&mock);
  CHECK(ftun_linux_socket_protect_with_io(7u, &policy, &io) == FTUN_E_REJECTED);
  CHECK(mock.mark == 0u && mock.device[0] == '\0');
  memset(&mock, 0, sizeof(mock));
  mock.fail_call = 4u;
  mock.fail_status = FTUN_E_REJECTED;
  io = mock_io(&mock);
  CHECK(ftun_linux_socket_protect_with_io(7u, &policy, &io) == FTUN_E_REJECTED);
  CHECK(mock.mark == 0u && mock.device[0] == '\0' && mock.event_count == 5u &&
        mock.events[4] == EVENT_SET_DEVICE);

  memset(&mock, 0, sizeof(mock));
  mock.fail_call = 4u;
  mock.fail_status = FTUN_E_REJECTED;
  mock.second_fail_call = 5u;
  mock.second_fail_status = FTUN_E_IO;
  io = mock_io(&mock);
  CHECK(ftun_linux_socket_protect_with_io(7u, &policy, &io) ==
        FTUN_E_STATE_CORRUPT);
  CHECK(strcmp(mock.device, "eth0") == 0 && mock.mark == 0u);
  memset(&mock, 0, sizeof(mock));
  mock.ignore_mark_set = true;
  io = mock_io(&mock);
  CHECK(ftun_linux_socket_protect_with_io(7u, &policy, &io) ==
        FTUN_E_STATE_CORRUPT);
  CHECK(mock.device[0] == '\0' && mock.mark == 0u);

  memset(&mock, 0, sizeof(mock));
  mock.ignore_device_set = true;
  io = mock_io(&mock);
  CHECK(ftun_linux_socket_protect_with_io(7u, &policy, &io) ==
        FTUN_E_STATE_CORRUPT);
  CHECK(mock.device[0] == '\0' && mock.mark == 0u);

  policy = protect_policy(NULL);
  memset(&mock, 0, sizeof(mock));
  memcpy(mock.device, "eth9", 5u);
  io = mock_io(&mock);
  CHECK(ftun_linux_socket_protect_with_io(7u, &policy, &io) == FTUN_OK);
  CHECK(mock.mark == policy.mark && strcmp(mock.device, "eth9") == 0);

  policy = protect_policy("bad/name");
  CHECK(ftun_linux_socket_protect_with_io(7u, &policy, &io) == FTUN_E_INVALID);
  policy = protect_policy("0123456789abcdef");
  CHECK(ftun_linux_socket_protect_with_io(7u, &policy, &io) == FTUN_E_INVALID);
  policy = protect_policy(NULL);
  policy.mark = 0u;
  CHECK(ftun_linux_socket_protect_with_io(7u, &policy, &io) == FTUN_E_INVALID);
  policy = protect_policy(NULL);
  incomplete = io;
  incomplete.set_mark = NULL;
  CHECK(ftun_linux_socket_protect_with_io(7u, &policy, &incomplete) ==
        FTUN_E_INVALID);
  CHECK(ftun_linux_socket_protect_with_io((ftun_native_socket_t)INT_MAX + 1u,
                                           &policy, &io) == FTUN_E_INVALID);
  CHECK(ftun_linux_socket_protect_with_io(7u, NULL, &io) == FTUN_E_INVALID);
  return 0;
}
