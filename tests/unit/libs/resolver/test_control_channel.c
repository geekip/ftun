#include "libs/resolver/control_channel.h"
#include "platform/clock.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "control channel failed %d: %s\n", __LINE__, #x); return 1; } } while (0)

typedef struct {
  bool hold_open;
  ftun_operation_token_t opening;
  ftun_stream_write_token_t writing;
  ftun_path_completion_fn completion;
  void *user;
  ftun_path_t *path;
  unsigned int cancelled, destroyed;
} fixture_t;
static fixture_t fixture;

static ftun_status_t cancel_open(void *user)
{
  (void)user;
  fixture.cancelled++;
  return FTUN_E_AGAIN;
}

static void opened(ftun_operation_t *operation, ftun_error_t error, void *user)
{
  fixture_t *state = user;
  state->completion(operation, error, state->path, state->user);
}

static ftun_status_t read_bytes(void *user, void *buffer, size_t capacity, size_t *length)
{
  (void)user; (void)buffer; (void)capacity;
  *length = 0u;
  return FTUN_E_AGAIN;
}

static ftun_status_t write_bytes(void *user, ftun_stream_write_token_t write,
  const ftun_buffer_slice_t *slice, size_t *accepted)
{
  ftun_bytes_t bytes;
  (void)user;
  if (ftun_buffer_slice_data(slice, &bytes) != FTUN_OK) return FTUN_E_INVALID;
  fixture.writing = write;
  *accepted = bytes.length;
  return FTUN_OK;
}

static ftun_status_t cancel_write(void *user, ftun_stream_write_token_t write)
{
  (void)user; (void)write;
  fixture.cancelled++;
  return FTUN_E_AGAIN;
}

static ftun_status_t shutdown_write(void *user)
{
  (void)user;
  return FTUN_OK;
}

static void destroy(void *user)
{
  (void)user;
  fixture.destroyed++;
}

ftun_status_t __wrap_ftun_socket_path_open(void *context, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *spec,
  ftun_operation_t **out)
{
  ftun_status_t status;
  ftun_stream_options_t options = request->stream;
  ftun_stream_backend_t backend = {0};
  ftun_stream_t *stream = NULL;
  (void)context; (void)core;
  fixture.completion = request->completion;
  fixture.user = request->user;
  if (!fixture.hold_open) {
    options.budget = request->dial.budget;
    options.operations = request->dial.operations;
    backend.read = read_bytes;
    backend.write_start = write_bytes;
    backend.write_cancel = cancel_write;
    backend.shutdown_write = shutdown_write;
    backend.destroy = destroy;
    status = ftun_stream_create(&options, &backend, &stream);
    if (status != FTUN_OK) return status;
    status = ftun_path_adopt_stream(spec, &stream, &fixture.path);
    if (status != FTUN_OK) return status;
  }
  status = ftun_operation_accept(request->dial.operations, opened, &fixture,
    out, &fixture.opening);
  if (status != FTUN_OK) return status;
  if (fixture.hold_open) return ftun_operation_set_cancel_hook(*out, cancel_open, &fixture);
  return ftun_operation_complete(fixture.opening, (ftun_error_t){FTUN_OK, 0u, 0});
}

static int run(bool hold_open)
{
  ftun_budget_t *budget = NULL;
  ftun_control_channel_t *channel = NULL;
  ftun_endpoint_t endpoint = {0};
  ftun_budget_usage_t usage;
  uint64_t now;
  size_t written = 99u;
  memset(&fixture, 0, sizeof(fixture));
  fixture.hold_open = hold_open;
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 128u, &budget) == FTUN_OK);
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  CHECK(ftun_control_channel_create(budget, 7u, now + 20u, &channel) == FTUN_OK);
  endpoint.kind = FTUN_ADDRESS_IPV4; endpoint.address[0] = 127u;
  endpoint.address[3] = 1u; endpoint.port = 80u;
  CHECK(ftun_control_channel_connect(channel, &endpoint, 0u, FTUN_DIAL_PURPOSE_PROBE) ==
    (hold_open ? FTUN_E_TIMEOUT : FTUN_OK));
  if (!hold_open) {
    CHECK(ftun_control_channel_write(channel, (const uint8_t *)"abc", 3u, &written) == FTUN_E_TIMEOUT);
    CHECK(written == 0u && fixture.writing.stream != NULL);
  }
  CHECK(ftun_control_channel_close(&channel) == FTUN_E_AGAIN && channel != NULL);
  CHECK(fixture.cancelled != 0u && fixture.destroyed == 0u);
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes != 0u);
  if (hold_open) {
    CHECK(ftun_operation_complete(fixture.opening, (ftun_error_t){FTUN_E_CANCELLED, 0u, 0}) == FTUN_OK);
  } else {
    CHECK(ftun_stream_write_complete(fixture.writing, (ftun_error_t){FTUN_E_CANCELLED, 0u, 0}) == FTUN_OK);
  }
  CHECK(ftun_control_channel_close(&channel) == FTUN_OK && channel == NULL);
  CHECK(fixture.destroyed == (hold_open ? 0u : 1u));
  CHECK(ftun_budget_get_usage(budget, &usage) == FTUN_OK && usage.used_resources.memory_bytes == 0u && usage.used_resources.descriptors == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

/* 文件描述符耗尽时创建通道：事件后端建不起来，创建必须干净地失败并返回。
 * 此前清理会去轮询没有后端的事件循环，永远得到 UNSUPPORTED，把调用它的
 * Worker 线程永久卡在清理循环里。alarm 让退化为死循环时测试失败而不是挂起。 */
static int descriptor_exhaustion(void)
{
  struct rlimit original;
  struct rlimit limited;
  ftun_budget_t *budget = NULL;
  ftun_control_channel_t *channel = NULL;
  ftun_status_t status;
  uint64_t now;
  int highest = 2;
  int descriptor;
  CHECK(ftun_budget_create(NULL, 1024u * 1024u, 128u, &budget) == FTUN_OK);
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  for (descriptor = 3; descriptor < 1024; descriptor++) {
    if (fcntl(descriptor, F_GETFD) != -1) highest = descriptor;
  }
  CHECK(getrlimit(RLIMIT_NOFILE, &original) == 0);
  limited = original;
  limited.rlim_cur = (rlim_t)highest + 1u;
  alarm(15u);
  CHECK(setrlimit(RLIMIT_NOFILE, &limited) == 0);
  status = ftun_control_channel_create(budget, 7u, now + 1000u, &channel);
  CHECK(setrlimit(RLIMIT_NOFILE, &original) == 0);
  alarm(0u);
  CHECK(status != FTUN_OK && channel == NULL);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  return 0;
}

int main(void)
{
  CHECK(descriptor_exhaustion() == 0);
  CHECK(run(true) == 0);
  CHECK(run(false) == 0);
  puts("control channel failed cancellation retains open/write state until owner completion");
  return 0;
}
