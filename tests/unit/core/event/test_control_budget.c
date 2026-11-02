#include "core/event/loop.h"
#include "core/event/backend.h"
#include "core/context.h"
#include "core/limits.h"
#include "platform/socket.h"
#include <stdio.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "control event budget failed at %d: %s\n", __LINE__, #x); return 1; } } while (0)

typedef struct { ftun_handle_t socket; unsigned int received; } reader_t;
static void readable(ftun_event_source_t *source, uint32_t events, void *user)
{
  reader_t *reader = user;
  ftun_status_t status;
  char byte;
  (void)source; (void)events;
  if (ftun_socket_receive_nowait(reader->socket, &byte, 1u, &status) == 1 && byte == 'x') reader->received++;
}
static void unused(ftun_event_source_t *source, uint32_t events, void *user)
{ (void)source; (void)events; (void)user; }

int main(void)
{
  ftun_budget_options_t limits = {{4u * 1024u * 1024u, 64u, 1024u}, {0}, {0}};
  ftun_budget_t *root = NULL, *data = NULL;
  ftun_core_t *core = NULL;
  ftun_event_loop_t *loop = NULL;
  ftun_event_source_t *ordinary[6] = {0}, *io = NULL, *timer = NULL, *extra = NULL;
  ftun_reservation_t hold = {0}, descriptors = {0};
  ftun_budget_usage_t before, after;
  ftun_handle_t pair[2];
  reader_t reader;
  size_t i, callbacks;
  ftun_status_t status;
  CHECK(ftun_budget_create_resources(NULL, &limits, &root) == FTUN_OK);
  limits.limit.memory_bytes /= 2u;
  CHECK(ftun_budget_create_resources(root, &limits, &data) == FTUN_OK);
  CHECK(ftun_core_context_create(root, &core) == FTUN_OK);
  CHECK(ftun_event_loop_create_with_budget(core, data, 8u, &loop) == FTUN_OK);
  CHECK(ftun_event_backend_attach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_bind_control(loop, root, 2u) == FTUN_OK);
  for (i = 0u; i < 6u; i++) CHECK(ftun_event_task_start(loop, unused, NULL, &ordinary[i]) == FTUN_OK);
  CHECK(ftun_event_task_start(loop, unused, NULL, &extra) == FTUN_E_LIMIT && extra == NULL);
  CHECK(ftun_budget_get_usage(data, &before) == FTUN_OK);
  CHECK(ftun_budget_reserve(data, before.normal_available_resources.memory_bytes, &hold) == FTUN_OK);
  CHECK(ftun_budget_get_usage(data, &before) == FTUN_OK);
  CHECK(ftun_budget_reserve_resources(root, (ftun_budget_resources_t){0u, 2u, 0u}, &descriptors) == FTUN_OK);
  CHECK(ftun_socket_pair(pair) == FTUN_OK);
  reader = (reader_t){pair[0], 0u};
  CHECK(ftun_event_control_io_start(loop, (ftun_native_socket_t)pair[0], FTUN_EVENT_READ,
    readable, &reader, &io) == FTUN_OK);
  CHECK(ftun_event_control_timer_start(loop, UINT64_MAX, unused, NULL, &timer) == FTUN_OK);
  CHECK(ftun_event_loop_bind_control(loop, NULL, 0u) == FTUN_E_AGAIN);
  CHECK(ftun_event_control_timer_start(loop, UINT64_MAX, unused, NULL, &extra) == FTUN_E_LIMIT && extra == NULL);
  CHECK(ftun_budget_get_usage(data, &after) == FTUN_OK &&
    before.used_resources.memory_bytes == after.used_resources.memory_bytes &&
    before.used_resources.queue_slots == after.used_resources.queue_slots);
  CHECK(ftun_socket_send_nowait(pair[1], "x", 1u, &status) == 1);
  CHECK(ftun_event_loop_run_once(loop, true, 8u, &callbacks) == FTUN_OK && reader.received == 1u);
  CHECK(ftun_event_source_cancel(&timer) == FTUN_OK && ftun_event_source_cancel(&io) == FTUN_OK);
  CHECK(ftun_event_loop_bind_control(loop, NULL, 0u) == FTUN_OK);
  CHECK(ftun_socket_close((ftun_native_socket_t)pair[0]) == FTUN_OK &&
    ftun_socket_close((ftun_native_socket_t)pair[1]) == FTUN_OK);
  ftun_reservation_release(&descriptors);
  ftun_reservation_release(&hold);
  for (i = 0u; i < 6u; i++) CHECK(ftun_event_source_cancel(&ordinary[i]) == FTUN_OK);
  CHECK(ftun_event_loop_stop(loop) == FTUN_OK && ftun_event_backend_detach(loop) == FTUN_OK);
  CHECK(ftun_event_loop_destroy(&loop) == FTUN_OK && ftun_core_context_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&data) == FTUN_OK && ftun_budget_destroy(&root) == FTUN_OK);
  puts("Control event budget: reserved slots and real I/O progress after data memory exhaustion passed");
  return 0;
}
