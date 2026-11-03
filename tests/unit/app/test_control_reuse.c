#define _POSIX_C_SOURCE 200809L
#include "app/control.h"
#include "app/control/server.h"
#include "core/core.h"
#include "core/event/loop.h"
#include "core/log/aggregate.h"
#include "platform/clock.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "control reuse failed at %d: %s\n", __LINE__, #x); return 1; } } while (0)
static unsigned int runs, ready_count;
ftun_status_t __real_ftun_log_aggregate_attach(ftun_core_t *, ftun_event_loop_t *);
ftun_status_t __wrap_ftun_log_aggregate_attach(ftun_core_t *core, ftun_event_loop_t *loop)
{
  if (runs == 1u) {
    static const ftun_log_event_t failure = {FTUN_LOG_CTL, FTUN_LOG_WARN, "ctl.test", "test failure"};
    ftun_log_record_t record = {.event = &failure, .error = {.status = FTUN_E_IO}};
    uint64_t now;
    if (ftun_monotonic_now(&now) != FTUN_OK ||
        ftun_log_failure(core, &record, 1u, (ftun_string_t){"reuse", 5u}, now) != FTUN_OK) abort();
  }
  ftun_status_t status = __real_ftun_log_aggregate_attach(core, loop);
  return status == FTUN_OK && runs == 0u ? FTUN_E_IO : status;
}
static ftun_status_t ready(ftun_core_t *core, void *user)
{
  ftun_core_info_t info;
  ftun_app_command_result_t result;
  uint64_t now;
  (void)user;
  ready_count++;
  if (ftun_core_get_info(core, &info) != FTUN_OK || ftun_monotonic_now(&now) != FTUN_OK) return FTUN_E_IO;
  return ftun_app_control_stop(core, now + 3000u,
    (ftun_app_generation_guard_t){true, info.generation}, &result);
}
int main(void)
{
  char directory[] = "/tmp/ftun-control-reuse-XXXXXX", config[256], endpoint[256];
  ftun_core_t *core = NULL;
  ftun_core_options_t options = {.struct_size = sizeof(options), .abi_version = FTUN_ABI_VERSION};
  CHECK(mkdtemp(directory) != NULL);
  CHECK(snprintf(config, sizeof(config), "%s/config.json", directory) > 0);
  CHECK(snprintf(endpoint, sizeof(endpoint), "%s/run.sock", directory) > 0);
  int descriptor = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  socklen_t length = sizeof(address);
  CHECK(descriptor >= 0 && bind(descriptor, (struct sockaddr *)&address, length) == 0);
  CHECK(getsockname(descriptor, (struct sockaddr *)&address, &length) == 0 && close(descriptor) == 0);
  FILE *file = fopen(config, "w");
  CHECK(file != NULL);
  CHECK(fprintf(file, "{\"base\":{\"state-cache\":false},\"dns\":{\"enable\":false},\"log\":{\"level\":\"warn\"},"
    "\"inbounds\":[{\"name\":\"reuse\",\"type\":\"socks5\",\"listen\":\"127.0.0.1:%u\"}],\"rules\":[\"MATCH,DIRECT\"]}",
    (unsigned int)ntohs(address.sin_port)) > 0);
  CHECK(fclose(file) == 0);
  CHECK(ftun_core_create(&options, &core) == FTUN_OK);
  CHECK(ftun_app_control_set_ready(core, ready, NULL) == FTUN_OK);
  for (runs = 0u; runs < 2u; runs++) {
    ftun_ctl_server_t *server = NULL;
    CHECK(ftun_ctl_server_create(core, endpoint, &server) == FTUN_OK);
    CHECK(ftun_app_control_bind_server(core, server) == FTUN_OK);
    ftun_status_t expected = runs == 0u ? FTUN_E_IO : FTUN_OK;
    CHECK(ftun_core_run(core, config) == expected);
    CHECK(ftun_ctl_server_finish(server, expected) == FTUN_OK);
    CHECK(ftun_app_control_bind_server(core, NULL) == FTUN_OK);
    CHECK(ftun_ctl_server_destroy(&server) == FTUN_OK);
  }
  CHECK(ready_count == 1u);
  CHECK(ftun_core_destroy(&core) == FTUN_OK);
  CHECK(unlink(config) == 0 && rmdir(directory) == 0);
  return 0;
}
