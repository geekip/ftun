#define _POSIX_C_SOURCE 200809L

#include "cli.h"
#include "ftun/ftun.h"

#include "config/config.h"
#include "config/model.h"
#include "config/parser.h"
#include "core/runtime.h"
#if defined(FTUN_HAVE_MODULE_FAKEIP)
#include "state/fakeip_store.h"
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#if defined(FTUN_HAVE_MODULE_FAKEIP)
#include <sys/random.h>
#endif

#define FTUN_CLI_MEMORY_LIMIT (64u * 1024u * 1024u)

#ifndef FTUN_SOURCE_REVISION
#define FTUN_SOURCE_REVISION "unknown"
#endif

typedef struct {
  ftun_core_t *core;
  const char *config_path;
  pthread_mutex_t mutex;
  int done;
} ftun_cli_signal_context_t;

static void ftun_cli_usage(FILE *output)
{
  fputs(
    "Usage:\n"
    "  ftun version\n"
    "  ftun help\n"
    "  ftun check -c CONFIG\n"
    "  ftun run -c CONFIG\n"
    "  ftun stop PID\n"
    "  ftun reload PID\n"
    "  ftun fakeip init -c CONFIG\n",
    output);
}

static void ftun_cli_print_version(void)
{
  printf("FTUN %s\nsource: %s\ncapabilities: core", ftun_version(),
         FTUN_SOURCE_REVISION);
#if defined(FTUN_HAVE_MODULE_DNS)
  fputs(",dns", stdout);
#endif
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  fputs(",fakeip", stdout);
#endif
#if defined(FTUN_HAVE_MODULE_TUN)
  fputs(",tun", stdout);
#endif
#if defined(FTUN_HAVE_MODULE_FRS)
  fputs(",frs", stdout);
#endif
  fputc('\n', stdout);
}

static int ftun_cli_error(const char *operation, ftun_status_t status)
{
  fprintf(stderr, "ftun: %s: %s\n", operation, ftun_status_name(status));
  return 1;
}

static const char *ftun_cli_config_argument(int argc, char **argv, int start)
{
  if (argc == start + 1) return argv[start];
  if (argc == start + 2 &&
      (strcmp(argv[start], "-c") == 0 ||
       strcmp(argv[start], "--config") == 0)) return argv[start + 1];
  return NULL;
}

static ftun_status_t ftun_cli_core_create(ftun_core_t **out)
{
  ftun_core_options_t options;
  memset(&options, 0, sizeof(options));
  options.struct_size = sizeof(options);
  options.abi_version = FTUN_ABI_VERSION;
  options.owned_memory_limit = FTUN_CLI_MEMORY_LIMIT;
  /* 256 production TCP flows can each hold a write per direction while DNS,
   * health, FRS and control operations remain live. */
  options.operation_capacity = 1024u;
  options.retained_runtime_limit = 4u;
  return ftun_core_create(&options, out);
}

static ftun_status_t ftun_cli_check_config(const char *path,
                                            int require_inbound,
                                            ftun_config_t **out_config)
{
  ftun_core_t *core = NULL;
  ftun_config_t *config = NULL;
  ftun_runtime_t *candidate = NULL;
  ftun_status_t status;
  if (out_config != NULL) *out_config = NULL;
  status = ftun_cli_core_create(&core);
  if (status == FTUN_OK) status = ftun_config_load(core, path, &config);
  if (status == FTUN_OK && require_inbound && config->inbound_count == 0u) {
    status = FTUN_E_INVALID;
  }
  /* prepare also checks required FRS files and compiled feature resources;
   * abort makes check read-only with respect to the active runtime. */
  if (status == FTUN_OK) status = ftun_runtime_prepare(core, config, &candidate);
  /* `run` performs the configured first-download transaction in Core.  Its
   * read-only preflight may therefore accept only a genuinely missing FRS;
   * an existing corrupt or unbindable file still fails here. */
  if (status == FTUN_E_EOF && require_inbound && config != NULL &&
      config->frs.active && config->frs.auto_update &&
      config->frs.url != NULL && config->frs.url[0] != '\0') {
    status = FTUN_OK;
  }
  if (candidate != NULL) (void)ftun_runtime_abort(core, &candidate);
  if (status == FTUN_OK && out_config != NULL) {
    *out_config = config;
    config = NULL;
  }
  (void)ftun_config_destroy(&config);
  if (ftun_core_destroy(&core) != FTUN_OK && status == FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
  }
  return status;
}

static int ftun_cli_check(const char *path)
{
  ftun_status_t status = ftun_cli_check_config(path, 0, NULL);
  if (status != FTUN_OK) return ftun_cli_error("check", status);
  printf("configuration OK: %s\n", path);
  return 0;
}

static void ftun_cli_reload_done(ftun_operation_t *operation,
                                 ftun_error_t error, void *user)
{
  (void)operation;
  (void)user;
  if (error.status == FTUN_OK) {
    fputs("ftun: reload committed\n", stderr);
  } else {
    fprintf(stderr, "ftun: reload rejected at stage %u: %s\n",
            error.stage, ftun_status_name(error.status));
  }
}

static void *ftun_cli_signal_waiter(void *user)
{
  ftun_cli_signal_context_t *context = (ftun_cli_signal_context_t *)user;
  sigset_t signals;
  (void)sigemptyset(&signals);
  (void)sigaddset(&signals, SIGHUP);
  (void)sigaddset(&signals, SIGINT);
  (void)sigaddset(&signals, SIGTERM);
  for (;;) {
    int signal_number = 0;
    int done;
    if (sigwait(&signals, &signal_number) != 0) continue;
    (void)pthread_mutex_lock(&context->mutex);
    done = context->done;
    (void)pthread_mutex_unlock(&context->mutex);
    if (done) break;
    if (signal_number == SIGHUP) {
      ftun_operation_t *operation = NULL;
      ftun_status_t status = ftun_core_reload(
        context->core, context->config_path, ftun_cli_reload_done,
        context, &operation);
      if (status != FTUN_OK) {
        fprintf(stderr, "ftun: reload request rejected: %s\n",
                ftun_status_name(status));
      }
    } else {
      ftun_status_t status = ftun_core_stop(context->core, UINT64_MAX);
      if (status != FTUN_OK && status != FTUN_E_STALE) {
        fprintf(stderr, "ftun: stop request failed: %s\n",
                ftun_status_name(status));
      }
      break;
    }
  }
  return NULL;
}

static int ftun_cli_run(const char *path)
{
  ftun_cli_signal_context_t context;
  ftun_config_t *checked = NULL;
  ftun_core_t *core = NULL;
  pthread_t signal_thread;
  sigset_t signals;
  sigset_t previous;
  ftun_status_t status;
  int thread_started = 0;
  int mutex_started = 0;
  int signals_blocked = 0;
  int exit_code = 1;
  status = ftun_cli_check_config(path, 1, &checked);
  if (status != FTUN_OK) {
    if (status == FTUN_E_INVALID) {
      fputs("ftun: run: invalid configuration or no service inbound\n", stderr);
      return 1;
    }
    return ftun_cli_error("run preflight", status);
  }
  (void)ftun_config_destroy(&checked);
  status = ftun_cli_core_create(&core);
  if (status != FTUN_OK) return ftun_cli_error("create", status);
  memset(&context, 0, sizeof(context));
  context.core = core;
  context.config_path = path;
  if (pthread_mutex_init(&context.mutex, NULL) != 0) {
    status = FTUN_E_IO;
    goto done;
  }
  mutex_started = 1;
  (void)sigemptyset(&signals);
  (void)sigaddset(&signals, SIGHUP);
  (void)sigaddset(&signals, SIGINT);
  (void)sigaddset(&signals, SIGTERM);
  if (pthread_sigmask(SIG_BLOCK, &signals, &previous) != 0) {
    status = FTUN_E_IO;
    goto done;
  }
  signals_blocked = 1;
  if (pthread_create(&signal_thread, NULL, ftun_cli_signal_waiter,
                     &context) != 0) {
    status = FTUN_E_IO;
    goto done;
  }
  thread_started = 1;
  status = ftun_core_run(core, path);
  (void)pthread_mutex_lock(&context.mutex);
  context.done = 1;
  (void)pthread_mutex_unlock(&context.mutex);
  (void)pthread_kill(signal_thread, SIGTERM);
  (void)pthread_join(signal_thread, NULL);
  thread_started = 0;
  if (status == FTUN_OK) exit_code = 0;

done:
  if (thread_started) {
    (void)pthread_mutex_lock(&context.mutex);
    context.done = 1;
    (void)pthread_mutex_unlock(&context.mutex);
    (void)pthread_kill(signal_thread, SIGTERM);
    (void)pthread_join(signal_thread, NULL);
  }
  if (signals_blocked) (void)pthread_sigmask(SIG_SETMASK, &previous, NULL);
  if (mutex_started) (void)pthread_mutex_destroy(&context.mutex);
  if (ftun_core_destroy(&core) != FTUN_OK && status == FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
    exit_code = 1;
  }
  if (status != FTUN_OK) (void)ftun_cli_error("run", status);
  return exit_code;
}

static int ftun_cli_signal_process(const char *text, int signal_number,
                                   const char *operation)
{
  char *end = NULL;
  unsigned long value;
  errno = 0;
  value = strtoul(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || value <= 1u ||
      value > (unsigned long)INT_MAX) {
    fprintf(stderr, "ftun: %s: invalid PID\n", operation);
    return 2;
  }
  if (kill((pid_t)value, signal_number) != 0) {
    fprintf(stderr, "ftun: %s: %s\n", operation, strerror(errno));
    return 1;
  }
  return 0;
}

#if defined(FTUN_HAVE_MODULE_FAKEIP)
static int ftun_cli_random_uuid(uint8_t uuid[FTUN_FAKEIP_UUID_BYTES])
{
  size_t offset = 0u;
  while (offset < FTUN_FAKEIP_UUID_BYTES) {
    ssize_t count = getrandom(uuid + offset,
                              FTUN_FAKEIP_UUID_BYTES - offset, 0u);
    if (count > 0) {
      offset += (size_t)count;
    } else if (count < 0 && errno == EINTR) {
      continue;
    } else {
      int descriptor = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
      if (descriptor < 0) return 0;
      while (offset < FTUN_FAKEIP_UUID_BYTES) {
        count = read(descriptor, uuid + offset,
                     FTUN_FAKEIP_UUID_BYTES - offset);
        if (count > 0) offset += (size_t)count;
        else if (count < 0 && errno == EINTR) continue;
        else break;
      }
      if (close(descriptor) != 0 || offset != FTUN_FAKEIP_UUID_BYTES) return 0;
    }
  }
  uuid[6] = (uint8_t)((uuid[6] & 0x0fu) | 0x40u);
  uuid[8] = (uint8_t)((uuid[8] & 0x3fu) | 0x80u);
  return 1;
}

static int ftun_cli_fakeip_range(const char *range,
                                 uint32_t *first, uint32_t *end)
{
  struct in_addr address;
  const char *slash;
  char ip[INET_ADDRSTRLEN];
  char *tail = NULL;
  unsigned long prefix;
  size_t length;
  uint32_t host;
  uint32_t mask;
  uint32_t network;
  uint32_t broadcast;
  if (range == NULL || first == NULL || end == NULL ||
      (slash = strchr(range, '/')) == NULL) return 0;
  length = (size_t)(slash - range);
  if (length == 0u || length >= sizeof(ip)) return 0;
  memcpy(ip, range, length);
  ip[length] = '\0';
  errno = 0;
  prefix = strtoul(slash + 1u, &tail, 10);
  if (errno != 0 || tail == slash + 1u || *tail != '\0' || prefix > 32u ||
      inet_pton(AF_INET, ip, &address) != 1) return 0;
  host = ntohl(address.s_addr);
  mask = prefix == 0u ? 0u : UINT32_MAX << (32u - (unsigned int)prefix);
  network = host & mask;
  broadcast = network | ~mask;
  if (host != network || network == UINT32_MAX ||
      network + 1u >= broadcast) return 0;
  *first = network + 1u;
  *end = broadcast;
  return 1;
}
#endif

static int ftun_cli_fakeip_init(const char *path)
{
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  ftun_config_t *config = NULL;
  ftun_fakeip_store_identity_t identity;
  char *directory = NULL;
  size_t length;
  ftun_status_t status = ftun_cli_check_config(path, 0, &config);
  if (status != FTUN_OK) return ftun_cli_error("fakeip init", status);
  if (!config->dns.enable || !config->dns.fake_ip.enable ||
      !config->dns.fake_ip.persist || config->base.cache_file == NULL) {
    (void)ftun_config_destroy(&config);
    fputs("ftun: fakeip init: persistent FakeIP is not enabled\n", stderr);
    return 1;
  }
  memset(&identity, 0, sizeof(identity));
  if (!ftun_cli_fakeip_range(config->dns.fake_ip.range,
                             &identity.first_address,
                             &identity.end_address_exclusive) ||
      !ftun_cli_random_uuid(identity.uuid)) {
    (void)ftun_config_destroy(&config);
    return ftun_cli_error("fakeip init", FTUN_E_IO);
  }
  length = strlen(config->base.cache_file);
  if (length > SIZE_MAX - sizeof(".fakeip")) {
    (void)ftun_config_destroy(&config);
    return ftun_cli_error("fakeip init", FTUN_E_LIMIT);
  }
  directory = (char *)malloc(length + sizeof(".fakeip"));
  if (directory == NULL) {
    (void)ftun_config_destroy(&config);
    return ftun_cli_error("fakeip init", FTUN_E_LIMIT);
  }
  memcpy(directory, config->base.cache_file, length);
  memcpy(directory + length, ".fakeip", sizeof(".fakeip"));
  status = ftun_fakeip_store_initialize(directory, &identity);
  if (status == FTUN_OK) printf("FakeIP state initialized: %s\n", directory);
  free(directory);
  (void)ftun_config_destroy(&config);
  return status == FTUN_OK ? 0 : ftun_cli_error("fakeip init", status);
#else
  (void)path;
  return ftun_cli_error("fakeip init", FTUN_E_UNSUPPORTED);
#endif
}

int ftun_cli_main(int argc, char **argv)
{
  const char *path;
  if (argc == 2 &&
      (strcmp(argv[1], "version") == 0 || strcmp(argv[1], "--version") == 0)) {
    ftun_cli_print_version();
    return 0;
  }
  if (argc == 2 &&
      (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0 ||
       strcmp(argv[1], "-h") == 0)) {
    ftun_cli_usage(stdout);
    return 0;
  }
  if (argc >= 2 && strcmp(argv[1], "check") == 0) {
    path = ftun_cli_config_argument(argc, argv, 2);
    if (path != NULL) return ftun_cli_check(path);
  } else if (argc >= 2 && strcmp(argv[1], "run") == 0) {
    path = ftun_cli_config_argument(argc, argv, 2);
    if (path != NULL) return ftun_cli_run(path);
  } else if (argc == 3 && strcmp(argv[1], "stop") == 0) {
    return ftun_cli_signal_process(argv[2], SIGTERM, "stop");
  } else if (argc == 3 && strcmp(argv[1], "reload") == 0) {
    return ftun_cli_signal_process(argv[2], SIGHUP, "reload");
  } else if (argc >= 3 && strcmp(argv[1], "fakeip") == 0 &&
             strcmp(argv[2], "init") == 0) {
    path = ftun_cli_config_argument(argc, argv, 3);
    if (path != NULL) return ftun_cli_fakeip_init(path);
  }
  ftun_cli_usage(stderr);
  return 2;
}
