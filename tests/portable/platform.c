#include "app/cli/cli.h"
#include "platform/clock.h"
#include "platform/file.h"
#include "platform/pidfile.h"
#include "platform/poller.h"
#include "platform/process.h"
#include "platform/random.h"
#include "platform/socket.h"
#include "util/endpoint.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined(_WIN32)
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#endif

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "platform contract: %d: %s\n", __LINE__, #x); exit(1); } } while (0)

typedef struct {
  ftun_mutex_t mutex;
  ftun_condition_t condition;
  unsigned int state;
} shared_t;
static void *peer(void *argument)
{
  shared_t *shared = argument;
  ftun_mutex_lock(&shared->mutex);
  shared->state = 1u;
  ftun_condition_signal(&shared->condition);
  while (shared->state == 1u) ftun_condition_wait(&shared->condition, &shared->mutex);
  shared->state = 3u;
  ftun_condition_broadcast(&shared->condition);
  ftun_mutex_unlock(&shared->mutex);
  return NULL;
}
static void threads(void)
{
  shared_t shared = {0};
  ftun_thread_t thread;
  uint64_t now;
  CHECK(ftun_mutex_init(&shared.mutex) == FTUN_OK);
  CHECK(ftun_condition_init(&shared.condition) == FTUN_OK);
  for (unsigned int detach = 0u; detach < 2u; detach++) {
    shared.state = 0u;
    ftun_mutex_lock(&shared.mutex);
    CHECK(ftun_monotonic_now(&now) == FTUN_OK);
    CHECK(ftun_condition_wait_until(&shared.condition, &shared.mutex, now) == FTUN_E_TIMEOUT);
    CHECK(ftun_condition_wait_until(&shared.condition, &shared.mutex, now + 20u) == FTUN_E_TIMEOUT);
    CHECK(ftun_thread_create(&thread, peer, &shared) == FTUN_OK);
    if (detach) CHECK(ftun_thread_detach(&thread) == FTUN_OK);
    while (shared.state != 1u) CHECK(ftun_condition_wait_until(&shared.condition, &shared.mutex, now + 5000u) == FTUN_OK);
    shared.state = 2u;
    ftun_condition_signal(&shared.condition);
    while (shared.state != 3u) CHECK(ftun_condition_wait_until(&shared.condition, &shared.mutex, now + 5000u) == FTUN_OK);
    ftun_mutex_unlock(&shared.mutex);
    if (!detach) CHECK(ftun_thread_join(&thread) == FTUN_OK);
  }
  ftun_condition_destroy(&shared.condition);
  ftun_mutex_destroy(&shared.mutex);
}
static void *wake(void *argument)
{
  ftun_thread_pause(20u);
  ftun_poller_wakeup(argument);
  return NULL;
}
static void *poller_allocate(void *context, size_t bytes, size_t descriptors)
{
  (void)context; (void)descriptors;
  return malloc(bytes);
}
static void poller_release(void *context, void *memory) { (void)context; free(memory); }
static void polling(void)
{
  enum { PAIRS = 96 };
  ftun_handle_t pairs[PAIRS][2];
  ftun_poller_io_t io[PAIRS] = {0};
  ftun_poller_t poller = {0};
  ftun_poller_event_t events[FTUN_POLLER_CAPACITY];
  ftun_thread_t thread;
  bool seen[PAIRS] = {false};
  size_t count, total = 0u;
  ftun_status_t status;
  CHECK(ftun_poller_create(&poller, (ftun_poller_memory_t){poller_allocate, poller_release, NULL}) == FTUN_OK);
  CHECK(ftun_thread_create(&thread, wake, &poller) == FTUN_OK);
  CHECK(ftun_poller_wait(&poller, 5000, events, &count) == FTUN_OK && count == 0u);
  CHECK(ftun_thread_join(&thread) == FTUN_OK);
  for (size_t i = 0u; i < PAIRS; i++) {
    CHECK(ftun_socket_pair(pairs[i]) == FTUN_OK);
    io[i].socket = (ftun_native_socket_t)pairs[i][0];
    CHECK(ftun_poller_update(&poller, &io[i], FTUN_POLLER_READ, &io[i]) == FTUN_OK);
    io[i].events = FTUN_POLLER_READ;
    CHECK(ftun_socket_stream_send(pairs[i][1], "x", 1u, &status) == 1 && status == FTUN_OK);
  }
  /* 不消费就绪数据，验证超过单批容量时后半批不会永久饥饿。 */
  for (size_t round = 0u; round < 8u && total < PAIRS; round++) {
    CHECK(ftun_poller_wait(&poller, 1000, events, &count) == FTUN_OK && count != 0u);
    for (size_t i = 0u; i < count; i++) {
      size_t index = (size_t)((ftun_poller_io_t *)events[i].user - io);
      CHECK(index < PAIRS && (events[i].events & FTUN_POLLER_READ));
      if (!seen[index]) { seen[index] = true; total++; }
    }
  }
  CHECK(total == PAIRS);
  for (size_t i = 0u; i < PAIRS; i++) {
    char byte;
    CHECK(ftun_socket_stream_receive(pairs[i][0], &byte, 1u, &status) == 1 && byte == 'x');
    CHECK(ftun_poller_update(&poller, &io[i], 0u, NULL) == FTUN_OK);
    io[i].events = 0u;
    CHECK(ftun_socket_close((ftun_native_socket_t)pairs[i][0]) == FTUN_OK);
    CHECK(ftun_socket_close((ftun_native_socket_t)pairs[i][1]) == FTUN_OK);
  }
  ftun_poller_destroy(&poller);
}
static void datagrams(ftun_address_kind_t family)
{
  ftun_endpoint_t address = {0}, source;
  ftun_handle_t socket;
  ftun_socket_bind_issue_t issue;
  ftun_status_t status;
  size_t length;
  char buffer[4];
  address.kind = family;
  if (family == FTUN_ADDRESS_IPV4) { address.address[0] = 127u; address.address[3] = 1u; }
  else address.address[15] = 1u;
  CHECK(ftun_socket_listen(&address, FTUN_DIAL_UDP, 0, &socket, &issue) == FTUN_OK);
  CHECK(ftun_socket_name(socket, &address) == FTUN_OK);
  CHECK(ftun_socket_send_to(socket, "", 0u, &address, &status) == 0 && status == FTUN_OK);
  uint64_t now;
  CHECK(ftun_monotonic_now(&now) == FTUN_OK);
  CHECK(ftun_blocking_socket_wait(socket, FTUN_POLLER_READ, now + 5000u));
  CHECK(ftun_socket_receive_from(socket, buffer, sizeof(buffer), &source, &status) == 0 && status == FTUN_OK);
  /* 短包和恰好填满缓冲区都不是截断；随后超长包必须拒绝。 */
  for (size_t size = 3u; size <= sizeof(buffer); size++) {
    CHECK(ftun_socket_send_to(socket, "full", size, &address, &status) == (ptrdiff_t)size && status == FTUN_OK);
    CHECK(ftun_monotonic_now(&now) == FTUN_OK);
    CHECK(ftun_blocking_socket_wait(socket, FTUN_POLLER_READ, now + 5000u));
    CHECK(ftun_socket_datagram_receive(NULL, (ftun_native_socket_t)socket, buffer, sizeof(buffer), &length, &source) == FTUN_OK);
    CHECK(length == size && memcmp(buffer, "full", size) == 0 && ftun_endpoint_equal(&source, &address));
  }
  CHECK(ftun_socket_send_to(socket, "truncated", 9u, &address, &status) == 9 && status == FTUN_OK);
  CHECK(ftun_blocking_socket_wait(socket, FTUN_POLLER_READ, now + 5000u));
  CHECK(ftun_socket_datagram_receive(NULL, (ftun_native_socket_t)socket, buffer, sizeof(buffer), &length, &source) == FTUN_E_LIMIT);
  CHECK(ftun_socket_close((ftun_native_socket_t)socket) == FTUN_OK);
}
static ftun_status_t renamed(ftun_file_stage_t stage, void *argument)
{
  bool *published = argument;
  CHECK(*published == (stage >= FTUN_FILE_STAGE_RENAMED));
  return stage == FTUN_FILE_STAGE_RENAMED ? FTUN_E_IO : FTUN_OK;
}
static void files(void)
{
  char directory[96], path[128], temporary[128], canonical[4096], buffer[8] = {0};
  ftun_file_handle_t file;
  ftun_platform_file_lock_t lock, contender;
  uint64_t size;
  size_t written;
  bool created, published;
  ftun_handle_t descriptor, duplicate;
  ftun_file_info_t info;
  int64_t before, after;
  CHECK(ftun_wallclock_unix_ms(&before) == FTUN_OK);
  snprintf(directory, sizeof(directory), "ftun-platform-%lu", (unsigned long)ftun_process_id());
  snprintf(path, sizeof(path), "%s/\xe6\xb5\x8b\xe8\xaf\x95", directory);
  snprintf(temporary, sizeof(temporary), "%s%s", directory, FTUN_FILE_TEMPORARY_SUFFIX);
  CHECK(ftun_directory_create(directory, 0700u) == FTUN_OK);
  CHECK(ftun_directory_ensure(directory, 0700u) == FTUN_OK);
  CHECK(ftun_platform_file_open_append(path, false, &file, &size) == FTUN_OK && size == 0u);
  CHECK(ftun_platform_file_write(&file, (ftun_bytes_t){(const uint8_t *)"old", 3u}, &written) == FTUN_OK && written == 3u);
  CHECK(ftun_platform_file_close(&file) == FTUN_OK);
  CHECK(ftun_file_open(path, FTUN_FILE_READ, &file.descriptor) == FTUN_OK);
  ftun_error_t error = ftun_platform_file_write_error(&file,
    (ftun_bytes_t){(const uint8_t *)"denied", 6u}, &written);
  CHECK(error.status != FTUN_OK && error.native_code != 0 && written == 0u);
  CHECK(ftun_platform_file_close(&file) == FTUN_OK);
  CHECK(ftun_platform_file_lock_acquire(path, &lock) == FTUN_OK);
  CHECK(ftun_platform_file_lock_acquire(path, &contender) == FTUN_E_AGAIN);
  CHECK(ftun_platform_file_lock_release(&lock) == FTUN_OK);
  CHECK(ftun_platform_file_write_temporary(temporary, (ftun_bytes_t){(const uint8_t *)"new", 3u}, 0600u, &created) == FTUN_OK && created);
  CHECK(ftun_platform_file_replace(temporary, path, directory, renamed, &published, true, &published) == FTUN_E_IO && published);
  snprintf(temporary, sizeof(temporary), "%s%s", directory, FTUN_FILE_TEMPORARY_SUFFIX);
  CHECK(ftun_platform_file_write_temporary(temporary, (ftun_bytes_t){(const uint8_t *)"ignored", 7u},
    0600u, &created) == FTUN_OK && created);
  CHECK(ftun_platform_file_replace(temporary, path, directory, NULL, NULL, false, &published) == FTUN_E_STALE && !published);
  ftun_platform_file_remove_temporary(temporary);
  CHECK(ftun_file_real_path(path, canonical, sizeof(canonical)) == FTUN_OK);
  CHECK(ftun_file_open(path, FTUN_FILE_READ_NOFOLLOW, &descriptor) == FTUN_OK);
  CHECK(!ftun_file_is_terminal(descriptor) && !ftun_file_enable_ansi(descriptor));
  CHECK(ftun_file_duplicate(descriptor, &duplicate) == FTUN_OK);
  CHECK(ftun_file_inspect(descriptor, &info) == FTUN_OK);
  CHECK(ftun_wallclock_unix_ms(&after) == FTUN_OK);
  CHECK(info.modified_unix_ms >= before - 2000 && info.modified_unix_ms <= after);
  CHECK(ftun_file_read(duplicate, buffer, sizeof(buffer)) == 3 && memcmp(buffer, "new", 3u) == 0);
  const char *mapped = ftun_file_map_read(descriptor, 3u);
  CHECK(mapped != NULL && memcmp(mapped, "new", 3u) == 0);
  CHECK(ftun_file_unmap(mapped, 3u) == FTUN_OK);
  CHECK(ftun_file_close(duplicate) == FTUN_OK && ftun_file_close(descriptor) == FTUN_OK);
  ftun_platform_file_remove_temporary(path);
  snprintf(temporary, sizeof(temporary), "%s%s", directory, FTUN_FILE_TEMPORARY_SUFFIX);
  CHECK(ftun_platform_file_write_temporary(temporary, (ftun_bytes_t){(const uint8_t *)"created", 7u},
    0600u, &created) == FTUN_OK && created);
  CHECK(ftun_platform_file_replace(temporary, path, directory, NULL, NULL, false, &published) == FTUN_OK && published);
  CHECK(ftun_file_open(path, FTUN_FILE_READ_NOFOLLOW, &descriptor) == FTUN_OK);
  CHECK(ftun_file_read(descriptor, buffer, sizeof(buffer)) == 7 && memcmp(buffer, "created", 7u) == 0);
  CHECK(ftun_file_close(descriptor) == FTUN_OK);
  ftun_platform_file_remove_temporary(path);
  {
    char source[128], target[128], child[160];
    snprintf(source, sizeof(source), "%s/state.XXXXXX", directory);
    snprintf(target, sizeof(target), "%s/state", directory);
    CHECK(ftun_directory_create_temporary(source, &created) == FTUN_OK && created);
    snprintf(child, sizeof(child), "%s/value", source);
    CHECK(ftun_platform_file_open_append(child, false, &file, &size) == FTUN_OK);
    CHECK(ftun_platform_file_write(&file, (ftun_bytes_t){(const uint8_t *)"state", 5u}, &written) == FTUN_OK && written == 5u);
    CHECK(ftun_file_sync(file.descriptor, false) == FTUN_OK);
    CHECK(ftun_platform_file_close(&file) == FTUN_OK);
    CHECK(ftun_directory_publish(source, target, directory, NULL, NULL, &published) == FTUN_OK && published);
    CHECK(ftun_file_inspect_path_nofollow(source, &info) == FTUN_E_EOF);
    CHECK(ftun_file_inspect_path_nofollow(target, &info) == FTUN_OK && info.directory);
    snprintf(child, sizeof(child), "%s/value", target);
    CHECK(ftun_file_open(child, FTUN_FILE_READ_NOFOLLOW, &descriptor) == FTUN_OK);
    CHECK(ftun_file_read(descriptor, buffer, sizeof(buffer)) == 5 && memcmp(buffer, "state", 5u) == 0);
    CHECK(ftun_file_close(descriptor) == FTUN_OK);
    snprintf(source, sizeof(source), "%s/state.XXXXXX", directory);
    CHECK(ftun_directory_create_temporary(source, &created) == FTUN_OK && created);
    CHECK(ftun_directory_publish(source, target, directory, NULL, NULL, &published) == FTUN_E_STALE && !published);
    ftun_platform_file_remove_temporary(child);
    CHECK(ftun_directory_publish(source, target, directory, NULL, NULL, &published) == FTUN_E_STALE && !published);
    ftun_directory_remove(target);
    CHECK(ftun_directory_publish(source, target, directory, NULL, NULL, &published) == FTUN_OK && published);
    ftun_directory_remove(target);
  }
  {
    /* 临时目录里仍有打开的文件句柄（候选锁）时发布：结果必须与平台声明一致。
     * Windows 拒绝重命名这样的目录；声明为假的平台，调用方必须先关闭句柄再发布。 */
    char source[128], target[128], child[160];
    ftun_platform_file_lock_t lock;
    ftun_status_t status;
    snprintf(source, sizeof(source), "%s/held.XXXXXX", directory);
    snprintf(target, sizeof(target), "%s/held", directory);
    CHECK(ftun_directory_create_temporary(source, &created) == FTUN_OK && created);
    snprintf(child, sizeof(child), "%s/lock", source);
    CHECK(ftun_platform_file_lock_acquire(child, &lock) == FTUN_OK);
    status = ftun_directory_publish(source, target, directory, NULL, NULL, &published);
    if (ftun_directory_publish_allows_open_files()) {
      CHECK(status == FTUN_OK && published);
    } else {
      CHECK(status != FTUN_OK && !published);
    }
    CHECK(ftun_platform_file_lock_release(&lock) == FTUN_OK);
    if (!published) {
      CHECK(ftun_directory_publish(source, target, directory, NULL, NULL, &published) == FTUN_OK && published);
    }
    snprintf(child, sizeof(child), "%s/lock", target);
    ftun_platform_file_remove_temporary(child);
    ftun_directory_remove(target);
  }
  ftun_directory_remove(directory);
}
static void pidfiles(void)
{
  char directory[128], path[256], contents[32], expected[32];
  uint32_t pid;
  ftun_handle_t descriptor;
  ftun_pidfile_t first = FTUN_PIDFILE_INVALID, second = FTUN_PIDFILE_INVALID;
  (void)snprintf(directory, sizeof(directory), "ftun-pidfile-%u", ftun_process_id());
  (void)snprintf(path, sizeof(path), "%s/实例.pid", directory);
  CHECK(ftun_directory_create(directory, 0700u) == FTUN_OK);
  CHECK(ftun_pidfile_probe(path, &pid) == FTUN_E_EOF && pid == 0u);
  CHECK(ftun_pidfile_acquire(path, &first, &pid) == FTUN_OK);
  CHECK(ftun_pidfile_probe(path, &pid) == FTUN_OK && pid == ftun_process_id());
  CHECK(ftun_pidfile_acquire(path, &second, &pid) == FTUN_E_AGAIN && pid == ftun_process_id());
  CHECK(!ftun_platform_file_is_open(&second.file));
  CHECK(ftun_file_open(path, FTUN_FILE_READ_NOFOLLOW, &descriptor) == FTUN_OK);
  int length = snprintf(expected, sizeof(expected), "%u\n", ftun_process_id());
  CHECK(ftun_file_read(descriptor, contents, sizeof(contents)) == length);
  CHECK(memcmp(contents, expected, (size_t)length) == 0);
  CHECK(ftun_file_close(descriptor) == FTUN_OK);
  CHECK(ftun_pidfile_rewrite(&first) == FTUN_OK);
  CHECK(ftun_pidfile_release(&first) == FTUN_OK);
  CHECK(ftun_file_open(path, FTUN_FILE_READ, &descriptor) != FTUN_OK);
  CHECK(ftun_pidfile_acquire(path, &second, &pid) == FTUN_OK);
  CHECK(ftun_pidfile_release(&second) == FTUN_OK);
  ftun_directory_remove(directory);
#if defined(_WIN32)
  {
    char storage[4096], expanded[4096], wanted[4096];
    ftun_string_t home;
    CHECK(ftun_user_home(storage, sizeof(storage), &home) == FTUN_OK);
    (void)snprintf(wanted, sizeof(wanted), "%.*s/instance.pid", (int)home.length, home.data);
    ftun_file_path_normalize(wanted);
    CHECK(ftun_pidfile_path("~\\instance.pid", expanded, sizeof(expanded)) == FTUN_OK);
    CHECK(strcmp(wanted, expanded) == 0);
  }
#endif
}

static void *wait_signal(void *argument)
{
  uint32_t received;
  CHECK(ftun_signal_wait(FTUN_SIGNAL_HANGUP, &received) == FTUN_OK && received == FTUN_SIGNAL_HANGUP);
  *(bool *)argument = true;
  return NULL;
}
static void process(void)
{
  uint8_t identity[128], random[512];
  size_t length;
  ftun_process_alarm_t alarm;
  ftun_signal_mask_t previous;
  ftun_thread_t thread;
  bool received = false;
  int error;
  int64_t wall;
  bool exited;
  {
    ftun_local_time_t local;
    CHECK(ftun_wallclock_local(&local) == FTUN_OK);
    CHECK(local.calendar.year >= 2024 && local.calendar.month >= 1 && local.calendar.month <= 12);
    CHECK(local.calendar.millisecond < 1000u && abs(local.offset_minutes) < 24 * 60);
#if defined(_WIN32)
    {
      struct tm calendar = {0};
      int64_t before_local, after_local, reconstructed;
      calendar.tm_year = local.calendar.year - 1900;
      calendar.tm_mon = local.calendar.month - 1;
      calendar.tm_mday = local.calendar.day;
      calendar.tm_hour = local.calendar.hour;
      calendar.tm_min = local.calendar.minute;
      calendar.tm_sec = local.calendar.second;
      CHECK(ftun_wallclock_unix_ms(&before_local) == FTUN_OK);
      reconstructed = (int64_t)_mkgmtime64(&calendar) * 1000 + local.calendar.millisecond -
        (int64_t)local.offset_minutes * 60000;
      CHECK(ftun_wallclock_unix_ms(&after_local) == FTUN_OK);
      CHECK(reconstructed >= before_local - 2000 && reconstructed <= after_local);
    }
#endif
  }
  CHECK(ftun_wallclock_unix_ms(&wall) == FTUN_OK);
  CHECK(llabs(wall - (int64_t)time(NULL) * 1000) < 2000);
  CHECK(ftun_process_exited(ftun_process_id(), &exited) == FTUN_OK && !exited);
  CHECK(ftun_random_bytes(random, sizeof(random)) == FTUN_OK);
  CHECK(ftun_platform_boot_identity(identity, sizeof(identity), &length) == FTUN_OK && length != 0u);
  CHECK(ftun_process_boot_token() != 0u);
  CHECK(ftun_process_alarm_start(&alarm, 5000u) == FTUN_OK);
  ftun_process_alarm_destroy(&alarm);
  CHECK(ftun_signals_block(FTUN_SIGNAL_HANGUP, &previous) == FTUN_OK);
  CHECK(ftun_thread_create(&thread, wait_signal, &received) == FTUN_OK);
  CHECK(ftun_process_signal(ftun_process_id(), FTUN_SIGNAL_HANGUP, &error) == FTUN_OK);
  CHECK(ftun_thread_join(&thread) == FTUN_OK && received);
  CHECK(ftun_signals_restore(&previous) == FTUN_OK);
}
#if defined(_WIN32)
static int full_pipe(void)
{
  HANDLE reader, writer;
  ftun_handle_t descriptor;
  ftun_status_t status;
  char bytes[4096] = {0};
  /* 使用原生匿名管道；Wine继承的Unix管道不支持Windows管道等待模式。 */
  CHECK(CreatePipe(&reader, &writer, NULL, 4096u));
  int original = _open_osfhandle((intptr_t)writer, _O_WRONLY | _O_BINARY);
  CHECK(original >= 0);
  CHECK(ftun_file_duplicate(original, &descriptor) == FTUN_OK);
  CHECK(ftun_file_close(original) == FTUN_OK);
  for (size_t i = 0u; i < 1024u; i++) {
    ptrdiff_t count = ftun_file_write_some(descriptor, bytes, sizeof(bytes), &status);
    if (status == FTUN_E_AGAIN) {
      CHECK(ftun_file_close(descriptor) == FTUN_OK);
      CHECK(CloseHandle(reader));
      return 0;
    }
    CHECK(count > 0 && status == FTUN_OK);
  }
  CHECK(false);
  return 1;
}
/* Wine继承的Unix管道不是Win32命名管道；用CreatePipe验证真实CLI有界写入。 */
static int cli_pipe(int argc, char **argv)
{
  HANDLE reader, writer;
  char output[16384];
  DWORD received;
  size_t used = 0u;
  CHECK(argc > 2 && strcmp(argv[2], "check") == 0);
  CHECK(CreatePipe(&reader, &writer, NULL, 65536u));
  int saved = _dup(1), saved_error = _dup(2);
  int descriptor = _open_osfhandle((intptr_t)writer, _O_WRONLY | _O_BINARY);
  CHECK(saved >= 0 && saved_error >= 0 && descriptor >= 0 &&
    _dup2(descriptor, 1) == 0 && _dup2(descriptor, 2) == 0);
  CHECK(_close(descriptor) == 0);
  int result = ftun_cli_main(argc - 1, argv + 1);
  CHECK(_dup2(saved, 1) == 0 && _close(saved) == 0 &&
    _dup2(saved_error, 2) == 0 && _close(saved_error) == 0);
  while (ReadFile(reader, output + used, (DWORD)(sizeof(output) - used), &received, NULL)) {
    used += received;
    CHECK(used < sizeof(output));
  }
  CHECK(GetLastError() == ERROR_BROKEN_PIPE && CloseHandle(reader));
  CHECK(used != 0u && fwrite(output, 1u, used, stdout) == used);
  return result;
}

#endif
int main(int argc, char **argv)
{
#if defined(_WIN32)
  if (argc == 2 && strcmp(argv[1], "pipe") == 0) return full_pipe();
  if (argc > 2 && strcmp(argv[1], "cli-pipe") == 0) return cli_pipe(argc, argv);
#endif
  /* 测试宿主暴露原生PID，外部驱动直接调用真实CLI的重载/停止路径。 */
  if (argc > 1) {
    printf("process-id: %lu\n", (unsigned long)ftun_process_id());
    fflush(stdout);
    return ftun_cli_main(argc, argv);
  }
  threads(); polling(); datagrams(FTUN_ADDRESS_IPV4); datagrams(FTUN_ADDRESS_IPV6); files(); pidfiles(); process();
  puts("portable platform contracts: passed");
  return 0;
}
