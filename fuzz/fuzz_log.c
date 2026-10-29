#include "fuzz_common.h"

#include "core/limits.h"
#include "core/log/log.h"

#include <pthread.h>
#include <string.h>

/* 日志格式化：对端文本（诊断的 message/path）无论含什么字节，写出的每一行都只能
 * 在末尾有一个换行，其余字节不能是控制字符，防止伪造日志行或终端控制序列。 */
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static uint8_t captured[16384];
static size_t captured_length;
static unsigned int lines;
static ftun_logger_t *logger;

static ftun_status_t capture(void *user, ftun_bytes_t line)
{
  (void)user;
  (void)pthread_mutex_lock(&lock);
  if (line.length <= sizeof(captured) - captured_length) {
    memcpy(captured + captured_length, line.data, line.length);
    captured_length += line.length;
  }
  lines++;
  (void)pthread_mutex_unlock(&lock);
  return FTUN_OK;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  ftun_logger_options_t options;
  (void)argc;
  (void)argv;
  memset(&options, 0, sizeof(options));
  options.level = FTUN_LOG_TRACE;
  options.queue_capacity = 8u;
  options.writer = capture;
  FUZZ_REQUIRE(ftun_logger_create(&options, &logger) == FTUN_OK);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  ftun_diagnostic_t diagnostic;
  size_t split = size == 0u ? 0u : data[0] % (size + 1u);
  size_t index;
  ftun_status_t status;
  memset(&diagnostic, 0, sizeof(diagnostic));
  diagnostic.error.status = FTUN_E_IO;
  diagnostic.message = (ftun_string_t){(const char *)data, split};
  diagnostic.path = (ftun_string_t){(const char *)data + split, size - split};
  (void)pthread_mutex_lock(&lock);
  captured_length = 0u;
  lines = 0u;
  (void)pthread_mutex_unlock(&lock);
  status = ftun_logger_write(logger, FTUN_LOG_ERROR, &diagnostic);
  FUZZ_NOT_CORRUPT(status);
  FUZZ_REQUIRE(ftun_logger_flush(logger) == FTUN_OK);
  (void)pthread_mutex_lock(&lock);
  FUZZ_REQUIRE(lines <= 1u);
  if (captured_length != 0u) {
    FUZZ_REQUIRE(captured[captured_length - 1u] == '\n');
    for (index = 0u; index + 1u < captured_length; index++) {
      FUZZ_REQUIRE(captured[index] >= 0x20u && captured[index] != 0x7fu);
    }
  }
  (void)pthread_mutex_unlock(&lock);
  return 0;
}

void ftun_fuzz_seeds(ftun_fuzz_seed_fn add)
{
  static const uint8_t plain[] = "\x08" "disk full/var/log/ftun.log";
  static const uint8_t control[] = "\x05" "a\nb\r\x1b[31mc\x7f\x00" "tail";
  static const uint8_t utf8[] = "\x03" "\xe6\x97\xa5\xe6\x9c\xac\xff\xfe";
  add(plain, sizeof(plain) - 1u);
  add(control, sizeof(control) - 1u);
  add(utf8, sizeof(utf8) - 1u);
}
