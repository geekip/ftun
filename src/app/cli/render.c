#include "app/cli/render.h"
#include "app/cli/args.h"
#include "platform/file.h"
#include "platform/clock.h"
#include "platform/thread.h"

#include <stdio.h>
#include <string.h>

int ftun_cli_output(int descriptor, const char *text)
{
  size_t length = strlen(text), offset = 0u;
  uint64_t started, now;
  if (ftun_monotonic_now(&started) != FTUN_OK) return FTUN_EXIT_FAIL;
  if (ftun_thread_block_sigpipe() != FTUN_OK) return FTUN_EXIT_FAIL;
  while (offset < length) {
    size_t count = length - offset < 512u ? length - offset : 512u;
    if (ftun_monotonic_now(&now) != FTUN_OK || now - started >= 2000u) return FTUN_EXIT_FAIL;
    ftun_status_t status = ftun_platform_file_write_ready(descriptor,
      (ftun_bytes_t){(const uint8_t *)text + offset, count});
    if (status == FTUN_E_AGAIN) {
      if (ftun_monotonic_now(&now) != FTUN_OK || now - started >= 2000u) return FTUN_EXIT_FAIL;
      uint32_t remaining = (uint32_t)(2000u - (now - started));
      status = ftun_file_wait_writable(descriptor, remaining < 50u ? remaining : 50u);
      if (status != FTUN_OK && status != FTUN_E_AGAIN) return FTUN_EXIT_FAIL;
      continue;
    }
    if (status != FTUN_OK) return FTUN_EXIT_FAIL;
    offset += count;
  }
  return FTUN_EXIT_OK;
}

int ftun_cli_json_write(cJSON *object)
{
  char *text = object == NULL ? NULL : cJSON_PrintUnformatted(object);
  int result = FTUN_EXIT_FAIL;
  cJSON_Delete(object);
  if (text != NULL) {
    if (ftun_cli_output(1, text) == FTUN_EXIT_OK &&
        ftun_cli_output(1, "\n") == FTUN_EXIT_OK) result = FTUN_EXIT_OK;
    cJSON_free(text);
  }
  if (result != FTUN_EXIT_OK) (void)ftun_cli_output(2, "ftun: JSON output failed\n");
  return result;
}

int ftun_cli_failure(const char *operation, const char *result,
  const char *message, bool json)
{
  if (json) {
    cJSON *object = cJSON_CreateObject();
    if (object == NULL || cJSON_AddStringToObject(object, "result", result) == NULL ||
        cJSON_AddStringToObject(object, "op", operation) == NULL ||
        cJSON_AddStringToObject(object, "message", message) == NULL) {
      cJSON_Delete(object);
      object = NULL;
    }
    (void)ftun_cli_json_write(object);
  } else {
    char text[1024];
    (void)snprintf(text, sizeof(text), "ftun: %s: %s\n", operation, message);
    (void)ftun_cli_output(2, text);
  }
  return FTUN_EXIT_FAIL;
}
