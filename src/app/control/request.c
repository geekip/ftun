#include "app/control/request.h"
#include "core/config/document.h"
#include <string.h>

ftun_status_t ftun_ctl_request_parse(ftun_budget_t *budget, ftun_bytes_t input,
  ftun_ctl_request_t *out)
{
  static const char *const operations[] = {
    "status", "dns.status", "proxy.status", "reload", "stop"
  };
  ftun_config_json_t document;
  ftun_ctl_request_t request = {0};
  const cJSON *field, *op, *boot, *timeout;
  ftun_status_t status;
  size_t i;
  memset(out, 0, sizeof(*out));
  if (input.length > FTUN_CTL_REQUEST_MAX) return FTUN_E_LIMIT;
  if (input.data == NULL || input.length == 0u ||
      memchr(input.data, '\n', input.length) != NULL ||
      memchr(input.data, '\r', input.length) != NULL) return FTUN_E_INVALID;
  status = ftun_config_json_try_open(budget, input, &document);
  if (status != FTUN_OK) return status;
  status = FTUN_E_INVALID;
  for (field = document.root->child; field != NULL; field = field->next) {
    if (strcmp(field->string, "op") != 0 && strcmp(field->string, "boot") != 0 &&
        strcmp(field->string, "timeout_ms") != 0) goto done;
  }
  op = cJSON_GetObjectItemCaseSensitive(document.root, "op");
  boot = cJSON_GetObjectItemCaseSensitive(document.root, "boot");
  timeout = cJSON_GetObjectItemCaseSensitive(document.root, "timeout_ms");
  if (!cJSON_IsString(op)) goto done;
  for (i = 0u; i < sizeof(operations) / sizeof(operations[0]); i++) {
    if (strcmp(op->valuestring, operations[i]) == 0) {
      request.operation = (ftun_ctl_operation_t)(i + 1u);
      break;
    }
  }
  if (request.operation == 0) goto done;
  request.timeout_ms = request.operation == FTUN_CTL_RELOAD ? 30000u :
    request.operation == FTUN_CTL_STOP ? 15000u : 5000u;
  if (timeout != NULL) {
    double value;
    if (!cJSON_IsNumber(timeout)) goto done;
    value = timeout->valuedouble;
    if (value < 0.0 || value > FTUN_CTL_TIMEOUT_MAX ||
        value != (double)(uint32_t)value) goto done;
    request.timeout_ms = (uint32_t)value;
    if (request.timeout_ms == 0u && request.operation != FTUN_CTL_RELOAD &&
        request.operation != FTUN_CTL_STOP) goto done;
  }
  if (boot != NULL) {
    if (!cJSON_IsString(boot) || strlen(boot->valuestring) != 16u) goto done;
    for (i = 0u; i < 16u; i++) {
      unsigned char value = (unsigned char)boot->valuestring[i];
      uint64_t digit;
      if (value >= '0' && value <= '9') digit = value - '0';
      else if (value >= 'a' && value <= 'f') digit = value - 'a' + 10u;
      else if (value >= 'A' && value <= 'F') digit = value - 'A' + 10u;
      else goto done;
      request.boot = (request.boot << 4u) | digit;
    }
    request.boot_present = true;
  }
  *out = request;
  status = FTUN_OK;
done:
  ftun_config_json_close(&document);
  return status;
}
