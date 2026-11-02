#include "core/config/fields.h"
#include "util/time_math.h"
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char *ftun_config_string_copy(ftun_config_t *config, const char *value)
{
  size_t length;
  char *copy;
  if (value == NULL) return NULL;
  length = strlen(value);
  if (length > FTUN_CONFIG_MAX_STRING_BYTES) return NULL;
  copy = (char *)ftun_config_allocate(config, length + 1u, 1u);
  if (copy == NULL) return NULL;
  memcpy(copy, value, length + 1u);
  return copy;
}

static int ftun_field_allowed(const char *field, const char *const *allowed,
                              size_t allowed_count)
{
  size_t index;
  for (index = 0u; index < allowed_count; index++) {
    if (strcmp(field, allowed[index]) == 0) return 1;
  }
  return 0;
}

ftun_status_t ftun_config_parse_failure(ftun_config_t *config, const cJSON *node,
  const char *missing, ftun_status_t status, const char *message)
{
  const ftun_config_document_t *document = ftun_config_document_header(config);
  if (document->parse_error == NULL) return status;
  return ftun_config_error_node(document->parse_error, status, document->parse_root,
    node, missing, message);
}

ftun_status_t ftun_config_check_fields(ftun_config_t *config, const cJSON *object,
  const char *const *allowed, size_t allowed_count)
{
  const cJSON *item;
  if (!cJSON_IsObject(object)) return ftun_config_parse_failure(config, object, NULL,
    FTUN_E_INVALID, "expected an object");
  for (item = object->child; item != NULL; item = item->next) {
    if (item->string == NULL || !ftun_field_allowed(item->string, allowed, allowed_count))
      return ftun_config_parse_failure(config, item, NULL, FTUN_E_INVALID, "unknown configuration field");
  }
  return FTUN_OK;
}

ftun_status_t ftun_config_replace_string(ftun_config_t *config, char **destination,
  const cJSON *object, const char *name, int required)
{
  const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
  char *copy;
  if (item == NULL) return required ? ftun_config_parse_failure(config, object, name,
    FTUN_E_INVALID, "required string is missing") : FTUN_OK;
  if (!cJSON_IsString(item) || item->valuestring == NULL)
    return ftun_config_parse_failure(config, item, NULL, FTUN_E_INVALID, "expected a string");
  copy = ftun_config_string_copy(config, item->valuestring);
  if (copy == NULL) return ftun_config_parse_failure(config, item, NULL,
    FTUN_E_LIMIT, "configuration string allocation failed");
  if (*destination != NULL) ftun_config_free_bytes(config, *destination, strlen(*destination) + 1u);
  *destination = copy;
  return FTUN_OK;
}

ftun_status_t ftun_config_optional_bool(ftun_config_t *config, const cJSON *object,
  const char *name, bool *value)
{
  const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
  if (item == NULL) return FTUN_OK;
  if (!cJSON_IsBool(item)) return ftun_config_parse_failure(config, item, NULL,
    FTUN_E_INVALID, "expected a boolean");
  *value = cJSON_IsTrue(item) != 0;
  return FTUN_OK;
}

ftun_status_t ftun_config_optional_uint(ftun_config_t *config, const cJSON *object,
  const char *name, uint32_t minimum, uint32_t maximum, uint32_t *value)
{
  const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
  double number;
  if (item == NULL) return FTUN_OK;
  if (!cJSON_IsNumber(item)) return ftun_config_parse_failure(config, item, NULL,
    FTUN_E_INVALID, "expected an integer");
  number = item->valuedouble;
  if (!isfinite(number) || number < (double)minimum || number > (double)maximum ||
      (double)(uint32_t)number != number) {
    char message[96];
    (void)snprintf(message, sizeof(message), "integer must be between %u and %u", minimum, maximum);
    return ftun_config_parse_failure(config, item, NULL, FTUN_E_INVALID, message);
  }
  *value = (uint32_t)number;
  return FTUN_OK;
}

ftun_status_t ftun_config_parse_string_list(ftun_config_t *config, const cJSON *object,
  const char *name, ftun_config_string_list_t *list, int require_nonempty)
{
  const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
  const cJSON *child;
  size_t count = 0u, index = 0u;
  if (!cJSON_IsArray(item)) return ftun_config_parse_failure(config,
    item != NULL ? item : object, item == NULL ? name : NULL, FTUN_E_INVALID, "expected an array");
  for (child = item->child; child != NULL; child = child->next) count++;
  if ((require_nonempty && count == 0u) || count > FTUN_CONFIG_MAX_ARRAY_ITEMS)
    return ftun_config_parse_failure(config, item, NULL,
      count == 0u ? FTUN_E_INVALID : FTUN_E_LIMIT, "array must contain a supported number of items");
  if (count == 0u) return FTUN_OK;
  list->items = (char **)ftun_config_allocate(config, count, sizeof(*list->items));
  if (list->items == NULL) return ftun_config_parse_failure(config, item, NULL,
    FTUN_E_LIMIT, "configuration array allocation failed");
  list->count = count;
  for (child = item->child; child != NULL; child = child->next, index++) {
    if (!cJSON_IsString(child) || child->valuestring == NULL)
      return ftun_config_parse_failure(config, child, NULL, FTUN_E_INVALID, "expected a string");
    list->items[index] = ftun_config_string_copy(config, child->valuestring);
    if (list->items[index] == NULL) return ftun_config_parse_failure(config, child, NULL,
      FTUN_E_LIMIT, "configuration string allocation failed");
  }
  return FTUN_OK;
}

ftun_status_t ftun_config_optional_duration(ftun_config_t *config, const cJSON *object,
  const char *name, bool allow_null, uint32_t *value)
{
  const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
  uint64_t milliseconds;
  if (item == NULL) return FTUN_OK;
  if (cJSON_IsNull(item)) {
    if (!allow_null) return ftun_config_parse_failure(config, item, NULL,
      FTUN_E_INVALID, "duration cannot be null");
    *value = 0u;
    return FTUN_OK;
  }
  if (!cJSON_IsString(item) || !ftun_duration_parse_ms(item->valuestring, &milliseconds))
    return ftun_config_parse_failure(config, item, NULL, FTUN_E_INVALID, "invalid duration");
  if (milliseconds > UINT32_MAX) return ftun_config_parse_failure(config, item, NULL,
    FTUN_E_INVALID, "duration exceeds supported range");
  *value = (uint32_t)milliseconds;
  return FTUN_OK;
}

void ftun_config_string_list_clear(ftun_config_string_list_t *list)
{
  size_t index;
  if (list == NULL) return;
  for (index = 0u; index < list->count; index++) free(list->items[index]);
  free(list->items);
  list->items = NULL;
  list->count = 0u;
}

