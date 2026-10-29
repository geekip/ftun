#include "core/config/fields.h"
#include "util/time_math.h"
#include <math.h>
#include <stdlib.h>
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

ftun_status_t ftun_config_check_fields(const cJSON *object,
                                       const char *const *allowed,
                                       size_t allowed_count)
{
  const cJSON *item;
  if (!cJSON_IsObject(object)) return FTUN_E_INVALID;
  for (item = object->child; item != NULL; item = item->next) {
    if (item->string == NULL ||
        !ftun_field_allowed(item->string, allowed, allowed_count)) {
      return FTUN_E_INVALID;
    }
  }
  return FTUN_OK;
}

ftun_status_t ftun_config_replace_string(ftun_config_t *config, char **destination, const cJSON *item,
                                         int required)
{
  char *copy;
  if (item == NULL) return required ? FTUN_E_INVALID : FTUN_OK;
  if (!cJSON_IsString(item) || item->valuestring == NULL) return FTUN_E_INVALID;
  copy = ftun_config_string_copy(config, item->valuestring);
  if (copy == NULL) return FTUN_E_LIMIT;
  if (*destination != NULL) ftun_config_free_bytes(config, *destination, strlen(*destination) + 1u);
  *destination = copy;
  return FTUN_OK;
}

ftun_status_t ftun_config_optional_bool(const cJSON *object, const char *name,
                                        bool *value)
{
  const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
  if (item == NULL) return FTUN_OK;
  if (!cJSON_IsBool(item)) return FTUN_E_INVALID;
  *value = cJSON_IsTrue(item) != 0;
  return FTUN_OK;
}

ftun_status_t ftun_config_optional_uint(const cJSON *object, const char *name,
                                        uint32_t minimum, uint32_t maximum,
                                        uint32_t *value)
{
  const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
  double number;
  if (item == NULL) return FTUN_OK;
  if (!cJSON_IsNumber(item)) return FTUN_E_INVALID;
  number = item->valuedouble;
  if (!isfinite(number) || number < (double)minimum || number > (double)maximum ||
      (double)(uint32_t)number != number) return FTUN_E_INVALID;
  *value = (uint32_t)number;
  return FTUN_OK;
}

ftun_status_t ftun_config_parse_string_list(ftun_config_t *config, const cJSON *item,
                                            ftun_config_string_list_t *list,
                                            int require_nonempty)
{
  const cJSON *child;
  size_t count = 0u;
  size_t index = 0u;
  if (!cJSON_IsArray(item)) return FTUN_E_INVALID;
  for (child = item->child; child != NULL; child = child->next) count++;
  if ((require_nonempty && count == 0u) || count > FTUN_CONFIG_MAX_ARRAY_ITEMS) {
    return count == 0u ? FTUN_E_INVALID : FTUN_E_LIMIT;
  }
  if (count == 0u) return FTUN_OK;
  list->items = (char **)ftun_config_allocate(config, count, sizeof(*list->items));
  if (list->items == NULL) return FTUN_E_LIMIT;
  list->count = count;
  for (child = item->child; child != NULL; child = child->next, index++) {
    if (!cJSON_IsString(child) || child->valuestring == NULL) return FTUN_E_INVALID;
    list->items[index] = ftun_config_string_copy(config, child->valuestring);
    if (list->items[index] == NULL) return FTUN_E_LIMIT;
  }
  return FTUN_OK;
}

ftun_status_t ftun_config_optional_duration(const cJSON *object, const char *name,
                                            bool allow_null, uint32_t *value)
{
  const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
  uint64_t milliseconds;
  if (item == NULL) return FTUN_OK;
  if (cJSON_IsNull(item)) {
    if (!allow_null) return FTUN_E_INVALID;
    *value = 0u;
    return FTUN_OK;
  }
  if (!cJSON_IsString(item) || !ftun_duration_parse_ms(item->valuestring, &milliseconds) ||
      milliseconds > UINT32_MAX) return FTUN_E_INVALID;
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

