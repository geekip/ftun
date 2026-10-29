#include "core/config/document.h"
#include "core/limits.h"
#include <assert.h>
#include <math.h>
#include "platform/thread.h"
#include <stdlib.h>
#include <string.h>

/* cJSON 写入进程级错误位置；只串行解析，不锁业务模型构造。 */
static ftun_mutex_t parse_mutex = FTUN_MUTEX_INITIALIZER;

static ftun_config_document_t *header(ftun_config_t *config)
{
  return (ftun_config_document_t *)config;
}

ftun_status_t ftun_config_document_create(size_t size, ftun_budget_t *budget,
  const ftun_config_document_ops_t *ops, ftun_config_t **out)
{
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_config_document_t *document;
  ftun_status_t status;
  assert(size >= sizeof(*document));
  assert(ops != NULL && ops->prepare_destroy != NULL && ops->destroy != NULL && ops->section != NULL);
  if (out == NULL) return FTUN_E_INVALID;
  *out = NULL;
  if (budget != NULL) {
    status = ftun_budget_reserve(budget, size, &reservation);
    if (status != FTUN_OK) return status;
  }
  document = calloc(1u, size);
  if (document == NULL) {
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  document->reference_count = 1u;
  document->owned_bytes = size;
  document->budget = budget;
  document->reservation = reservation;
  document->ops = ops;
  *out = (ftun_config_t *)document;
  return FTUN_OK;
}

const void *ftun_config_document_section(const ftun_config_t *config, uint32_t section_id)
{
  const ftun_config_document_t *document = (const ftun_config_document_t *)config;
  return document->ops->section(config, section_id);
}

const ftun_config_modules_t *ftun_config_document_modules(const ftun_config_t *config)
{
  return ((const ftun_config_document_t *)config)->modules;
}

void *ftun_config_allocate(ftun_config_t *config, size_t count, size_t size)
{
  ftun_budget_resources_t resources = {0};
  size_t bytes;
  void *value;
  if (config == NULL || count == 0u || size == 0u || count > SIZE_MAX / size) return NULL;
  bytes = count * size;
  if (bytes > SIZE_MAX - header(config)->owned_bytes) return NULL;
  resources.memory_bytes = header(config)->owned_bytes + bytes;
  if ((header(config)->reservation).budget != NULL &&
      ftun_reservation_resize(&(header(config)->reservation), resources) != FTUN_OK) return NULL;
  value = calloc(count, size);
  if (value == NULL) {
    resources.memory_bytes = header(config)->owned_bytes;
    if ((header(config)->reservation).budget != NULL) (void)ftun_reservation_resize(&(header(config)->reservation), resources);
    return NULL;
  }
  header(config)->owned_bytes += bytes;
  return value;
}

void ftun_config_free_bytes(ftun_config_t *config, void *value, size_t bytes)
{
  ftun_budget_resources_t resources = {0};
  if (value == NULL) return;
  free(value);
  header(config)->owned_bytes -= bytes;
  resources.memory_bytes = header(config)->owned_bytes;
  if ((header(config)->reservation).budget != NULL) (void)ftun_reservation_resize(&(header(config)->reservation), resources);
}

ftun_status_t ftun_config_retain(ftun_config_t *config)
{
  ftun_config_document_t *document = header(config);
  if (config == NULL) return FTUN_E_INVALID;
  if (document->reference_count == 0u) return FTUN_E_STATE_CORRUPT;
  if (document->reference_count == SIZE_MAX) return FTUN_E_LIMIT;
  document->reference_count++;
  return FTUN_OK;
}

ftun_status_t ftun_config_destroy(ftun_config_t **config)
{
  ftun_config_t *owned;
  ftun_config_document_t *document;
  ftun_status_t status;
  if (config == NULL) return FTUN_E_INVALID;
  owned = *config;
  if (owned == NULL) return FTUN_OK;
  document = header(owned);
  if (document->reference_count == 0u) return FTUN_E_STATE_CORRUPT;
  if (document->reference_count > 1u) {
    document->reference_count--;
    *config = NULL;
    return FTUN_OK;
  }
  status = document->ops->prepare_destroy(owned);
  if (status != FTUN_OK) return status;
  ftun_reservation_release(&document->reservation);
  document->reference_count = 0u;
  *config = NULL;
  document->ops->destroy(owned);
  free(owned);
  return FTUN_OK;
}

static int ftun_utf8_valid(const unsigned char *text)
{
  size_t index = 0u;
  while (text[index] != 0u) {
    unsigned int codepoint;
    size_t remaining;
    unsigned char first = text[index];
    if (first < 0x80u) {
      index++;
      continue;
    }
    if (first >= 0xc2u && first <= 0xdfu) {
      codepoint = first & 0x1fu;
      remaining = 1u;
    } else if (first >= 0xe0u && first <= 0xefu) {
      codepoint = first & 0x0fu;
      remaining = 2u;
    } else if (first >= 0xf0u && first <= 0xf4u) {
      codepoint = first & 0x07u;
      remaining = 3u;
    } else {
      return 0;
    }
    while (remaining != 0u) {
      unsigned char next = text[index + 1u];
      if ((next & 0xc0u) != 0x80u) return 0;
      codepoint = (codepoint << 6u) | (next & 0x3fu);
      index++;
      remaining--;
    }
    if ((first == 0xe0u && codepoint < 0x800u) ||
        (first == 0xedu && codepoint >= 0xd800u) ||
        (first == 0xf0u && codepoint < 0x10000u) ||
        codepoint > 0x10ffffu ||
        (codepoint >= 0xd800u && codepoint <= 0xdfffu)) return 0;
    index++;
  }
  return 1;
}

static ftun_status_t ftun_json_preflight(ftun_bytes_t json, size_t *scratch_bytes)
{
  size_t index;
  size_t depth = 0u;
  size_t nodes = 1u;
  int in_string = 0;
  int escaped = 0;
  if (json.data == NULL || json.length == 0u) return FTUN_E_INVALID;
  if (json.length > FTUN_CONFIG_MAX_JSON_BYTES) return FTUN_E_LIMIT;
  for (index = 0u; index < json.length; index++) {
    unsigned char byte = json.data[index];
    if (byte == 0u) return FTUN_E_INVALID;
    if (in_string) {
      if (escaped) {
        if (byte == 'u') {
          uint32_t codepoint = 0u;
          size_t digit;
          if (index + 4u >= json.length) return FTUN_E_INVALID;
          for (digit = 1u; digit <= 4u; digit++) {
            unsigned char value = json.data[index + digit];
            uint32_t nibble;
            if (value >= '0' && value <= '9') nibble = value - '0';
            else if (value >= 'a' && value <= 'f') nibble = value - 'a' + 10u;
            else if (value >= 'A' && value <= 'F') nibble = value - 'A' + 10u;
            else return FTUN_E_INVALID;
            codepoint = (codepoint << 4u) | nibble;
          }
          index += 4u;
          if (codepoint == 0u || (codepoint >= 0xdc00u && codepoint <= 0xdfffu)) {
            return FTUN_E_INVALID;
          }
          if (codepoint >= 0xd800u && codepoint <= 0xdbffu) {
            uint32_t low = 0u;
            if (index + 6u >= json.length || json.data[index + 1u] != '\\' ||
                json.data[index + 2u] != 'u') return FTUN_E_INVALID;
            for (digit = 3u; digit <= 6u; digit++) {
              unsigned char value = json.data[index + digit];
              uint32_t nibble;
              if (value >= '0' && value <= '9') nibble = value - '0';
              else if (value >= 'a' && value <= 'f') nibble = value - 'a' + 10u;
              else if (value >= 'A' && value <= 'F') nibble = value - 'A' + 10u;
              else return FTUN_E_INVALID;
              low = (low << 4u) | nibble;
            }
            if (low < 0xdc00u || low > 0xdfffu) return FTUN_E_INVALID;
            index += 6u;
          }
        }
        escaped = 0;
      } else if (byte == '\\') {
        escaped = 1;
      } else if (byte == '"') {
        in_string = 0;
      }
      continue;
    }
    if (byte == '"') {
      in_string = 1;
    } else if (byte == '{' || byte == '[') {
      size_t next = index + 1u;
      depth++;
      if (depth > FTUN_CONFIG_MAX_DEPTH) return FTUN_E_LIMIT;
      while (next < json.length && json.data[next] <= 0x20u) next++;
      /* cJSON为非空容器首项及每个逗号后的项分配节点，键与值共用一项。 */
      if (next == json.length || json.data[next] != (byte == '{' ? '}' : ']')) nodes++;
    } else if (byte == ',') {
      nodes++;
    } else if (byte == '}' || byte == ']') {
      if (depth == 0u) return FTUN_E_INVALID;
      depth--;
    }
    if (nodes > FTUN_CONFIG_MAX_NODES) return FTUN_E_LIMIT;
  }
  /* 输入副本、所有字符串及当前数字解析副本的保守同时存活上界。
   * cJSON节点在分配前已计数，不切换进程全局allocator hooks。 */
  *scratch_bytes = nodes * sizeof(cJSON) + 3u * (json.length + 1u);
  return in_string || escaped || depth != 0u ? FTUN_E_INVALID : FTUN_OK;
}

static ftun_status_t ftun_json_tree_check(const cJSON *item, size_t depth,
                                          size_t *nodes)
{
  const cJSON *child;
  size_t children = 0u;
  if (item == NULL || nodes == NULL) return FTUN_E_INVALID;
  if (depth > FTUN_CONFIG_MAX_DEPTH || *nodes >= FTUN_CONFIG_MAX_NODES) {
    return FTUN_E_LIMIT;
  }
  (*nodes)++;
  if (item->string != NULL &&
      strlen(item->string) > FTUN_CONFIG_MAX_STRING_BYTES) return FTUN_E_LIMIT;
  if (item->string != NULL &&
      !ftun_utf8_valid((const unsigned char *)item->string)) return FTUN_E_INVALID;
  if (cJSON_IsString(item) && item->valuestring == NULL) return FTUN_E_INVALID;
  if (cJSON_IsString(item) &&
      strlen(item->valuestring) > FTUN_CONFIG_MAX_STRING_BYTES) return FTUN_E_LIMIT;
  if (cJSON_IsString(item) &&
      !ftun_utf8_valid((const unsigned char *)item->valuestring)) return FTUN_E_INVALID;
  if (cJSON_IsNumber(item) && !isfinite(item->valuedouble)) return FTUN_E_INVALID;
  if (cJSON_IsObject(item)) {
    const cJSON *other;
    for (child = item->child; child != NULL; child = child->next) {
      children++;
      for (other = child->next; other != NULL; other = other->next) {
        if (child->string != NULL && other->string != NULL &&
            strcmp(child->string, other->string) == 0) return FTUN_E_INVALID;
      }
    }
  } else if (cJSON_IsArray(item)) {
    for (child = item->child; child != NULL; child = child->next) children++;
  }
  if (children > FTUN_CONFIG_MAX_ARRAY_ITEMS) return FTUN_E_LIMIT;
  for (child = item->child; child != NULL; child = child->next) {
    ftun_status_t status = ftun_json_tree_check(child, depth + 1u, nodes);
    if (status != FTUN_OK) return status;
  }
  return FTUN_OK;
}

ftun_status_t ftun_config_json_open(ftun_budget_t *budget, ftun_bytes_t json,
  ftun_config_json_t *out)
{
  char *input;
  cJSON *root;
  size_t nodes = 0u, scratch_bytes;
  ftun_reservation_t scratch = (ftun_reservation_t){0};
  ftun_status_t status;
  if (out == NULL) return FTUN_E_INVALID;
  memset(out, 0, sizeof(*out));
  if (json.length >= 3u && json.data != NULL && json.data[0] == 0xefu &&
      json.data[1] == 0xbbu && json.data[2] == 0xbfu) {
    json.data += 3u;
    json.length -= 3u;
    if (json.length >= 3u && json.data[0] == 0xefu &&
        json.data[1] == 0xbbu && json.data[2] == 0xbfu) {
      return FTUN_E_INVALID;
    }
  }
  status = ftun_json_preflight(json, &scratch_bytes);
  if (status != FTUN_OK) return status;
  if (budget != NULL) {
    status = ftun_budget_reserve(budget, scratch_bytes, &scratch);
    if (status != FTUN_OK) return status;
  }
  input = (char *)malloc(json.length + 1u);
  if (input == NULL) {
    ftun_reservation_release(&scratch);
    return FTUN_E_LIMIT;
  }
  memcpy(input, json.data, json.length);
  input[json.length] = '\0';
  ftun_mutex_lock(&parse_mutex);
  root = cJSON_ParseWithLengthOpts(input, json.length + 1u, NULL, 1);
  ftun_mutex_unlock(&parse_mutex);
  free(input);
  if (root == NULL || !cJSON_IsObject(root)) {
    cJSON_Delete(root);
    ftun_reservation_release(&scratch);
    return FTUN_E_INVALID;
  }
  status = ftun_json_tree_check(root, 1u, &nodes);
  if (status != FTUN_OK) {
    cJSON_Delete(root);
    ftun_reservation_release(&scratch);
    return status;
  }
  out->root = root;
  out->reservation = scratch;
  return FTUN_OK;
}

void ftun_config_json_close(ftun_config_json_t *document)
{
  if (document == NULL) return;
  cJSON_Delete(document->root);
  ftun_reservation_release(&document->reservation);
  document->root = NULL;
}
