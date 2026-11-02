#include "core/config/error.h"
#include "core/config/document.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* JSON Pointer规则沿用已有cJSON_Utils的树定位/转义方式；改用有界栈和拥有缓冲，
 * 不调用其逐层堆分配的FindPointerFromObjectTo。 */
typedef struct { const char *key; size_t index; bool array; } part_t;
typedef struct { char *data; size_t used, capacity; bool *truncated; bool full; } output_t;

static bool atom(output_t *out, const char *data, size_t size)
{
  if (out->full) return false;
  if (size >= out->capacity - out->used) {
    out->full = true;
    *out->truncated = true;
    return false;
  }
  memcpy(out->data + out->used, data, size);
  out->used += size;
  out->data[out->used] = '\0';
  return true;
}

static void literal(output_t *out, const char *text)
{
  (void)atom(out, text, strlen(text));
}

static size_t utf8_bytes(unsigned char first)
{
  return first < 0x80u ? 1u : first < 0xe0u ? 2u : first < 0xf0u ? 3u : 4u;
}

static void pointer_key(output_t *out, const char *key)
{
  size_t index = 0u;
  if (!atom(out, "/", 1u)) return;
  while (key[index] != '\0') {
    size_t size = utf8_bytes((unsigned char)key[index]);
    if (key[index] == '~' || key[index] == '/') {
      if (!atom(out, key[index] == '~' ? "~0" : "~1", 2u)) return;
    } else if (!atom(out, key + index, size)) return;
    index += size;
  }
}

static bool identifier(const char *key)
{
  size_t index;
  if (!((key[0] >= 'a' && key[0] <= 'z') || (key[0] >= 'A' && key[0] <= 'Z') || key[0] == '_')) return false;
  for (index = 1u; key[index] != '\0'; ++index) {
    char byte = key[index];
    if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
        (byte >= '0' && byte <= '9') || byte == '_' || byte == '-')) return false;
  }
  return true;
}

static void field_key(output_t *out, const char *key)
{
  size_t index = 0u, capacity;
  bool full;
  if (identifier(key)) {
    if (out->used != 0u && !atom(out, ".", 1u)) return;
    while (key[index] != '\0') {
      if (!atom(out, key + index, 1u)) return;
      index++;
    }
    return;
  }
  if (out->full) return;
  if (out->capacity - out->used <= 4u) { *out->truncated = true; out->full = true; return; }
  literal(out, "[\"");
  capacity = out->capacity;
  out->capacity -= 2u;
  while (key[index] != '\0') {
    unsigned char byte = (unsigned char)key[index];
    size_t size = utf8_bytes(byte);
    char escaped[7];
    if (byte == '\\' || byte == '"') {
      escaped[0] = '\\'; escaped[1] = (char)byte;
      if (!atom(out, escaped, 2u)) break;
    } else if (byte < 0x20u || byte == 0x7fu) {
      (void)snprintf(escaped, sizeof(escaped), "\\u%04x", (unsigned int)byte);
      if (!atom(out, escaped, 6u)) break;
    } else if (!atom(out, key + index, size)) break;
    index += size;
  }
  full = out->full;
  out->capacity = capacity;
  out->full = false;
  literal(out, "\"]");
  out->full = full || out->full;
}

static void index_part(output_t *out, size_t index, bool display)
{
  char text[32];
  (void)snprintf(text, sizeof(text), display ? "[%zu]" : "/%zu", index);
  literal(out, text);
}

static bool locate(const cJSON *root, const cJSON *target, part_t *parts,
  size_t depth, size_t *count)
{
  const cJSON *child;
  size_t index = 0u;
  if (root == target) { *count = depth; return true; }
  for (child = root->child; child != NULL; child = child->next, ++index) {
    parts[depth] = (part_t){child->string, index, cJSON_IsArray(root) != 0};
    if (locate(child, target, parts, depth + 1u, count)) return true;
  }
  return false;
}

static void display_pointer(ftun_config_error_t *error)
{
  const char *cursor = error->pointer;
  output_t out = {error->field, 0u, sizeof(error->field), &error->truncated, false};
  while (*cursor == '/') {
    char key[FTUN_CONFIG_ERROR_PATH_BYTES];
    size_t used = 0u, index;
    bool number = true;
    cursor++;
    while (*cursor != '\0' && *cursor != '/') {
      if (*cursor == '~' && (cursor[1] == '0' || cursor[1] == '1')) {
        key[used++] = cursor[1] == '0' ? '~' : '/';
        cursor += 2u;
      } else key[used++] = *cursor++;
    }
    key[used] = '\0';
    for (index = 0u; index < used; ++index)
      if (key[index] < '0' || key[index] > '9') number = false;
    if (number && used != 0u) {
      literal(&out, "["); literal(&out, key); literal(&out, "]");
    } else field_key(&out, key);
  }
  if (out.used == 0u) literal(&out, "<root>");
}

void ftun_config_error_begin(ftun_config_error_t *error, ftun_config_step_t phase)
{
  if (error == NULL) return;
  memset(error, 0, sizeof(*error));
  error->phase = phase;
}

static ftun_status_t begin_error(ftun_config_error_t *error, ftun_status_t status,
  const char *message)
{
  int count;
  error->error.status = status;
  error->error.stage = error->phase == FTUN_CONFIG_STEP_READ
    ? FTUN_STAGE_CONFIG_READ : FTUN_STAGE_CONFIG_PREPARE;
  count = snprintf(error->message, sizeof(error->message), "%s", message);
  if (count >= (int)sizeof(error->message)) error->truncated = true;
  return status;
}

ftun_status_t ftun_config_error_setf(ftun_config_error_t *error, ftun_status_t status,
  const char *message, const char *format, ...)
{
  va_list arguments;
  int count;
  if (error == NULL) return status;
  if (error->error.status != FTUN_OK) return error->error.status;
  (void)begin_error(error, status, message);
  va_start(arguments, format);
  count = vsnprintf(error->pointer, sizeof(error->pointer), format, arguments);
  va_end(arguments);
  if (count >= (int)sizeof(error->pointer)) {
    size_t end = sizeof(error->pointer) - 1u, start = end;
    /* 找到末尾字符的首字节；只有不完整字符才移除。 */
    while (start != 0u && ((unsigned char)error->pointer[start - 1u] & 0xc0u) == 0x80u) start--;
    if (start != 0u && utf8_bytes((unsigned char)error->pointer[start - 1u]) > end - start + 1u) end = start - 1u;
    if (end != 0u && error->pointer[end - 1u] == '~') end--;
    error->pointer[end] = '\0';
    error->truncated = true;
  }
  display_pointer(error);
  return status;
}

ftun_status_t ftun_config_error_set(ftun_config_error_t *error, ftun_status_t status,
  const char *pointer, const char *message)
{
  return ftun_config_error_setf(error, status, message, "%s", pointer);
}

ftun_status_t ftun_config_error_node(ftun_config_error_t *error, ftun_status_t status,
  const cJSON *root, const cJSON *node, const char *missing, const char *message)
{
  part_t parts[FTUN_CONFIG_MAX_DEPTH];
  size_t count = 0u, index;
  bool found;
  output_t pointer, field;
  if (error == NULL) return status;
  if (error->error.status != FTUN_OK) return error->error.status;
  found = locate(root, node, parts, 0u, &count);
  assert(found); (void)found;
  (void)begin_error(error, status, message);
  pointer = (output_t){error->pointer, 0u, sizeof(error->pointer), &error->truncated, false};
  field = (output_t){error->field, 0u, sizeof(error->field), &error->truncated, false};
  for (index = 0u; index < count; ++index) {
    if (parts[index].array) {
      index_part(&pointer, parts[index].index, false);
      index_part(&field, parts[index].index, true);
    } else {
      pointer_key(&pointer, parts[index].key);
      field_key(&field, parts[index].key);
    }
  }
  if (missing != NULL) { pointer_key(&pointer, missing); field_key(&field, missing); }
  if (field.used == 0u) literal(&field, "<root>");
  return status;
}

const char *ftun_config_step_name(ftun_config_step_t step)
{
  static const char *const names[] = {"none", "read", "parse", "paths", "validate", "compile", "attachments"};
  return step >= FTUN_CONFIG_STEP_NONE && step <= FTUN_CONFIG_STEP_ATTACHMENTS ? names[step] : "unknown";
}

size_t ftun_config_error_json(const ftun_config_error_t *error, char *output, size_t capacity)
{
  cJSON root = {0}, fields[6] = {{0}};
  static const char *const names[] = {"phase", "pointer", "field", "message", "truncated", "offset"};
  const char *values[] = {ftun_config_step_name(error->phase), error->pointer,
    error->field, error->message};
  size_t index, count = error->offset_valid ? 6u : 5u;
  root.type = cJSON_Object;
  root.child = fields;
  for (index = 0u; index < count; index++) {
    fields[index].string = (char *)names[index];
    if (index + 1u < count) fields[index].next = &fields[index + 1u];
    if (index != 0u) fields[index].prev = &fields[index - 1u];
    if (index < 4u) {
      fields[index].type = cJSON_String;
      fields[index].valuestring = (char *)values[index];
    } else if (index == 4u) fields[index].type = error->truncated ? cJSON_True : cJSON_False;
    else {
      fields[index].type = cJSON_Number;
      fields[index].valuedouble = (double)error->offset;
    }
  }
  if (!cJSON_PrintPreallocated(&root, output, (int)capacity, 0)) return 0u;
  return strlen(output);
}
