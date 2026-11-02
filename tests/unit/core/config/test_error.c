#include "core/config/document.h"
#include "core/config/error.h"
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "config error failed at %d: %s\n", __LINE__, #x); return 1; } } while (0)

static ftun_status_t open_text(const char *text, ftun_config_json_t *out)
{
  return ftun_config_json_open(NULL, (ftun_bytes_t){(const uint8_t *)text, strlen(text)}, out);
}

int main(void)
{
  const char *json = "{\"outbounds\":[{},{},{\"server\":7}],\"a~/b\":{\"0\":{\"x.y\\n\":false}},\"\":true}";
  ftun_config_json_t document;
  ftun_config_error_t error, copy;
  const cJSON *array, *third, *node;
  char long_key[1600], input[1800], encoded[2200];
  size_t index;
  CHECK(open_text(json, &document) == FTUN_OK);
  array = cJSON_GetObjectItemCaseSensitive(document.root, "outbounds");
  third = cJSON_GetArrayItem(array, 2);
  node = cJSON_GetObjectItemCaseSensitive(third, "server");
  ftun_config_error_begin(&error, FTUN_CONFIG_STEP_PARSE);
  CHECK(ftun_config_error_node(&error, FTUN_E_INVALID, document.root, node, NULL, "expected a string") == FTUN_E_INVALID);
  CHECK(strcmp(error.pointer, "/outbounds/2/server") == 0 && strcmp(error.field, "outbounds[2].server") == 0);
  CHECK(error.phase == FTUN_CONFIG_STEP_PARSE && error.error.stage == FTUN_STAGE_CONFIG_PREPARE && !error.truncated);
  copy = error;
  CHECK(ftun_config_error_set(&error, FTUN_E_LIMIT, "/later", "later error") == FTUN_E_INVALID);
  CHECK(memcmp(&copy, &error, sizeof(copy)) == 0);
  ftun_config_error_begin(&error, FTUN_CONFIG_STEP_PARSE);
  CHECK(ftun_config_error_node(&error, FTUN_E_INVALID, document.root, cJSON_GetArrayItem(array, 0), "server", "missing string") == FTUN_E_INVALID);
  CHECK(strcmp(error.pointer, "/outbounds/0/server") == 0 && strcmp(error.field, "outbounds[0].server") == 0);
  ftun_config_error_begin(&error, FTUN_CONFIG_STEP_PARSE);
  node = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(
    cJSON_GetObjectItemCaseSensitive(document.root, "a~/b"), "0"), "x.y\n");
  CHECK(ftun_config_error_node(&error, FTUN_E_INVALID, document.root, node, NULL, "invalid bool") == FTUN_E_INVALID);
  CHECK(strcmp(error.pointer, "/a~0~1b/0/x.y\n") == 0);
  CHECK(strcmp(error.field, "[\"a~/b\"][\"0\"][\"x.y\\u000a\"]") == 0);
  ftun_config_error_begin(&error, FTUN_CONFIG_STEP_PARSE);
  CHECK(ftun_config_error_node(&error, FTUN_E_INVALID, document.root,
    cJSON_GetObjectItemCaseSensitive(document.root, ""), NULL, "unknown field") == FTUN_E_INVALID);
  CHECK(strcmp(error.pointer, "/") == 0 && strcmp(error.field, "[\"\"]") == 0);
  ftun_config_json_close(&document);
  CHECK(strcmp(copy.pointer, "/outbounds/2/server") == 0 && strcmp(copy.message, "expected a string") == 0);
  ftun_config_error_begin(&error, FTUN_CONFIG_STEP_VALIDATE);
  CHECK(ftun_config_error_setf(&error, FTUN_E_INVALID, "invalid server", "/outbounds/%zu/server", (size_t)2u) == FTUN_E_INVALID);
  CHECK(strcmp(error.pointer, copy.pointer) == 0 && strcmp(error.field, copy.field) == 0);

  for (index = 0u; index < 1500u; index += 3u) memcpy(long_key + index, "\xe4\xb8\xad", 3u);
  long_key[1500] = '\0';
  ftun_config_error_begin(&error, FTUN_CONFIG_STEP_VALIDATE);
  CHECK(ftun_config_error_setf(&error, FTUN_E_INVALID, "long field", "/%s/server", long_key) == FTUN_E_INVALID);
  CHECK(error.truncated && strlen(error.pointer) < sizeof(error.pointer));
  (void)snprintf(encoded, sizeof(encoded), "{\"path\":\"%s\"}", error.pointer);
  CHECK(open_text(encoded, &document) == FTUN_OK);
  ftun_config_json_close(&document);
  (void)snprintf(input, sizeof(input), "{\"%s\":{\"server\":0}}", long_key);
  CHECK(open_text(input, &document) == FTUN_OK);
  node = cJSON_GetObjectItemCaseSensitive(document.root->child, "server");
  ftun_config_error_begin(&error, FTUN_CONFIG_STEP_PARSE);
  CHECK(ftun_config_error_node(&error, FTUN_E_INVALID, document.root, node, NULL, "long key") == FTUN_E_INVALID);
  CHECK(error.truncated && strstr(error.pointer, "server") == NULL && strstr(error.field, "server") == NULL);
  CHECK(strlen(error.field) >= 2u && strcmp(error.field + strlen(error.field) - 2u, "\"]") == 0);
  ftun_config_json_close(&document);
  ftun_config_error_begin(&error, FTUN_CONFIG_STEP_READ);
  CHECK(ftun_config_error_set(&error, FTUN_E_IO, "", "cannot read configuration") == FTUN_E_IO);
  CHECK(error.error.stage == FTUN_STAGE_CONFIG_READ && strcmp(error.field, "<root>") == 0);
  CHECK(strcmp(ftun_config_step_name(FTUN_CONFIG_STEP_ATTACHMENTS), "attachments") == 0);
  {
    const char *duplicate = "{\"dns\":{\"enable\":true,\"enable\":false}}";
    const char *finite = "{\"outbounds\":[{\"port\":1e1000}]}";
    const char *invalid = "{\"a\":}";
    const char *bom = "\xef\xbb\xbf{\"a\":}";
    const char bad_utf8[] = {'{', '"', (char)0xc0, (char)0xaf, '"', ':', '0', '}'};
    CHECK(ftun_config_json_open_error(NULL, (ftun_bytes_t){(const uint8_t *)duplicate, strlen(duplicate)}, &document, &error) == FTUN_E_INVALID);
    CHECK(document.root == NULL && strcmp(error.pointer, "/dns/enable") == 0 &&
      strstr(error.message, "duplicate") != NULL && !error.offset_valid);
    CHECK(ftun_config_json_open_error(NULL, (ftun_bytes_t){(const uint8_t *)finite, strlen(finite)}, &document, &error) == FTUN_E_INVALID);
    CHECK(strcmp(error.pointer, "/outbounds/0/port") == 0 && strcmp(error.field, "outbounds[0].port") == 0);
    CHECK(ftun_config_json_open_error(NULL, (ftun_bytes_t){(const uint8_t *)invalid, strlen(invalid)}, &document, &error) == FTUN_E_INVALID);
    CHECK(error.offset_valid && error.offset == 5u && error.pointer[0] == '\0');
    CHECK(ftun_config_json_open_error(NULL, (ftun_bytes_t){(const uint8_t *)bom, strlen(bom)}, &document, &error) == FTUN_E_INVALID);
    CHECK(error.offset_valid && error.offset == 8u);
    CHECK(ftun_config_json_open_error(NULL, (ftun_bytes_t){(const uint8_t *)bad_utf8, sizeof(bad_utf8)}, &document, &error) == FTUN_E_INVALID);
    CHECK(error.pointer[0] == '\0' && strstr(error.message, "UTF-8") != NULL);
  }
  return 0;
}
