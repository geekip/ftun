#include "app/control/status.h"
#include "core/config/document.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "status failed at %d: %s\n", __LINE__, #x); abort(); } } while (0)

static cJSON *document(ftun_ctl_status_t *snapshot, ftun_ctl_operation_t operation,
  char *text, size_t capacity)
{
  ftun_config_json_t json;
  size_t length, prefix;
  memcpy(text, "{\"result\":\"ok\"", 14u);
  prefix = 14u;
  CHECK(ftun_ctl_status_json(snapshot, operation, text + prefix, capacity - prefix, &length) == FTUN_OK);
  CHECK(length + prefix < capacity && text[prefix + length - 1u] == '\n');
  CHECK(ftun_config_json_open(NULL, (ftun_bytes_t){(const uint8_t *)text, length + prefix}, &json) == FTUN_OK);
  return json.root; /* NULL预算时只有解析树，由本测试直接Delete。 */
}

#if defined(FTUN_HAVE_MODULE_DNS) || defined(FTUN_HAVE_MODULE_PROXY)
static void list_check(cJSON *root, const char *key, size_t total)
{
  cJSON *list = cJSON_GetObjectItemCaseSensitive(root, key);
  cJSON *items = cJSON_GetObjectItemCaseSensitive(list, "items");
  cJSON *count = cJSON_GetObjectItemCaseSensitive(list, "count");
  CHECK(cJSON_IsArray(items) && cJSON_IsNumber(count));
  CHECK(count->valuedouble == cJSON_GetArraySize(items));
  CHECK(cJSON_GetObjectItemCaseSensitive(list, "total")->valuedouble == (double)total);
  CHECK(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(list, "truncated")));
}

#endif

int main(void)
{
  ftun_ctl_status_t *snapshot = calloc(1u, sizeof(*snapshot));
  char text[65536], name[1024];
  size_t index, length;
  cJSON *root;
  CHECK(snapshot != NULL);
  memset(name, '\n', sizeof(name) - 1u); name[sizeof(name) - 1u] = '\0';
  snapshot->host.core.state = FTUN_CORE_RUNNING;
  memset(snapshot->host.config_path, '\x01', sizeof(snapshot->host.config_path) - 1u);
  memset(snapshot->log_file, '\x01', sizeof(snapshot->log_file) - 1u);
  root = document(snapshot, FTUN_CTL_STATUS, text, sizeof(text));
  CHECK(strlen(cJSON_GetObjectItemCaseSensitive(root, "config")->valuestring) == 4096u);
  CHECK(cJSON_IsNull(cJSON_GetObjectItemCaseSensitive(root, "last_reload")));
  cJSON_Delete(root);
#if defined(FTUN_HAVE_MODULE_PROXY)
  snapshot->proxy.listeners_count = snapshot->proxy.groups_count =
    snapshot->proxy.outbounds_count = snapshot->proxy.frs_count = FTUN_STATUS_MAX_ITEMS;
  snapshot->proxy.listeners_total = snapshot->proxy.groups_total =
    snapshot->proxy.outbounds_total = snapshot->proxy.frs_total = 129u;
  snapshot->proxy.frs_known = true;
  for (index = 0u; index < FTUN_STATUS_MAX_ITEMS; ++index) {
    ftun_status_label_set(&snapshot->proxy.listeners[index].name, name);
    snapshot->proxy.listeners[index].address.kind = FTUN_ADDRESS_IPV4;
    snapshot->proxy.listeners[index].address.port = 1080u;
    ftun_status_label_set(&snapshot->proxy.groups[index].name, name);
    ftun_status_label_set(&snapshot->proxy.groups[index].selected, name);
    ftun_status_label_set(&snapshot->proxy.outbounds[index].name, name);
    ftun_status_label_set(&snapshot->proxy.frs[index].name, name);
  }
  snapshot->proxy.outbounds[0].connections = UINT64_MAX;
  root = document(snapshot, FTUN_CTL_PROXY_STATUS, text, sizeof(text));
  list_check(root, "listeners", 129u); list_check(root, "groups", 129u);
  list_check(root, "outbounds", 129u); list_check(root, "frs", 129u);
  CHECK(strstr(text, "18446744073709551615") != NULL);
  CHECK(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(
    cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(root, "groups"), "items"), 0), "name_truncated")));
  cJSON_Delete(root);
  snapshot->proxy.frs_known = false;
  snapshot->proxy.frs_total = snapshot->proxy.frs_count = 0u;
  root = document(snapshot, FTUN_CTL_PROXY_STATUS, text, sizeof(text));
  CHECK(cJSON_IsNull(cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(root, "frs"), "total")));
  cJSON_Delete(root);
#endif
#if defined(FTUN_HAVE_MODULE_DNS)
  snapshot->dns.listeners_count = snapshot->dns.upstreams_count = FTUN_STATUS_MAX_ITEMS;
  snapshot->dns.listeners_total = snapshot->dns.upstreams_total = 128u;
  for (index = 0u; index < FTUN_STATUS_MAX_ITEMS; ++index) {
    ftun_status_label_set(&snapshot->dns.listeners[index].server, name);
    snapshot->dns.listeners[index].address.kind = FTUN_ADDRESS_IPV4;
    snapshot->dns.listeners[index].address.port = 53u;
    ftun_status_label_set(&snapshot->dns.upstreams[index].server, name);
    ftun_status_label_set(&snapshot->dns.upstreams[index].group, name);
    snapshot->dns.upstreams[index].address.kind = FTUN_ADDRESS_IPV6;
    snapshot->dns.upstreams[index].address.port = 53u;
  }
  root = document(snapshot, FTUN_CTL_DNS_STATUS, text, sizeof(text));
  list_check(root, "listeners", 128u); list_check(root, "upstreams", 128u);
  cJSON_Delete(root);
#endif
  CHECK(ftun_ctl_status_json(snapshot, FTUN_CTL_STATUS, text, 16u, &length) == FTUN_E_LIMIT);
  {
    ftun_status_label_t label;
    char unicode[512];
    for (index = 0u; index < 510u; index += 3u) memcpy(unicode + index, "中", 3u);
    unicode[510] = '\0';
    ftun_status_label_set(&label, unicode);
    CHECK(label.truncated && strlen(label.text) == 255u && memcmp(label.text + 252u, "中", 3u) == 0);
    unicode[0] = 'x';
    for (index = 1u; index < 511u; index += 3u) memcpy(unicode + index, "中", 3u);
    unicode[511] = '\0';
    ftun_status_label_set(&label, unicode);
    CHECK(label.truncated && strlen(label.text) == 253u && memcmp(label.text + 250u, "中", 3u) == 0);
  }
  free(snapshot);
  puts("status: bounded owned labels, JSON byte/item truncation, totals, unknown FRS and integer precision passed");
  return 0;
}
