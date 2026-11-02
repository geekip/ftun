#include "app/cli/internal.h"
#include "app/cli/render.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

typedef struct { char text[65536u]; size_t used, lines; bool truncated; } text_t;
static const cJSON *get(const cJSON *object, const char *key)
{ return cJSON_GetObjectItemCaseSensitive(object, key); }
static const char *string(const cJSON *object, const char *key)
{ const cJSON *value = get(object, key); return cJSON_IsString(value) ? value->valuestring : ""; }
static double number(const cJSON *object, const char *key)
{ const cJSON *value = get(object, key); return cJSON_IsNumber(value) ? value->valuedouble : 0; }

#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 2, 3)))
#endif
static void line(text_t *out, const char *format, ...)
{
  int count;
  va_list args;
  if (out->truncated) return;
  if (out->lines == 63u) { out->truncated = true; return; }
  va_start(args, format);
  count = vsnprintf(out->text + out->used, sizeof(out->text) - out->used - 256u, format, args);
  va_end(args);
  if (count < 0 || (size_t)count >= sizeof(out->text) - out->used - 256u) { out->truncated = true; return; }
  out->used += (size_t)count;
  out->text[out->used++] = '\n';
  out->lines++;
}

static void value(text_t *out, const char *label, const cJSON *object)
{
  size_t before = out->used;
  if (out->truncated || object == NULL) return;
  if (out->lines == 63u) { out->truncated = true; return; }
  if (sizeof(out->text) - out->used <= 256u + strlen(label) + 3u) { out->truncated = true; return; }
  (void)snprintf(out->text + out->used, sizeof(out->text) - out->used,
    label[0] == ' ' ? "%s" : "%s: ", label);
  out->used += strlen(out->text + out->used);
  if (!cJSON_PrintPreallocated((cJSON *)object, out->text + out->used,
      (int)(sizeof(out->text) - out->used - 256u), false)) {
    out->used = before;
    out->truncated = true;
    return;
  }
  out->used += strlen(out->text + out->used);
  out->text[out->used++] = '\n';
  out->lines++;
}

static void list(text_t *out, const cJSON *root, const char *key, const char *title)
{
  const cJSON *object = get(root, key), *item;
  if (!cJSON_IsObject(object)) return;
  if (cJSON_IsNull(get(object, "total"))) line(out, "%s: total unknown", title);
  else line(out, "%s: total=%.0f returned=%.0f%s", title, number(object, "total"), number(object, "count"),
    cJSON_IsTrue(get(object, "truncated")) ? " (truncated)" : "");
  cJSON_ArrayForEach(item, get(object, "items")) { value(out, "  ", item); }
}

int ftun_cli_status_render(const char *operation, const cJSON *root)
{
  text_t out = {{0}, 0u, 0u, false};
  const cJSON *service;
  if (strcmp(operation, "status") == 0) {
    line(&out, "FTUN %s %s pid=%.0f boot=%s uptime=%.0fms", string(root, "version"), string(root, "state"),
      number(root, "pid"), string(root, "boot"), number(root, "uptime_ms"));
    value(&out, "Config", get(root, "config"));
    line(&out, "Generation: %.0f reload_pending=%s", number(root, "generation"),
      cJSON_IsTrue(get(root, "reload_pending")) ? "true" : "false");
    value(&out, "Last reload", get(root, "last_reload"));
    value(&out, "Resources", get(root, "resources"));
    value(&out, "Sessions", get(root, "sessions"));
    value(&out, "Logs", get(root, "logs"));
    cJSON_ArrayForEach(service, get(root, "services")) { value(&out, "Service", service); }
  } else {
    line(&out, "%s state=%s pid=%.0f boot=%s generation=%.0f", operation, string(root, "state"),
      number(root, "pid"), string(root, "boot"), number(root, "stats_generation"));
    line(&out, "Reason: %s retry_at_ms=%.0f", string(root, "reason"), number(root, "retry_at_ms"));
    if (strcmp(operation, "dns.status") == 0) {
      value(&out, "Queries", get(root, "queries"));
      value(&out, "Cache", get(root, "cache"));
      list(&out, root, "listeners", "Listeners");
      list(&out, root, "upstreams", "Upstreams");
    } else {
      value(&out, "Sessions", get(root, "sessions"));
      value(&out, "FRS state", get(root, "frs_state"));
      list(&out, root, "listeners", "Listeners");
      list(&out, root, "groups", "Groups");
      list(&out, root, "outbounds", "Outbounds (TCP, current generation)");
      list(&out, root, "frs", "FRS sets");
    }
  }
  if (out.truncated) {
    const char *notice = "Output truncated; use --json for available details.\n";
    memcpy(out.text + out.used, notice, strlen(notice));
    out.used += strlen(notice);
  }
  out.text[out.used] = '\0';
  return ftun_cli_output(1, out.text);
}
