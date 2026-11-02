#include "app/cli/internal.h"

#include "app/config/config.h"
#include "app/config/parser.h"
#include "core/context.h"
#include "app/runtime_support.h"
#include "core/event/loop.h"
#include "app/config/compile.h"
#include "app/cli/render.h"
#include "platform/file.h"

#include <stdio.h>
#include <string.h>

#define FTUN_CLI_MEMORY_LIMIT (64u * 1024u * 1024u)
#define FTUN_CLI_DESCRIPTOR_LIMIT 4096u
#define FTUN_CLI_QUEUE_MINIMUM 4096u

int ftun_cli_error(const char *operation, ftun_status_t status)
{
  fprintf(stderr, "ftun: %s: %s\n", operation, ftun_status_name(status));
  return 1;
}

ftun_status_t ftun_cli_core_create(const ftun_config_t *config,
                                   ftun_core_t **out)
{
  ftun_core_options_t options;
  size_t tcp_capacity = FTUN_CONFIG_CAPACITY_DEFAULT;
  size_t udp_capacity = FTUN_CONFIG_CAPACITY_DEFAULT;
  size_t association_capacity = FTUN_CONFIG_CAPACITY_DEFAULT;
  size_t flow_capacity;
  size_t excess_flow_capacity;
  size_t excess_udp_capacity;
  size_t required_descriptors;
  size_t required_memory;
  memset(&options, 0, sizeof(options));
  if (config != NULL) {
    tcp_capacity = config->base.proxy.capacity.tcp_flows;
    udp_capacity = config->base.proxy.capacity.udp_flows;
    association_capacity = config->base.proxy.capacity.udp_associations;
  }
  flow_capacity = tcp_capacity + association_capacity;
  excess_flow_capacity =
    (tcp_capacity > FTUN_CONFIG_CAPACITY_DEFAULT
       ? tcp_capacity - FTUN_CONFIG_CAPACITY_DEFAULT : 0u) +
    (association_capacity > FTUN_CONFIG_CAPACITY_DEFAULT
       ? association_capacity - FTUN_CONFIG_CAPACITY_DEFAULT : 0u);
  excess_udp_capacity = udp_capacity > FTUN_CONFIG_CAPACITY_DEFAULT
    ? udp_capacity - FTUN_CONFIG_CAPACITY_DEFAULT : 0u;
  /* admission 额度之外保留协议对象、事件 watcher 和共享缓冲的空间；这是
   * 逻辑上限。默认 256 档保持既有 64 MiB，只对扩容量追加额度。 */
  required_memory = FTUN_CLI_MEMORY_LIMIT +
    excess_flow_capacity * 32u * 1024u +
    excess_udp_capacity * 16u * 1024u;
  options.struct_size = sizeof(options);
  options.abi_version = FTUN_ABI_VERSION;
  options.owned_memory_limit = required_memory > FTUN_CLI_MEMORY_LIMIT
    ? required_memory : FTUN_CLI_MEMORY_LIMIT;
  /* 容量只是逻辑准入上限；slab 仍按需分配，不会在启动时预占全部内存。 */
  required_descriptors = 128u + 2u * (flow_capacity + udp_capacity);
  options.owned_descriptor_limit =
    required_descriptors > FTUN_CLI_DESCRIPTOR_LIMIT
      ? required_descriptors : FTUN_CLI_DESCRIPTOR_LIMIT;
  options.owned_queue_limit = 2048u +
    flow_capacity + udp_capacity + 2u * tcp_capacity;
  /* 每个 Flow/UDP 仅占一个去重 ready 槽；Relay Pool 在创建时准入
   * 每个 TCP 容量两个等待槽，不能再向 Flow 重复收取。 */
  /* 小流容量仍使用 1024 个 Operation 槽，并需容纳当前/候选 logger。
   * data 的一半保障不能被控制域借走；保留默认档的总槽位下限。 */
  if (options.owned_queue_limit < FTUN_CLI_QUEUE_MINIMUM) {
    options.owned_queue_limit = FTUN_CLI_QUEUE_MINIMUM;
  }
  if (config != NULL) {
    size_t event_capacity = 0u;
    size_t datagram_capacity = 0u;
    ftun_status_t status = ftun_app_event_source_capacity(config, &event_capacity);
    if (status != FTUN_OK) return status;
    if (event_capacity > SIZE_MAX - FTUN_EVENT_DEFERRED_CAPACITY ||
        options.owned_queue_limit > SIZE_MAX - event_capacity - FTUN_EVENT_DEFERRED_CAPACITY) {
      return FTUN_E_LIMIT;
    }
    /* Event 从遗漏计量改为逐 source 准入，CLI 同步覆盖配置允许的峰值。
     * 这里只派生上限，不预分配或预留尚未存在的 source。 */
    options.owned_queue_limit += event_capacity + FTUN_EVENT_DEFERRED_CAPACITY;
    status = ftun_app_datagram_capacity(config, &datagram_capacity);
    if (status != FTUN_OK) return status;
    if (options.owned_queue_limit > SIZE_MAX - datagram_capacity) return FTUN_E_LIMIT;
    /* Datagram 独立发送槽由通道准入；pending token 副本不再计一次。
     * 这里仅扩展 CLI 组合上限，显式 C API 限额仍由调用方决定。 */
    options.owned_queue_limit += datagram_capacity;
  }
  options.operation_capacity = 1024u;
  options.retained_runtime_limit = config != NULL
    ? config->base.reload_retain_count : FTUN_CONFIG_RELOAD_RETAIN_DEFAULT;
  return ftun_core_create(&options, out);
}

ftun_status_t ftun_cli_check_config(const char *path, int require_inbound,
                                    ftun_cli_checked_config_t *out)
{
  ftun_budget_t *budget = NULL;
  const ftun_app_runtime_support_t *support = ftun_app_runtime_support();
  ftun_status_t status;
  ftun_config_trace_t trace = {0};
  if (path == NULL || out == NULL || out->core != NULL || out->config != NULL) {
    return FTUN_E_INVALID;
  }
  ftun_config_error_begin(&out->error, FTUN_CONFIG_STEP_READ);
  status = ftun_cli_core_create(NULL, &out->core);
  if (status == FTUN_OK) status = ftun_core_context_budget(out->core, &budget);
  if (status == FTUN_OK) {
    status = ftun_config_load_budget_traced(budget, path, &out->config, &trace);
    out->error = trace.error;
  }
  if (status == FTUN_OK && require_inbound && out->config->inbound_count == 0u &&
      (!out->config->dns.enable || out->config->dns.listener_count == 0u)) {
    ftun_config_error_begin(&out->error, FTUN_CONFIG_STEP_VALIDATE);
    status = ftun_config_error_set(&out->error, FTUN_E_INVALID, "/inbounds",
      "configuration has no service root");
  }
  /* 业务附件只读准备；run 的首次文件下载豁免仍由对应装配负责。 */
  if (status == FTUN_OK && support != NULL) {
    status = support->check(out->core, out->config, require_inbound != 0,
      &out->error, &out->frs_sets);
  }
  if (status != FTUN_OK) (void)ftun_config_error_set(&out->error, status, "",
    "cannot prepare configuration resources");
  return status;
}

ftun_status_t ftun_cli_checked_config_destroy(ftun_cli_checked_config_t *checked)
{
  ftun_status_t status;
  if (checked == NULL) return FTUN_E_INVALID;
  status = ftun_config_destroy(&checked->config);
  if (status != FTUN_OK) return status;
  return ftun_core_destroy(&checked->core);
}

ftun_status_t ftun_cli_config_path(const char *path, char *output, size_t capacity)
{
  ftun_string_t home;
  if (path == NULL) {
    ftun_status_t status = ftun_user_home(output, capacity, &home);
    if (status != FTUN_OK) return status;
    const char suffix[] = "/.ftun/config.json";
    if (sizeof(suffix) > capacity - home.length) return FTUN_E_LIMIT;
    memcpy(output + home.length, suffix, sizeof(suffix));
  } else {
    size_t length = strlen(path);
    if (length >= capacity) return FTUN_E_LIMIT;
    memcpy(output, path, length + 1u);
  }
  return FTUN_OK;
}

int ftun_cli_config_error(const char *operation, const ftun_config_error_t *error, bool json)
{
  char output[16384];
  if (json) {
    char detail[14336];
    size_t length = ftun_config_error_json(error, detail, sizeof(detail));
    if (length == 0u) return FTUN_EXIT_FAIL;
    int count = snprintf(output, sizeof(output),
      "{\"result\":\"failed\",\"op\":\"%s\",\"status\":\"%s\",\"stage\":\"%s\",%s\n",
      operation, ftun_status_name(error->error.status), ftun_config_step_name(error->phase), detail + 1u);
    if (count < 0 || (size_t)count >= sizeof(output)) return FTUN_EXIT_FAIL;
    (void)ftun_cli_output(1, output);
  } else {
    (void)snprintf(output, sizeof(output), "ftun: %s: configuration %s: %s: %s (%s)%s\n",
      operation, ftun_config_step_name(error->phase), error->field, error->message,
      ftun_status_name(error->error.status), error->truncated ? " [truncated]" : "");
    (void)ftun_cli_output(2, output);
  }
  return FTUN_EXIT_FAIL;
}

int ftun_cli_check(const char *path, bool json)
{
  ftun_cli_checked_config_t checked = {0};
  char resolved[4096];
  cJSON *object = NULL, *modules = NULL, *startup = NULL;
  ftun_status_t status = ftun_cli_config_path(path, resolved, sizeof(resolved));
  ftun_config_error_begin(&checked.error, FTUN_CONFIG_STEP_READ);
  if (status == FTUN_OK) status = ftun_cli_check_config(resolved, 0, &checked);
  else (void)ftun_config_error_set(&checked.error, status, "",
    "cannot resolve default configuration path; use -c FILE");
  bool first_fakeip = false;
  if (status == FTUN_OK && (checked.config->plan->prepare & FTUN_PLAN_FAKE_IP) != 0u &&
      checked.config->dns.fake_ip.persist) {
    char directory[4097];
    ftun_file_info_t info;
    int length = snprintf(directory, sizeof(directory), "%s.fakeip", checked.config->base.proxy.cache_file);
    status = length < 0 || (size_t)length >= sizeof(directory) ? FTUN_E_LIMIT :
      ftun_file_inspect_path_nofollow(directory, &info);
    if (status == FTUN_E_EOF) { first_fakeip = true; status = FTUN_OK; }
    else if (status == FTUN_OK && !info.directory) status = FTUN_E_STATE_CORRUPT;
    if (status != FTUN_OK) {
      ftun_config_error_begin(&checked.error, FTUN_CONFIG_STEP_ATTACHMENTS);
      (void)ftun_config_error_set(&checked.error, status, "/base/cache-file", "cannot inspect FakeIP state directory");
    }
  }
  if (status == FTUN_OK) {
    const ftun_feature_plan_t *plan = checked.config->plan;
    static const struct { uint32_t bit; const char *name; } names[] = {
      {FTUN_BUILD_MODULE_CORE, "core"}, {FTUN_BUILD_MODULE_PROXY, "proxy"},
      {FTUN_BUILD_MODULE_DNS, "dns"}, {FTUN_BUILD_MODULE_FAKEIP, "fakeip"},
      {FTUN_BUILD_MODULE_TUN, "tun"}, {FTUN_BUILD_MODULE_FRS, "frs"}
    };
    char enabled[64] = "";
    size_t index, used = 0u;
    object = cJSON_CreateObject();
    modules = object == NULL ? NULL : cJSON_AddArrayToObject(object, "modules");
    startup = object == NULL ? NULL : cJSON_AddArrayToObject(object, "startup_only");
    if (object == NULL || modules == NULL || startup == NULL ||
        cJSON_AddStringToObject(object, "result", "ok") == NULL ||
        cJSON_AddNumberToObject(object, "listeners", (double)plan->prepare_listener_count) == NULL ||
        cJSON_AddNumberToObject(object, "tun_devices", (double)plan->prepare_tun_count) == NULL ||
        cJSON_AddNumberToObject(object, "rules", (double)checked.config->rules.count) == NULL ||
        cJSON_AddNumberToObject(object, "frs_sets", (double)checked.frs_sets) == NULL) status = FTUN_E_LIMIT;
    for (index = 0u; status == FTUN_OK && index < sizeof(names) / sizeof(names[0]); index++) {
      if ((plan->modules.required_modules & names[index].bit) == 0u) continue;
      cJSON *name = cJSON_CreateString(names[index].name);
      if (name == NULL || !cJSON_AddItemToArray(modules, name)) {
        cJSON_Delete(name);
        status = FTUN_E_LIMIT;
        break;
      }
      used += (size_t)snprintf(enabled + used, sizeof(enabled) - used,
        "%s%s", used == 0u ? "" : ", ", names[index].name);
    }
    static const char *const conditions[] = {
      "port permissions and availability", "TUN device and routes", "remote reachability", "FRS download",
      "persistent state identity and file locks", "FakeIP state will be created on first run"
    };
    for (index = 0u; status == FTUN_OK && index < sizeof(conditions) / sizeof(conditions[0]); index++) {
      bool include = index == 0u ? plan->prepare_listener_count != 0u :
        index == 1u ? plan->prepare_tun_count != 0u : index == 2u ?
        (plan->modules.required_modules & (FTUN_BUILD_MODULE_PROXY | FTUN_BUILD_MODULE_DNS)) != 0u :
        index == 3u ? checked.config->frs.active && checked.config->frs.auto_update :
        index == 4u ? (plan->prepare & (FTUN_PLAN_FAKE_IP | FTUN_PLAN_STATE_CACHE)) != 0u ||
        strcmp(checked.config->log.output, "stderr") != 0 : first_fakeip;
      if (!include) continue;
      cJSON *condition = cJSON_CreateString(conditions[index]);
      if (condition == NULL || !cJSON_AddItemToArray(startup, condition)) {
        cJSON_Delete(condition);
        status = FTUN_E_LIMIT;
      }
    }
    if (status == FTUN_OK && !json) {
      char output[2048];
      int count = snprintf(output, sizeof(output),
        "configuration OK\n  modules: %s\n  listeners: %zu; TUN devices: %zu; rules: %zu; FRS sets: %zu\nStartup-only checks:\n",
        enabled, plan->prepare_listener_count, plan->prepare_tun_count,
        checked.config->rules.count, checked.frs_sets);
      if (count < 0 || (size_t)count >= sizeof(output) || ftun_cli_output(1, output) != FTUN_EXIT_OK)
        status = FTUN_E_IO;
      const cJSON *item;
      cJSON_ArrayForEach(item, startup) {
        if (status != FTUN_OK) break;
        (void)snprintf(output, sizeof(output), "  %s\n", item->valuestring);
        if (ftun_cli_output(1, output) != FTUN_EXIT_OK) status = FTUN_E_IO;
      }
      if (status == FTUN_OK && startup->child == NULL && ftun_cli_output(1, "  none\n") != FTUN_EXIT_OK)
        status = FTUN_E_IO;
    }
  }
  ftun_status_t cleanup = ftun_cli_checked_config_destroy(&checked);
  if (status == FTUN_OK) status = cleanup;
  if (status != FTUN_OK) {
    cJSON_Delete(object);
    (void)ftun_config_error_set(&checked.error, status, "", "cannot complete configuration check");
    return ftun_cli_config_error("check", &checked.error, json);
  }
  if (json) return ftun_cli_json_write(object);
  cJSON_Delete(object);
  return FTUN_EXIT_OK;
}
