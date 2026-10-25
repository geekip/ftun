#include "app/cli/internal.h"

#include "config/config.h"
#include "config/parser.h"
#include "core/context.h"
#include "app/runtime_support.h"
#include "event/event.h"

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
    tcp_capacity = config->base.capacity.tcp_flows;
    udp_capacity = config->base.capacity.udp_flows;
    association_capacity = config->base.capacity.udp_associations;
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
  options.retained_runtime_limit = 4u;
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
  status = ftun_cli_core_create(NULL, &out->core);
  if (status == FTUN_OK) status = ftun_core_context_budget(out->core, &budget);
  if (status == FTUN_OK) {
    status = ftun_config_load_budget_traced(budget, path, &out->config, &trace);
    if (status != FTUN_OK) {
      fprintf(stderr, "ftun: configuration %s: %s\n",
        ftun_config_step_name(trace.failed), ftun_status_name(status));
    }
  }
  if (status == FTUN_OK && require_inbound && out->config->inbound_count == 0u &&
      (!out->config->dns.enable || out->config->dns.listener_count == 0u)) {
    status = FTUN_E_INVALID;
  }
  /* 业务附件只读准备；run 的首次文件下载豁免仍由对应装配负责。 */
  if (status == FTUN_OK && support != NULL) {
    status = support->check(out->core, out->config, require_inbound != 0);
  }
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

void ftun_cli_warn_deprecated_config(const ftun_config_t *config)
{
  if (config != NULL && config->tun.legacy_fields) {
    fputs("ftun: warning: TUN device fields under inbounds[] are deprecated; "
          "use top-level tun\n", stderr);
  }
}

int ftun_cli_check(const char *path)
{
  ftun_cli_checked_config_t checked = {0};
  ftun_status_t status = ftun_cli_check_config(path, 0, &checked);
  ftun_status_t cleanup_status;
  if (status == FTUN_OK) ftun_cli_warn_deprecated_config(checked.config);
  cleanup_status = ftun_cli_checked_config_destroy(&checked);
  if (status == FTUN_OK) status = cleanup_status;
  if (status != FTUN_OK) return ftun_cli_error("check", status);
  printf("configuration OK: %s\n", path);
  return 0;
}
