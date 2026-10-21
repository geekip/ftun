#include "app/cli/internal.h"

#include "config/config.h"
#include "config/parser.h"
#if defined(FTUN_HAVE_MODULE_PROXY)
#include "proxy/runtime_state.h"
#endif

#include <stdio.h>
#include <string.h>

#define FTUN_CLI_MEMORY_LIMIT (64u * 1024u * 1024u)
#define FTUN_CLI_DESCRIPTOR_LIMIT 4096u

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
    3u * flow_capacity + 2u * udp_capacity;
  options.operation_capacity = 1024u;
  options.retained_runtime_limit = 4u;
  return ftun_core_create(&options, out);
}

ftun_status_t ftun_cli_check_config(const char *path, int require_inbound,
                                    ftun_config_t **out_config)
{
  ftun_core_t *core = NULL;
  ftun_config_t *config = NULL;
#if defined(FTUN_HAVE_MODULE_PROXY)
  ftun_runtime_t *candidate = NULL;
#endif
  ftun_status_t status;
  if (out_config != NULL) *out_config = NULL;
  status = ftun_cli_core_create(NULL, &core);
  if (status == FTUN_OK) status = ftun_config_load(core, path, &config);
  if (status == FTUN_OK && require_inbound && config->inbound_count == 0u &&
      (!config->dns.enable || config->dns.listener_count == 0u)) {
    status = FTUN_E_INVALID;
  }
#if defined(FTUN_HAVE_MODULE_PROXY)
  /* prepare 也检查必需的 FRS 文件和编译能力资源；abort 保持 check 只读。 */
  if (status == FTUN_OK) status = ftun_runtime_prepare(core, config, &candidate);
  /* run 可执行首次 FRS 下载；只允许确实缺失的自动更新文件通过预检。 */
  if (status == FTUN_E_EOF && require_inbound && config != NULL &&
      config->frs.active && config->frs.auto_update &&
      config->frs.url != NULL && config->frs.url[0] != '\0') {
    status = FTUN_OK;
  }
  if (candidate != NULL) (void)ftun_runtime_abort(core, &candidate);
#endif
  if (status == FTUN_OK && out_config != NULL) {
    *out_config = config;
    config = NULL;
  }
  (void)ftun_config_destroy(&config);
  if (ftun_core_destroy(&core) != FTUN_OK && status == FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
  }
  return status;
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
  ftun_config_t *config = NULL;
  ftun_status_t status = ftun_cli_check_config(path, 0, &config);
  if (status != FTUN_OK) return ftun_cli_error("check", status);
  ftun_cli_warn_deprecated_config(config);
  (void)ftun_config_destroy(&config);
  printf("configuration OK: %s\n", path);
  return 0;
}
