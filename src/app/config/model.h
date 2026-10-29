#ifndef FTUN_APP_CONFIG_MODEL_H
#define FTUN_APP_CONFIG_MODEL_H
#include "core/config/document.h"
#include "proxy/config/transport.h"
#include "app/config/plan.h"
#include "dns/config/model.h"
#include "libs/transport/config.h"
#include "proxy/config/plan.h"
#include "libs/tun/config/model.h"
#include "proxy/config/model.h"

enum {
  FTUN_CONFIG_SECTION_SOURCE_PATH = 6u,
  FTUN_CONFIG_SECTION_BASE_DIRECTORY = 7u
};
typedef struct {
  ftun_config_proxy_base_t proxy;
  uint32_t watchdog_ms;
  uint32_t reload_retain_count;
} ftun_config_base_t;
struct ftun_config {
  ftun_config_document_t document;
  char *source_path;
  char *base_directory;
  ftun_feature_plan_t *plan;
  ftun_config_base_t base;
  struct {
    char *level;
    char *file;
    /* 单个日志文件的大小上限（字节，0 不轮转）与保留的文件总数（含当前文件）。 */
    uint32_t max_size;
    uint32_t max_files;
  } log;
  ftun_config_dns_t dns;
  ftun_config_frs_t frs;
  ftun_config_sniff_t sniff;
  ftun_config_tun_t tun;
  ftun_config_inbound_t *inbounds;
  size_t inbound_count;
  ftun_config_outbound_t *outbounds;
  size_t outbound_count;
  ftun_config_string_list_t rules;
};

/* 仅供调用方拥有的清零模型在构造阶段注册借用段，不建立拥有引用。 */
void ftun_config_bind_sections(ftun_config_t *config);
ftun_status_t ftun_config_create_owned(ftun_budget_t *budget, ftun_config_t **out);
/* 超时与存活的默认值（候选值）；空闲回收默认关闭。解析器和手工构造配置的
 * 测试共用这一份。 */
#define FTUN_CONFIG_LOG_MAX_SIZE_DEFAULT UINT32_C(10485760)
#define FTUN_CONFIG_LOG_MAX_SIZE_MINIMUM UINT32_C(65536)
#define FTUN_CONFIG_LOG_MAX_FILES_DEFAULT UINT32_C(3)
#define FTUN_CONFIG_LOG_MAX_FILES_MAXIMUM UINT32_C(32)
#define FTUN_CONFIG_RELOAD_RETAIN_DEFAULT UINT32_C(4)
#define FTUN_CONFIG_RELOAD_RETAIN_MAXIMUM UINT32_C(64)
#define FTUN_CONFIG_WATCHDOG_DEFAULT_MS UINT32_C(30000)
#define FTUN_CONFIG_WATCHDOG_MINIMUM_MS UINT32_C(1000)
#define FTUN_CONFIG_WATCHDOG_MAXIMUM_MS UINT32_C(600000)
#define FTUN_CONFIG_ROUTING_MARK_DEFAULT UINT32_C(0x4654)


void ftun_config_timeouts_default(ftun_config_t *config);
#endif
