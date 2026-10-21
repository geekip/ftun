#ifndef FTUN_PROXY_FRS_UPDATE_H
#define FTUN_PROXY_FRS_UPDATE_H

#include "internal/contracts.h"
#include "platform/file.h"

/* TASK-FRS-004 / TEST-FRS-004：FRS 下载、发布与 Runtime 更新，目标 0.4.0。 */

typedef enum {
  FTUN_FRS_UPDATE_NONE = 0,
  FTUN_FRS_UPDATE_UPDATED,
  FTUN_FRS_UPDATE_UNCHANGED,
  FTUN_FRS_UPDATE_DURABILITY_UNCERTAIN
} ftun_frs_update_outcome_t;

typedef struct {
  ftun_string_t url;
  ftun_string_t if_none_match;
  uint64_t deadline_ms;
  uint32_t outbound_id;
  uint32_t dns_server_id;
  bool conditional;
} ftun_frs_download_request_t;

typedef struct {
  uint8_t *data;
  size_t length;
  uint64_t finished_ms;
  uint32_t outbound_id;
  uint32_t dns_server_id;
  unsigned int http_status;
  bool tls_verified;
  ftun_string_t etag;
} ftun_frs_download_t;

typedef ftun_status_t (*ftun_frs_download_fn)(
  void *user, const ftun_frs_download_request_t *request,
  ftun_frs_download_t *out);
typedef void (*ftun_frs_download_release_fn)(void *user,
                                             ftun_frs_download_t *download);

struct ftun_frs_update_request {
  ftun_string_t url;
  const char *destination;
  const ftun_config_t *config;
  size_t maximum_bytes;
  uint64_t now_ms;
  uint64_t deadline_ms;
  uint32_t outbound_id;
  uint32_t dns_server_id;
  const char *etag;
  char **accepted_etag;
  ftun_frs_update_outcome_t *outcome;
  ftun_operation_queue_t *operations;
  ftun_completion_fn completion;
  void *completion_user;
  ftun_frs_download_fn download;
  ftun_frs_download_release_fn release;
  void *download_user;
  ftun_file_stage_hook_fn publish_hook;
  void *publish_hook_user;
};

/* 下载的是完整成品。候选先通过 FRS 校验和 Runtime 全引用绑定，再原子发布并
 * 提交完整 Runtime；失败保留旧代。304 只有绑定到有效本地基线时才有效。 */
ftun_status_t ftun_frs_update(ftun_core_t *core,
                              const ftun_frs_update_request_t *request,
                              ftun_operation_t **out);

#endif
