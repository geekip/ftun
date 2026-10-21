#ifndef FTUN_TRANSPORT_PATH_H
#define FTUN_TRANSPORT_PATH_H

#include "transport/dialer.h"

typedef struct ftun_path_provider ftun_path_provider_t;

typedef struct {
  ftun_status_t (*start)(void *context, ftun_core_t *core,
                         const ftun_dial_request_t *request,
                         ftun_operation_t **out);
  ftun_status_t (*reload_prepare)(void *context, uint64_t generation);
  void (*reload_commit)(void *context, uint64_t generation);
  void (*reload_abort)(void *context, uint64_t generation);
  ftun_status_t (*quiesce)(void *context);
  ftun_status_t (*stop_until)(void *context, uint64_t deadline_ms);
} ftun_path_provider_ops_t;

typedef struct {
  ftun_budget_t *budget;
  uint64_t generation;
  ftun_path_provider_ops_t ops;
  /* 借用；必须比 provider 及全部已接纳 operation 长寿。 */
  void *context;
} ftun_path_provider_spec_t;

typedef struct {
  uint64_t generation;
  uint64_t pending_generation;
  bool accepting;
  bool stopped;
  bool reload_prepared;
} ftun_path_provider_info_t;

/* Stream/Datagram 共用同一窄 Path Provider；两个入口强制核验 transport、
 * NetworkView generation、purpose 和 domain。成功 operation 的取消统一走
 * ftun_operation_cancel；reload 后旧 operation 仍按接纳时 generation 终结。 */
ftun_status_t ftun_path_provider_create(
  const ftun_path_provider_spec_t *spec, ftun_path_provider_t **out);
ftun_status_t ftun_path_provider_open_stream(
  ftun_path_provider_t *provider, ftun_core_t *core,
  const ftun_dial_request_t *request, ftun_operation_t **out);
ftun_status_t ftun_path_provider_open_datagram(
  ftun_path_provider_t *provider, ftun_core_t *core,
  const ftun_dial_request_t *request, ftun_operation_t **out);
ftun_status_t ftun_path_provider_reload_prepare(
  ftun_path_provider_t *provider, uint64_t generation);
ftun_status_t ftun_path_provider_reload_commit(
  ftun_path_provider_t *provider, uint64_t generation);
ftun_status_t ftun_path_provider_reload_abort(ftun_path_provider_t *provider);
ftun_status_t ftun_path_provider_quiesce(ftun_path_provider_t *provider);
ftun_status_t ftun_path_provider_stop_until(
  ftun_path_provider_t *provider, uint64_t deadline_ms);
ftun_status_t ftun_path_provider_get_info(
  const ftun_path_provider_t *provider, ftun_path_provider_info_t *out);
ftun_status_t ftun_path_provider_destroy(ftun_path_provider_t **provider);

#endif
