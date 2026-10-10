#include "ftun/ftun.h"
/* REQ-CORE-001 / REQ-CAPI-001 / TASK-DOC-001。
 * 后续 create -> prepare -> run -> stop/drain -> destroy；Core 是 loop 所有者。
 * 当前不分配伪 Core，不创建线程或设备；所有服务操作明确拒绝。 */
const char *ftun_version(void) { return FTUN_VERSION; }
ftun_status_t ftun_core_create(const ftun_core_options_t *options, ftun_core_t **out) {
  if (out == NULL) return FTUN_E_INVALID;
  *out = NULL;
  if (options == NULL || options->struct_size < sizeof(*options) ||
      options->abi_version != FTUN_ABI_VERSION) return FTUN_E_INVALID;
  return FTUN_E_NOT_IMPLEMENTED;
}
ftun_status_t ftun_core_run(ftun_core_t *core, const char *path) {
  (void)core; (void)path; return FTUN_E_NOT_IMPLEMENTED;
}
ftun_status_t ftun_core_stop(ftun_core_t *core, uint64_t deadline_ms) {
  (void)core; (void)deadline_ms; return FTUN_E_NOT_IMPLEMENTED;
}
ftun_status_t ftun_core_post(ftun_core_t *core, ftun_completion_fn callback, void *user,
                            ftun_operation_t **out) {
  if (out == NULL) return FTUN_E_INVALID;
  *out = NULL;
  (void)core; (void)callback; (void)user;
  return FTUN_E_NOT_IMPLEMENTED;
}
ftun_status_t ftun_core_reload(ftun_core_t *core, const char *path,
                              ftun_completion_fn callback, void *user,
                              ftun_operation_t **out) {
  (void)path; return ftun_core_post(core, callback, user, out);
}
ftun_status_t ftun_core_select(ftun_core_t *core, const char *group_name,
                              const char *member_name,
                              ftun_completion_fn callback, void *user,
                              ftun_operation_t **out) {
  (void)group_name; (void)member_name;
  return ftun_core_post(core, callback, user, out);
}
ftun_status_t ftun_core_destroy(ftun_core_t **core) {
  if (core == NULL) return FTUN_E_INVALID;
  if (*core == NULL) return FTUN_OK;
  return FTUN_E_NOT_IMPLEMENTED;
}
