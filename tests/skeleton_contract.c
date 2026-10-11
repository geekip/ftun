#include "ftun/ftun.h"
#include "route/router.h"
#include "transport/stream.h"
#include <stdio.h>
/* TEST-INTEGRATION-005：公开 C 边界的同步拒绝与创建/销毁契约。
 * 不用 assert，Release 的 NDEBUG 不得移除验收。 */
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "contract failed: %s\n", #x); return 1; } } while (0)
static int callbacks;
static void done(ftun_operation_t *op, ftun_error_t result, void *user) {
  (void)op; (void)result; (void)user; callbacks++;
}
int main(void) {
  ftun_core_options_t options = {0};
  ftun_core_t *core = (ftun_core_t *)(uintptr_t)1;
  ftun_operation_t *operation = (ftun_operation_t *)(uintptr_t)1;
  ftun_route_result_t route;
  size_t accepted = 123;
  ftun_core_info_t info;
  options.struct_size = sizeof(options);
  options.abi_version = FTUN_ABI_VERSION;
  CHECK(ftun_core_create(&options, &core) == FTUN_OK && core != NULL);
  CHECK(ftun_core_get_info(core, &info) == FTUN_OK);
  CHECK(info.state == FTUN_CORE_CREATED && info.generation == 0u &&
        info.pending_operations == 0u);
  CHECK(ftun_core_post(core, done, NULL, &operation) == FTUN_E_STALE);
  CHECK(operation == NULL && callbacks == 0);
  CHECK(ftun_core_select(core, "proxy", "node", done, NULL, &operation) == FTUN_E_STALE);
  CHECK(operation == NULL && callbacks == 0);
  /* 已交付的 Router 对无效输入同步拒绝，仍保持失败输出清空。 */
  CHECK(ftun_route_evaluate(NULL, NULL, 0, &route) == FTUN_E_INVALID);
  CHECK(route.kind == FTUN_ROUTE_UNSET && route.allowed == NULL);
  CHECK(ftun_stream_write_ref(NULL, NULL, &accepted, &operation) == FTUN_E_INVALID);
  CHECK(accepted == 0 && operation == NULL);
  CHECK(ftun_core_destroy(&core) == FTUN_OK && core == NULL);
  CHECK(ftun_core_create(NULL, &core) == FTUN_E_INVALID && core == NULL);
  options.abi_version++;
  CHECK(ftun_core_create(&options, &core) == FTUN_E_INVALID && core == NULL);
  options.abi_version = FTUN_ABI_VERSION;
  options.owned_memory_limit = 1u;
  CHECK(ftun_core_create(&options, &core) == FTUN_E_LIMIT && core == NULL);
  return 0;
}
