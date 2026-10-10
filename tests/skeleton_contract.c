#include "ftun/ftun.h"
#include "route/router.h"
#include "transport/stream.h"
#include <stdio.h>
/* TEST-SKELETON-001：安全边界验证，绝不将本测试当数据面功能验收。
 * 不用 assert，Release 的 NDEBUG 不得移除验收。 */
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "contract failed: %s\n", #x); return 1; } } while (0)
static int callbacks;
static void done(ftun_operation_t *op, ftun_error_t result, void *user) {
  (void)op; (void)result; (void)user; callbacks++;
}
int main(void) {
  ftun_core_options_t options = {sizeof(options), FTUN_ABI_VERSION, 0};
  ftun_core_t *core = (ftun_core_t *)(uintptr_t)1;
  ftun_operation_t *operation = (ftun_operation_t *)(uintptr_t)1;
  ftun_route_result_t route;
  size_t accepted = 123;
  CHECK(ftun_core_create(&options, &core) == FTUN_E_NOT_IMPLEMENTED);
  CHECK(core == NULL);
  CHECK(ftun_core_post(NULL, done, NULL, &operation) == FTUN_E_NOT_IMPLEMENTED);
  CHECK(operation == NULL && callbacks == 0);
  CHECK(ftun_core_select(NULL, "proxy", "node", done, NULL, &operation) == FTUN_E_NOT_IMPLEMENTED);
  CHECK(operation == NULL && callbacks == 0);
  CHECK(ftun_route_evaluate(NULL, NULL, 0, &route) == FTUN_E_NOT_IMPLEMENTED);
  CHECK(route.kind == FTUN_ROUTE_UNSET && route.allowed == NULL);
  CHECK(ftun_stream_write_ref(NULL, NULL, &accepted, &operation) == FTUN_E_NOT_IMPLEMENTED);
  CHECK(accepted == 0 && operation == NULL);
  CHECK(ftun_core_destroy(&core) == FTUN_OK);
  CHECK(ftun_core_create(NULL, &core) == FTUN_E_INVALID && core == NULL);
  return 0;
}
