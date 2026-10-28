#include "fuzz_common.h"

#include "config/compile.h"
#include "config/parser.h"
#include "config/validate.h"

#include <string.h>

/* JSON 配置：解析 -> 校验 -> 编译计划。任何阶段都不能把输入错误报成内部状态损坏，
 * 失败时不能留下输出对象。 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  ftun_config_t *config = NULL;
  ftun_status_t status = ftun_config_parse((ftun_bytes_t){data, size}, &config);
  FUZZ_NOT_CORRUPT(status);
  if (status != FTUN_OK) {
    FUZZ_REQUIRE(config == NULL);
    return 0;
  }
  FUZZ_REQUIRE(config != NULL);
  {
    ftun_diagnostic_t diagnostic;
    memset(&diagnostic, 0, sizeof(diagnostic));
    status = ftun_config_validate(config, &diagnostic);
    FUZZ_NOT_CORRUPT(status);
    if (status == FTUN_OK) {
      ftun_feature_plan_t *plan = NULL;
      status = ftun_config_compile(config, &plan);
      FUZZ_NOT_CORRUPT(status);
      if (status == FTUN_OK) FUZZ_REQUIRE(ftun_feature_plan_destroy(&plan) == FTUN_OK);
    }
  }
  FUZZ_REQUIRE(ftun_config_destroy(&config) == FTUN_OK);
  return 0;
}
