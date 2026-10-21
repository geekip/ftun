#ifndef FTUN_CORE_CORE_H
#define FTUN_CORE_CORE_H
/* 公共生命周期声明的内部入口，布局仍保持私有。 */
#include "ftun/ftun.h"
#include "core/context.h"
#include "core/service.h"

/* 组合入口必须显式选择业务服务；Core 自身不依赖任何 Proxy/Mesh 私有头。 */
ftun_status_t ftun_core_create_with_service(
  const ftun_core_options_t *options,
  const ftun_core_service_descriptor_t *descriptor,
  ftun_core_t **out);
#endif
