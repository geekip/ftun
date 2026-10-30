#ifndef FTUN_LIBS_RESOLVER_DUAL_H
#define FTUN_LIBS_RESOLVER_DUAL_H
#include "libs/resolver/resolver.h"
/* A和AAAA各接纳一次，共用绝对期限；结果按A/AAAA顺序合并，取消等待两个生产者。 */
ftun_status_t ftun_resolver_dual_start(const ftun_resolver_provider_ops_t *ops,
  void *context, ftun_core_t *core, const ftun_resolver_provider_request_t *request,
  ftun_operation_t **out);
#endif
