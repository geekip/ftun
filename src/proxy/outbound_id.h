#ifndef FTUN_PROXY_OUTBOUND_ID_H
#define FTUN_PROXY_OUTBOUND_ID_H

#include "util/types.h"

/* 配置顺序映射为稳定的 Proxy Snapshot 内部 ID。 */
#define FTUN_OUTBOUND_ID_DIRECT UINT32_C(0)
#define FTUN_OUTBOUND_ID_REJECT UINT32_C(1)
#define FTUN_OUTBOUND_ID_NAMED_BASE UINT32_C(2)

/* 配置名字只读查询；不选择组成员，也不执行I/O。 */
ftun_status_t ftun_proxy_outbound_id(const ftun_config_t *config,
  const char *name, uint32_t *out);

#endif
