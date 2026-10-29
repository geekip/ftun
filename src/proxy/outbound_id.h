#ifndef FTUN_PROXY_OUTBOUND_ID_H
#define FTUN_PROXY_OUTBOUND_ID_H

#include <stdint.h>

/* 配置顺序映射为稳定的 Proxy Snapshot 内部 ID。 */
#define FTUN_OUTBOUND_ID_DIRECT UINT32_C(0)
#define FTUN_OUTBOUND_ID_REJECT UINT32_C(1)
#define FTUN_OUTBOUND_ID_NAMED_BASE UINT32_C(2)

#endif
