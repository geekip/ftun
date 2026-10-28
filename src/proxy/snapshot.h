#ifndef FTUN_PROXY_SNAPSHOT_H
#define FTUN_PROXY_SNAPSHOT_H

#include "internal/contracts.h"

/* 
 * ftun_runtime_prepare 的不可变快照构造由 snapshot.c 实现，完整内部契约由
 * runtime_state.h 声明。 */
/* Snapshot 构造期使用的名称到稳定出口 ID 转换，不对 Proxy 外公开。 */
ftun_status_t ftun_runtime_resolve_outbound(ftun_string_t name,
                                             uint32_t *out, void *user);

#endif
