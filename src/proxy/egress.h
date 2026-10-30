#ifndef FTUN_PROXY_EGRESS_H
#define FTUN_PROXY_EGRESS_H
#include "libs/transport/egress.h"

/* 快照复制出站字段、成员及Bootstrap；不借用配置存储。
 * prepare只复制/校验配置，不执行网络I/O；owner首次open异步解析域名，同节点共享在途请求，TTL到期按需刷新；
 * 解析失败由core/recovery退避，等待者分别持有自己的期限和取消权。
 * bind 仅在交给owner前调用一次，设置代次和组选择回调。 */
typedef ftun_status_t (*ftun_proxy_egress_select_fn)(void *context,
  uint64_t generation, uint32_t group, uint32_t *member);
ftun_status_t ftun_proxy_egress_prepare(ftun_budget_t *budget,
  const ftun_config_t *config, uint32_t mark,
  const ftun_egress_provider_t **out);
void ftun_proxy_egress_bind(const ftun_egress_provider_t *provider,
  uint64_t generation, ftun_proxy_egress_select_fn select, void *context);
/* 仅在发布前装配物理工厂；context须可供worker借用。 */
void ftun_proxy_egress_set_path(const ftun_egress_provider_t *provider,
  ftun_path_provider_ops_t ops, void *context);
/* worker视图只读固定叶子和快照，不执行owner的组选择回调。 */
const ftun_egress_provider_t *ftun_proxy_egress_worker(
  const ftun_egress_provider_t *provider);
#endif
