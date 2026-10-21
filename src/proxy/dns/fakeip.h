#ifndef FTUN_PROXY_DNS_FAKEIP_H
#define FTUN_PROXY_DNS_FAKEIP_H

#include "core/budget.h"
#include "internal/contracts.h"
#include "proxy/state/fakeip_store.h"
#include "proxy/state/fakeip_snapshot.h"

typedef struct {
  ftun_budget_t *budget;
  ftun_fakeip_store_t *store; /* NULL 表示 persist=false。 */
  const ftun_fakeip_snapshot_t *snapshot;
  uint32_t first_address;
  uint32_t end_address_exclusive;
  size_t max_entries;
} ftun_fakeip_service_options_t;

typedef struct {
  uint32_t first_address;
  uint32_t end_address_exclusive;
  uint32_t next_address;
  uint32_t durable_end;
  size_t max_entries;
  size_t entries;
  size_t references;
  bool persistent;
  bool halted;
} ftun_fakeip_service_info_t;

/* persistent 模式从 store 身份和已验证 snapshot 恢复；snapshot 缺失必须由
 * 调用者明确传入空快照，不能静默当新池。未出现在快照但已预留的地址隔离，
 * next_address 从 durable_end 之后继续。非持久模式使用显式地址范围。 */
ftun_status_t ftun_fakeip_service_create(
  const ftun_fakeip_service_options_t *options,
  ftun_fakeip_service_t **out);
ftun_status_t ftun_fakeip_service_get_info(const ftun_fakeip_service_t *service,
                                           ftun_fakeip_service_info_t *out);

/* 全局 FakeIP 身份服务。
 * 需求 REQ-FAKE-001；任务 TASK-DNS-007；目标 0.3.0；验收 TEST-DNS-007。
 * 域名规范化为小写并移除单个尾点。重复域名返回同一地址；新域名只使用
 * 已耐久预留范围，容量/条目满时拒绝，释放 handle 也不回收或跨域复用。
 */
ftun_status_t ftun_fakeip_service_acquire(ftun_fakeip_service_t *service,
                                          ftun_string_t domain,
                                          ftun_fakeip_handle_t **out);
ftun_status_t ftun_fakeip_acquire(ftun_fakeip_service_t *service,
                                  ftun_string_t domain,
                                  ftun_fakeip_handle_t **out);
ftun_status_t ftun_fakeip_reverse(ftun_fakeip_service_t *service,
                                  uint32_t address,
                                  ftun_fakeip_handle_t **out);
ftun_status_t ftun_fakeip_handle_get(const ftun_fakeip_handle_t *handle,
                                     uint32_t *address,
                                     ftun_string_t *domain);
ftun_status_t ftun_fakeip_handle_release(ftun_fakeip_handle_t **handle);

/* 生成当前固定 sequence 的拥有型快照，可直接交 snapshot_save。 */
ftun_status_t ftun_fakeip_service_snapshot(ftun_fakeip_service_t *service,
                                           ftun_fakeip_snapshot_t **out);
ftun_status_t ftun_fakeip_service_destroy(ftun_fakeip_service_t **service);

#endif
