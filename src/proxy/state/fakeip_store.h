#ifndef FTUN_PROXY_STATE_FAKEIP_STORE_H
#define FTUN_PROXY_STATE_FAKEIP_STORE_H

#include "core/budget.h"
#include "core/worker.h"
#include "internal/contracts.h"

#define FTUN_FAKEIP_UUID_BYTES 16u

typedef enum {
  FTUN_FAKEIP_STORE_RESERVATION = 1,
  FTUN_FAKEIP_STORE_SNAPSHOT
} ftun_fakeip_store_operation_t;

typedef struct {
  uint8_t uuid[FTUN_FAKEIP_UUID_BYTES];
  uint32_t first_address;
  uint32_t end_address_exclusive;
} ftun_fakeip_store_identity_t;

typedef struct {
  const char *directory;
  ftun_budget_t *budget;
  ftun_worker_t *worker;
  void (*completion)(ftun_operation_t *operation, ftun_error_t error,
                     ftun_fakeip_store_operation_t kind,
                     uint64_t sequence, uint32_t reserved_end,
                     void *user);
  void *user;
} ftun_fakeip_store_options_t;

typedef struct {
  ftun_fakeip_store_identity_t identity;
  uint64_t sequence;
  uint32_t reserved_end;
  bool halted;
  bool pending;
} ftun_fakeip_store_info_t;

/* 显式离线初始化。directory 必须不存在；成功时 identity、空 reservation
 * 日志和空 mappings 快照均已同步，run/open 从不隐式创建这些文件。 */
ftun_status_t ftun_fakeip_store_initialize(
  const char *directory, const ftun_fakeip_store_identity_t *identity);
ftun_status_t ftun_fakeip_store_initialize_budget(ftun_budget_t *budget,
  const char *directory, const ftun_fakeip_store_identity_t *identity);

/* open 获取 directory/lock 的独占锁并完整校验 identity、连续预留日志及
 * 空/现有快照。worker/budget/completion 均借用且须比 store 长寿。 */
ftun_status_t ftun_fakeip_store_open(const ftun_fakeip_store_options_t *options,
                                     ftun_fakeip_store_t **out);
ftun_status_t ftun_fakeip_store_get_info(const ftun_fakeip_store_t *store,
                                         ftun_fakeip_store_info_t *out);

/* 预留范围持久化。
 * 需求 REQ-PERSIST-001；任务 TASK-STATE-001；目标 0.3.0；验收 TEST-STATE-001。
 * end_exclusive 必须单调增加且不超过池尾。接纳后由 Worker 追加带前值、
 * 序号和校验的记录并 fdatasync；仅 completion(OK) 后 info 才发布新高水位。
 * 任一失败/取消令 store halted，旧映射可读但拒绝后续新预留。
 */
ftun_status_t ftun_fakeip_store_reserve(ftun_fakeip_store_t *store,
                                        uint32_t end_exclusive,
                                        ftun_operation_t **out);

/* pending 操作完成前返回 AGAIN；成功释放独占锁。 */
ftun_status_t ftun_fakeip_store_destroy(ftun_fakeip_store_t **store);

#endif
