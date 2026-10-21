#ifndef FTUN_PROXY_STATE_FAKEIP_SNAPSHOT_H
#define FTUN_PROXY_STATE_FAKEIP_SNAPSHOT_H

#include "proxy/state/fakeip_store.h"

typedef struct {
  uint32_t address;
  ftun_string_t domain;
} ftun_fakeip_mapping_t;

struct ftun_fakeip_snapshot {
  uint8_t uuid[FTUN_FAKEIP_UUID_BYTES];
  uint64_t sequence;
  ftun_fakeip_mapping_t *mappings;
  size_t mapping_count;
  ftun_reservation_t *reservation;
  void *owned_block;
};

/* 批量映射快照。
 * 需求 REQ-PERSIST-001；任务 TASK-STATE-002；目标 0.3.0；验收 TEST-STATE-002。
 * save 在接纳前完整验证固定 sequence 视图并序列化为有界 Worker 输入；
 * Worker 在同目录写临时文件、同步、原子替换和目录同步。调用者在完成前
 * 可释放/修改输入 snapshot，因为 Worker 已拥有副本。
 */
ftun_status_t ftun_fakeip_snapshot_save(ftun_fakeip_store_t *store,
                                        const ftun_fakeip_snapshot_t *snapshot,
                                        ftun_operation_t **out);

/* load 的 max_mappings 是磁盘输入和内存分配上限。成功对象拥有全部域名；
 * 只接受当前 pool UUID、已耐久 sequence 和预留范围内的双向唯一映射。 */
ftun_status_t ftun_fakeip_snapshot_load(ftun_fakeip_store_t *store,
                                        size_t max_mappings,
                                        ftun_fakeip_snapshot_t **out);
ftun_status_t ftun_fakeip_snapshot_destroy(ftun_fakeip_snapshot_t **snapshot);

#endif
