#ifndef FTUN_STATE_GROUP_CACHE_H
#define FTUN_STATE_GROUP_CACHE_H
#include "internal/contracts.h"

#include "proxy/runtime_state.h"

/* REQ-STATE-001 / TASK-STATE-003 / TEST-STATE-003，目标 0.5.0：
 * ftun_group_cache_save 记录配置身份且不触及 FakeIP 状态。 */

#define FTUN_GROUP_CACHE_MAX_BYTES (1024u * 1024u)
#define FTUN_GROUP_CACHE_MAX_ENTRIES 1024u

typedef struct {
  uint64_t fingerprint;
  uint64_t saved_ms;
  bool health_clock_valid;
  ftun_runtime_group_record_t *records;
  size_t record_count;
} ftun_group_cache_snapshot_t;

/* 指纹只覆盖 Group 及其成员节点配置，不序列化密码。 */
ftun_status_t ftun_group_cache_fingerprint(const ftun_config_t *config,
                                           uint64_t *out);
ftun_status_t ftun_group_cache_write(
  const char *path, const ftun_group_cache_snapshot_t *snapshot);
ftun_status_t ftun_group_cache_load(const char *path,
                                    ftun_group_cache_snapshot_t **out);
ftun_status_t ftun_group_cache_destroy(ftun_group_cache_snapshot_t **snapshot);
/* owner 只捕获不可变运行态并编码到独立 buffer；publish 执行 boot-id 读取、
 * 临时文件写入、fsync/rename 和目录同步，适合放入持久化 Worker。 */
ftun_status_t ftun_group_cache_capture(ftun_core_t *core,
                                       uint8_t **out, size_t *out_length);
ftun_status_t ftun_group_cache_publish(const char *path,
                                       ftun_bytes_t captured);
/* 从 active Runtime 捕获同步快照并原子替换；不触及 FakeIP 文件。 */
ftun_status_t ftun_group_cache_save(ftun_core_t *core, const char *path);
#endif
