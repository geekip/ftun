#ifndef FTUN_PLATFORM_FILE_H
#define FTUN_PLATFORM_FILE_H

#include "internal/contracts.h"

typedef struct ftun_file_lock ftun_file_lock_t;

typedef enum {
  FTUN_FILE_STAGE_TEMP_SYNCED = 1,
  FTUN_FILE_STAGE_RENAMED,
  FTUN_FILE_STAGE_DIRECTORY_SYNCED
} ftun_file_stage_t;

typedef ftun_status_t (*ftun_file_stage_hook_fn)(ftun_file_stage_t stage,
                                                  void *user);

/* 锁文件由调用者选择，通常是 FakeIP identity 目录中的固定 lock 路径。
 * 成功后持有非阻塞独占锁，release 消费句柄。 */
ftun_status_t ftun_file_lock_acquire(const char *path, ftun_file_lock_t **out);
/* 自有锁对象和1 FD在打开前准入，直到release才归还。 */
ftun_status_t ftun_file_lock_acquire_budget(ftun_budget_t *budget,
  const char *path, ftun_file_lock_t **out);
ftun_status_t ftun_file_lock_release(ftun_file_lock_t **lock);

/* 持久文件替换。
 * 需求 REQ-PERSIST-001；任务 TASK-PLATFORM-005；目标 0.3.0；验收 TEST-PLATFORM-005。
 * temporary 必须是普通文件且与 destination 父目录同一文件系统。函数依次
 * fsync 临时文件、rename、fsync 父目录。rename 前失败保留旧权威文件；
 * rename 后失败会返回错误，但不会把已替换文件伪报成旧文件仍然权威。
 */
ftun_status_t ftun_file_replace(const char *temporary,
                                const char *destination);

/* 在 destination 同目录创建唯一临时文件、完整写入并执行上述替换。
 * hook 仅用于故障注入/宿主审计；返回错误立即停止在对应边界。 */
ftun_status_t ftun_file_write_atomic(const char *destination,
                                     ftun_bytes_t contents,
                                     unsigned int mode);
ftun_status_t ftun_file_write_atomic_with_hook(
  const char *destination, ftun_bytes_t contents, unsigned int mode,
  ftun_file_stage_hook_fn hook, void *hook_user);

/* 显式预算覆盖自有路径和每阶段FD；输入内容由调用方计量。
 * 旧独立入口以NULL预算调用，生产宿主应传入其长期预算。 */
ftun_status_t ftun_file_write_atomic_budget(ftun_budget_t *budget,
  const char *destination, ftun_bytes_t contents, unsigned int mode,
  ftun_file_stage_hook_fn hook, void *hook_user);

#endif
