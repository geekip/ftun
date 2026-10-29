#ifndef FTUN_PLATFORM_FILE_H
#define FTUN_PLATFORM_FILE_H
#include "util/types.h"

typedef enum {
  FTUN_FILE_STAGE_TEMP_SYNCED = 1,
  FTUN_FILE_STAGE_RENAMED,
  FTUN_FILE_STAGE_DIRECTORY_SYNCED
} ftun_file_stage_t;

typedef ftun_status_t (*ftun_file_stage_hook_fn)(ftun_file_stage_t stage,
                                                  void *user);

typedef struct { ftun_handle_t descriptor; } ftun_file_handle_t;
typedef ftun_file_handle_t ftun_platform_file_lock_t;
#define FTUN_FILE_INVALID {-1}
#define FTUN_FILE_TEMPORARY_SUFFIX "/.ftun.tmp.XXXXXX"
/* 文件句柄由平台操作；close 即使返回错误也消费句柄。
 * open_append 借用 path，返回文件当前字节数；不保留路径、不分配堆存储。
 * write 返回实际写入字节数，失败也报告已写前缀，不重发已交付的数据。 */
bool ftun_platform_file_is_open(const ftun_file_handle_t *file);
ftun_status_t ftun_platform_file_open_append(const char *path, bool truncate,
  ftun_file_handle_t *out, uint64_t *size);
ftun_status_t ftun_platform_file_close(ftun_file_handle_t *file);
ftun_status_t ftun_platform_file_write(ftun_file_handle_t *file,
  ftun_bytes_t contents, size_t *written);
/* 用于日志编号轮转：来源不存在时无需改名，其他失败明确返回错误。 */
ftun_status_t ftun_platform_file_rename_if_exists(const char *from, const char *to);
/* 同步文件原语，不做堆分配或资源准入；调用方先准入所需 FD 和路径存储。
 * parent 返回输入 path 或静态文本的借用，借用期不超过 path；不写入输入。 */
ftun_status_t ftun_platform_file_parent(const char *path, ftun_string_t *out);
/* acquire 成功交付一个 FD 的拥有权；失败不交付资源。release 无论状态均消费。
 * 调用方必须在没有并发使用时释放；不回调，不保留 path。 */
ftun_status_t ftun_platform_file_lock_acquire(const char *path, ftun_platform_file_lock_t *out);
ftun_status_t ftun_platform_file_lock_release(ftun_platform_file_lock_t *lock);
/* 同步持久化，占用两个 FD；按 fsync/rename/fsync 顺序调用 hook。
 * published 在 rename 成功时置位，后续失败也不撤销；hook 不得修改相关路径。
 * 输入同步借用，返回前关闭全部 FD，不拥有任何路径或 hook_user。 */
ftun_status_t ftun_platform_file_replace(const char *temporary,
  const char *destination, const char *parent, ftun_file_stage_hook_fn hook,
  void *hook_user, bool *published);
/* 占用一个 FD，修改调用方提供的唯一临时路径模板；完整写入并关闭。
 * created 说明路径已创建，失败时仍由调用方清理，不保留 contents。 */
ftun_status_t ftun_platform_file_write_temporary(char *temporary,
  ftun_bytes_t contents, unsigned int mode, bool *created);
void ftun_platform_file_remove_temporary(const char *temporary);
/* 单次就绪探测和有界诊断写入，不等待、不重试。 */
ftun_status_t ftun_platform_file_write_ready(ftun_handle_t descriptor, ftun_bytes_t contents);
/* 原生文件原语只借用路径与缓冲，不分配堆存储；调用方负责 FD/内存准入。
 * open 成功交付一个 FD；close 总是消费 FD。inspect 不打开 FD。
 * read 返回已读字节数，0 为 EOF，-1 为 I/O 错误；平台处理信号中断。 */
typedef enum {
  FTUN_FILE_READ = 0,
  FTUN_FILE_READ_NOFOLLOW,
  FTUN_FILE_READ_DIRECTORY,
  FTUN_FILE_APPEND_EXISTING
} ftun_file_open_mode_t;
typedef struct {
  uint64_t size;
  bool regular;
  bool directory;
} ftun_file_info_t;
ftun_status_t ftun_file_open(const char *path, ftun_file_open_mode_t mode, ftun_handle_t *out);
ftun_status_t ftun_file_close(ftun_handle_t descriptor);
ftun_status_t ftun_file_inspect(ftun_handle_t descriptor, ftun_file_info_t *out);
ftun_status_t ftun_file_inspect_path(const char *path, ftun_file_info_t *out);
ptrdiff_t ftun_file_read(ftun_handle_t descriptor, void *buffer, size_t capacity);
ptrdiff_t ftun_file_write_some(ftun_handle_t descriptor, const void *buffer, size_t length,
  ftun_status_t *status);
ftun_status_t ftun_file_sync(ftun_handle_t descriptor, bool data_only);
ftun_status_t ftun_directory_create(const char *path, unsigned int mode);
ftun_status_t ftun_directory_ensure(const char *path, unsigned int mode);
void ftun_directory_remove(const char *path);
/* 映射失败返回 NULL，原 FD 的偏移保持不变；成功后调用方拥有 unmap 责任。 */
void *ftun_file_map_read(ftun_handle_t descriptor, size_t length);
ftun_status_t ftun_file_unmap(const void *address, size_t length);
ftun_status_t ftun_file_real_path(const char *path, char *out, size_t capacity);
/* home 借用 storage；AGAIN 表示调用方应提供更大的有界缓冲。 */
ftun_status_t ftun_user_home(char *storage, size_t capacity, ftun_string_t *home);
ftun_status_t ftun_file_duplicate(ftun_handle_t descriptor, ftun_handle_t *out);
/* 等待一次可写，超时返回 AGAIN；信号中断交还上层检查截止时间。 */
ftun_status_t ftun_file_wait_writable(ftun_handle_t descriptor, uint32_t timeout_ms);
int ftun_file_standard_error(void);
#endif
