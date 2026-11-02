#ifndef FTUN_PLATFORM_PIDFILE_H
#define FTUN_PLATFORM_PIDFILE_H

#include "platform/file.h"

typedef struct {
  ftun_file_handle_t file;
  const char *path;
} ftun_pidfile_t;

#define FTUN_PIDFILE_INVALID {FTUN_FILE_INVALID, NULL}

/* 启动线程前串行调用；path 借用至 release/discard。成功拥有一个 FD，
 * 同步失败不交付资源。AGAIN 表示已持锁，holder 尽可能给出持有者 PID。
 * probe 最多临时打开一个 FD，EOF 表示缺失或锁已失效，不以 PID 存在判活。 */
ftun_status_t ftun_pidfile_acquire(const char *path, ftun_pidfile_t *out,
  uint32_t *holder);
ftun_status_t ftun_pidfile_probe(const char *path, uint32_t *pid);
ftun_status_t ftun_pidfile_rewrite(ftun_pidfile_t *pidfile);
/* release 只删除仍指向本实例文件的路径，始终消费句柄。
 * discard 仅关闭本进程句柄；fork 父进程不得解锁子进程继承的打开描述。 */
ftun_status_t ftun_pidfile_release(ftun_pidfile_t *pidfile);
ftun_status_t ftun_pidfile_discard(ftun_pidfile_t *pidfile);

/* 有界路径构造，不创建目录；NULL 使用 root/普通用户默认路径，~ 只展开一次。
 * HOME 不可用时失败；socket 路径按本机原生长度上限校验。 */
ftun_status_t ftun_pidfile_path(const char *configured, char *out, size_t capacity);
ftun_status_t ftun_pidfile_socket_path(const char *path, char *out, size_t capacity);
/* 原生后端共用的有界内容读取；descriptor 借用且位于文件开头。 */
ftun_status_t ftun_pidfile_read(ftun_handle_t descriptor, uint32_t *pid);

#endif
