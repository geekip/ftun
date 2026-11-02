#ifndef FTUN_PLATFORM_IPC_H
#define FTUN_PLATFORM_IPC_H
#include "util/types.h"

typedef struct {
  ftun_handle_t socket;
  const char *path;
  uint64_t device, inode;
} ftun_ipc_listener_t;
#define FTUN_IPC_LISTENER_INVALID {-1, NULL, 0u, 0u}

/* 调用方已持有对应PID文件锁，才可替换残留端点；非socket路径不会删除。
 * 成功交付1个非阻塞、close-on-exec句柄，path借用至close，调用前准入FD。
 * close消费句柄，只删除仍属于本监听的路径；不分配、不等待或重试。
 * 不具备带对端身份的本机IPC的平台明确返回UNSUPPORTED。 */
ftun_status_t ftun_ipc_listen(const char *path, ftun_ipc_listener_t *out);
ftun_status_t ftun_ipc_listener_close(ftun_ipc_listener_t *listener);
/* fork父进程关闭自己的句柄副本，不移除子进程仍持有的端点。 */
ftun_status_t ftun_ipc_listener_discard(ftun_ipc_listener_t *listener);
/* accept后的流句柄借用；系统凭据必须与实例相同用户或为root。
 * 鉴权不通过是OK+false，凭据读取失败返回错误，禁止降级到路径权限。 */
ftun_status_t ftun_ipc_peer_allowed(ftun_handle_t socket, bool *allowed, uint64_t *user_id);
/* 仅独立命令进程使用，在绝对单调期限内连接；成功交付一个非阻塞FD。
 * EOF表示端点缺失或无人监听；不重试、不扫描其他路径。 */
ftun_status_t ftun_ipc_connect(const char *path, uint64_t deadline_ms,
  ftun_handle_t *out);
#endif
