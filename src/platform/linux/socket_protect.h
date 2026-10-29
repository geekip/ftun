#ifndef FTUN_PLATFORM_LINUX_SOCKET_PROTECT_H
#define FTUN_PLATFORM_LINUX_SOCKET_PROTECT_H
#include "platform/protect.h"

#define FTUN_LINUX_SOCKET_DEVICE_BYTES 16u

typedef struct {
  ftun_status_t (*get_mark)(void *context, int descriptor, uint32_t *out);
  ftun_status_t (*set_mark)(void *context, int descriptor, uint32_t mark);
  ftun_status_t (*get_device)(void *context, int descriptor,
                              char out[FTUN_LINUX_SOCKET_DEVICE_BYTES]);
  ftun_status_t (*set_device)(void *context, int descriptor,
                              const char *interface_name);
  void *context;
} ftun_linux_socket_io_t;

/* 物理出口保护。
 * 实现路径：在 bind/connect/send 前设置必需 mark/出口约束；DIRECT、DNS、探测、relay 同样保护；必需项失败不得忽略。
 * 调用边界：不访问配置 AST，不跨线程修改 Session。
 * 输入同步借用；必须在 bind/connect/send 前调用。非零 mark 必需，接口名可选；
 * 声明的任一保护失败都返回错误，不允许调用者继续未保护拨号。
 * 已有不同 mark/device 视为冲突，不覆盖其他管理者设置。
 */
ftun_status_t ftun_linux_socket_protect(ftun_native_socket_t socket, const ftun_socket_policy_t *policy);
/* 测试与受控宿主注入；操作表仅在调用期间借用。 */
ftun_status_t ftun_linux_socket_protect_with_io(
  ftun_native_socket_t socket, const ftun_socket_policy_t *policy,
  const ftun_linux_socket_io_t *io);
#endif
