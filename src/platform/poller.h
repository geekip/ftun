#ifndef FTUN_PLATFORM_POLLER_H
#define FTUN_PLATFORM_POLLER_H
#include "util/types.h"
#define FTUN_POLLER_CAPACITY 64u
#define FTUN_POLLER_READ 1u
#define FTUN_POLLER_WRITE 2u
#define FTUN_POLLER_ERROR 4u
/* 原生句柄只由后端解释；存储随调用方预算一起准入。 */
typedef struct {
  size_t collected;
  union { uintptr_t alignment; unsigned char bytes[32]; } native;
} ftun_poller_t;
typedef struct { void *user; uint32_t events; } ftun_poller_event_t;
/* poller 拥有两个 FD。除 wakeup 外全部由 owner 串行调用；user 借用至 remove。
 * wait 只交付 readiness，不执行回调。remove 前必须保证没有在途 wait。 */
ftun_status_t ftun_poller_create(ftun_poller_t *poller);
ftun_status_t ftun_poller_update(ftun_poller_t *poller, ftun_native_socket_t fd,
  uint32_t previous, uint32_t interests, void *user);
ftun_status_t ftun_poller_wait(ftun_poller_t *poller, int timeout_ms,
  ftun_poller_event_t events[FTUN_POLLER_CAPACITY], size_t *count);
void ftun_poller_wakeup(ftun_poller_t *poller);
void ftun_poller_destroy(ftun_poller_t *poller);
#endif
