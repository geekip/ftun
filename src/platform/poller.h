#ifndef FTUN_PLATFORM_POLLER_H
#define FTUN_PLATFORM_POLLER_H
#include "util/types.h"
#define FTUN_POLLER_CAPACITY 64u
#define FTUN_POLLER_READ 1u
#define FTUN_POLLER_WRITE 2u
#define FTUN_POLLER_ERROR 4u
#define FTUN_POLLER_WAITABLE 1u
typedef struct {
  ftun_native_socket_t socket;
  uint32_t events;
  uint32_t kind;
#if defined(_WIN32)
  void *registration;
#endif
} ftun_poller_io_t;
/* 后端内部存储由宿主先准入再分配；release在原生对象真正静默后调用。
 * context借用至destroy返回；回调不得重入poller，由owner串行调用。 */
typedef struct {
  void *(*allocate)(void *context, size_t bytes, size_t descriptors);
  void (*release)(void *context, void *allocation);
  void *context;
} ftun_poller_memory_t;
#if defined(_WIN32)
#define FTUN_POLLER_HANDLES 4u
#define FTUN_POLLER_NAME "wepoll"
#define FTUN_POLLER_NATIVE_BYTES 80u
#elif defined(__APPLE__)
#define FTUN_POLLER_NATIVE_BYTES 32u
#define FTUN_POLLER_HANDLES 1u
#define FTUN_POLLER_NAME "kqueue"
#else
#define FTUN_POLLER_NATIVE_BYTES 32u
#define FTUN_POLLER_HANDLES 2u
#define FTUN_POLLER_NAME "epoll"
#endif
/* 原生句柄只由后端解释；存储随调用方预算一起准入。 */
typedef struct {
  size_t collected;
  union { uintptr_t alignment; unsigned char bytes[FTUN_POLLER_NATIVE_BYTES]; } native;
} ftun_poller_t;
typedef struct { void *user; uint32_t events; } ftun_poller_event_t;
/* FTUN_POLLER_HANDLES是固定句柄构造峰值；动态句柄通过memory回调单独准入。除 wakeup 外全部由 owner 串行调用；user 借用至 remove。
 * wait 只交付 readiness，不执行回调。remove 前必须保证没有在途 wait。 */
ftun_status_t ftun_poller_create(ftun_poller_t *poller, ftun_poller_memory_t memory);
ftun_status_t ftun_poller_update(ftun_poller_t *poller, ftun_poller_io_t *io,
  uint32_t interests, void *user);
ftun_status_t ftun_poller_wait(ftun_poller_t *poller, int timeout_ms,
  ftun_poller_event_t events[FTUN_POLLER_CAPACITY], size_t *count);
void ftun_poller_wakeup(ftun_poller_t *poller);
void ftun_poller_destroy(ftun_poller_t *poller);
#endif
