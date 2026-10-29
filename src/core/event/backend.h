#ifndef FTUN_CORE_EVENT_BACKEND_H
#define FTUN_CORE_EVENT_BACKEND_H
#include "util/types.h"

typedef struct {
  unsigned int version_major;
  unsigned int version_minor;
  const char *backend;
  bool async_thread_safe;
} ftun_event_backend_info_t;

/* 通过 platform/poller 等待 readiness，eventfd 唤醒单一 owner。
 * 先为 adapter/两个自有 FD 准入，source 成员与共享 FD group 分别计内存；
 * 业务 FD 由上层计量。每 FD 一个原生 watcher，成员通知按配额轮转，
 * 所有 timer 共用一个原生唤醒。source 必须在其业务 FD 关闭前取消。
 */
ftun_status_t ftun_event_backend_attach(ftun_event_loop_t *loop);
ftun_status_t ftun_event_backend_get_info(ftun_event_loop_t *loop, ftun_event_backend_info_t *out);
ftun_status_t ftun_event_backend_detach(ftun_event_loop_t *loop);
#endif
