#ifndef FTUN_EVENT_LIBEV_ADAPTER_H
#define FTUN_EVENT_LIBEV_ADAPTER_H
#include "internal/contracts.h"

typedef struct {
  unsigned int version_major;
  unsigned int version_minor;
  const char *backend;
  bool async_thread_safe;
} ftun_libev_info_t;

/* 完整上游 libev 适配。
 * 固定完整上游 4.33 发布包。Linux 仅启用 epoll 后端，保留线程
 * 支持并用自有非阻塞 eventfd 唤醒单一 owner loop。所有 watcher 只存在适配层。
 * 先为 adapter/两个自有 FD 准入，source 成员与共享 FD group 分别计内存；
 * 业务 FD 由上层计量。每 FD 一个原生 watcher，成员通知按配额轮转，
 * 所有 timer 共用一个原生唤醒。source 必须在其业务 FD 关闭前取消。
 */
ftun_status_t ftun_libev_attach(ftun_event_loop_t *loop);
ftun_status_t ftun_libev_get_info(ftun_event_loop_t *loop, ftun_libev_info_t *out);
ftun_status_t ftun_libev_detach(ftun_event_loop_t *loop);
#endif
