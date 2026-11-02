#ifndef FTUN_APP_CONTROL_SERVER_H
#define FTUN_APP_CONTROL_SERVER_H
#include "util/types.h"

#define FTUN_CTL_CONNECTIONS 8u
#define FTUN_CTL_EVENT_SOURCES (FTUN_CTL_CONNECTIONS + 2u)
#define FTUN_CTL_RESPONSE_MAX 65536u
typedef struct ftun_ctl_server ftun_ctl_server_t;

/* CLI在持有PID锁且启动线程前创建，拥有server并借用Core至destroy。
 * 固定连接/请求/响应缓冲及FD峰值先准入；path复制，不借CLI栈。
 * bind只在CREATED或run返回后清空；默认组合通过opaque binding借用server。 */
ftun_status_t ftun_ctl_server_create(ftun_core_t *core, const char *path,
  ftun_ctl_server_t **out);
ftun_status_t ftun_app_control_bind_server(ftun_core_t *core, ftun_ctl_server_t *server);
/* 以下由同一owner串行调用。attach早于业务source；detach撤销所有事件引用，
 * 保留等待终态/未写完的流。finish仅在run返回、回调已截止后有界排空。 */
ftun_status_t ftun_ctl_server_attach(ftun_ctl_server_t *server, ftun_event_loop_t *loop);
ftun_status_t ftun_ctl_server_detach(ftun_ctl_server_t *server);
ftun_status_t ftun_ctl_server_error(ftun_ctl_server_t *server);
ftun_status_t ftun_ctl_server_finish(ftun_ctl_server_t *server, ftun_status_t result);
/* owner业务静默后、日志撤销前；不声称writer已排空或Core已STOPPED。 */
void ftun_ctl_server_runtime_stopped(ftun_ctl_server_t *server, ftun_error_t error, uint64_t generation);
ftun_status_t ftun_ctl_server_destroy(ftun_ctl_server_t **server);
/* 仅fork父进程、尚未attach的副本：不删除端点，消费自有对象和FD。 */
ftun_status_t ftun_ctl_server_discard(ftun_ctl_server_t **server);
#endif
