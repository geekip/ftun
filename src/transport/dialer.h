#ifndef FTUN_TRANSPORT_DIALER_H
#define FTUN_TRANSPORT_DIALER_H
#include "internal/contracts.h"
#include "core/budget.h"
#include "core/operation.h"
#include "event/event.h"
#include "platform/linux/socket_protect.h"

#define FTUN_INVALID_SOCKET ((ftun_native_socket_t)UINTPTR_MAX)

#define FTUN_DIAL_STAGE_ADMISSION 1u
#define FTUN_DIAL_STAGE_SOCKET 2u
#define FTUN_DIAL_STAGE_PROTECT 3u
#define FTUN_DIAL_STAGE_CONNECT 4u
#define FTUN_DIAL_STAGE_WAIT 5u
#define FTUN_DIAL_STAGE_TIMEOUT 6u

typedef enum {
  FTUN_DIAL_TCP = 1,
  FTUN_DIAL_UDP
} ftun_dial_transport_t;

typedef enum {
  FTUN_DIAL_PURPOSE_BUSINESS = 1,
  FTUN_DIAL_PURPOSE_PROXY,
  FTUN_DIAL_PURPOSE_DNS,
  FTUN_DIAL_PURPOSE_BOOTSTRAP,
  FTUN_DIAL_PURPOSE_PROBE,
  FTUN_DIAL_PURPOSE_FRS_UPDATE
} ftun_dial_purpose_t;

typedef struct {
  ftun_native_socket_t socket;
  ftun_endpoint_t endpoint;
  ftun_dial_transport_t transport;
  ftun_dial_purpose_t purpose;
} ftun_dial_result_t;

typedef void (*ftun_dial_completion_fn)(ftun_operation_t *operation,
                                        ftun_error_t error,
                                        const ftun_dial_result_t *result,
                                        void *user);

struct ftun_dial_request {
  ftun_event_loop_t *loop;
  ftun_operation_queue_t *operations;
  ftun_budget_t *budget;
  ftun_endpoint_t endpoint;
  ftun_socket_policy_t protection;
  uint64_t deadline_ms;
  ftun_dial_transport_t transport;
  ftun_dial_purpose_t purpose;
  ftun_dial_completion_fn completion;
  void *user;
};

typedef struct {
  ftun_status_t (*open_socket)(void *context, ftun_dial_transport_t transport,
                               ftun_native_socket_t *out);
  ftun_status_t (*protect_socket)(void *context, ftun_native_socket_t socket,
                                  const ftun_socket_policy_t *policy);
  /* connect 只返回 OK、AGAIN 或终结错误。 */
  ftun_status_t (*connect_socket)(void *context, ftun_native_socket_t socket,
                                  const ftun_endpoint_t *endpoint);
  ftun_status_t (*get_socket_error)(void *context, ftun_native_socket_t socket);
  /* close 总是消费 socket，即使返回错误。 */
  ftun_status_t (*close_socket)(void *context, ftun_native_socket_t socket);
  void *context;
} ftun_dial_io_t;

/* 唯一物理拨号入口。
 * 需求 REQ-GUARD-001；任务 TASK-TRANSPORT-001；目标 0.2.0；验收 TEST-TRANSPORT-001。
 * 实现路径：先 resource admission 和 socket protection，再异步建连；记录 purpose；业务流量不按目的地址全局豁免规则。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * request 在返回前复制；成功 socket 仅在 completion 的 OK 结果中转移给调用方。
 * 同步拒绝清空 out 且零回调；接纳后由 Event/Operation 恰好一次终结。
 */
ftun_status_t ftun_dial_start(ftun_core_t *core, const ftun_dial_request_t *request, ftun_operation_t **out);
/* 测试与受控宿主注入；操作表按值复制。 */
ftun_status_t ftun_dial_start_with_io(ftun_core_t *core,
                                      const ftun_dial_request_t *request,
                                      const ftun_dial_io_t *io,
                                      ftun_operation_t **out);
#endif
