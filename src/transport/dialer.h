#ifndef FTUN_TRANSPORT_DIALER_H
#define FTUN_TRANSPORT_DIALER_H
#include "internal/contracts.h"
#include "core/budget.h"
#include "core/operation.h"
#include "event/event.h"
#include "network/view.h"
#include "network/socket_policy.h"

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

typedef struct {
  ftun_native_socket_t socket;
  ftun_endpoint_t endpoint;
  ftun_dial_transport_t transport;
  ftun_dial_purpose_t purpose;
  ftun_dial_domain_t domain;
  uint64_t network_generation;
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
  const ftun_endpoint_t *allowed;
  size_t allowed_count;
  const ftun_network_view_t *network_view;
  uint64_t network_generation;
  ftun_dial_domain_t requested_domain;
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
 * 实现路径：先核验 endpoint 属于 allowed 集合并通过 NetworkView 收窄
 * Underlay/Overlay，再做 resource admission、必要的 socket protection 和异步
 * 建连。Overlay 不设置 Underlay 绕行标记；受保护但不可达的目标明确拒绝。
 * 调用边界：不访问配置 AST，不跨线程修改 Session。
 * request 在返回前复制；成功 socket 仅在 completion 的 OK 结果中转移给调用方。
 * 同步拒绝清空 out 且零回调；接纳后由 Event/Operation 恰好一次终结。
 */
ftun_status_t ftun_dial_start(ftun_core_t *core, const ftun_dial_request_t *request, ftun_operation_t **out);
/* 共同授权门禁，不分配或打开 socket，不要求 completion；输出失败清零。
 * 非 socket 工厂也须遵守 endpoint/allowed/View/domain/protection 的收窄。 */
ftun_status_t ftun_dial_authorize(const ftun_dial_request_t *request,
  ftun_network_dial_decision_t *out);
/* 测试与受控宿主注入；操作表按值复制。 */
ftun_status_t ftun_dial_start_with_io(ftun_core_t *core,
                                      const ftun_dial_request_t *request,
                                      const ftun_dial_io_t *io,
                                      ftun_operation_t **out);
#endif
