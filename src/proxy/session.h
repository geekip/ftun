#ifndef FTUN_CORE_SESSION_H
#define FTUN_CORE_SESSION_H

#include "internal/contracts.h"

#define FTUN_SESSION_MAX_RESOLVED_IPV4 16u

typedef enum {
  FTUN_SESSION_ACCEPTED = 1,
  FTUN_SESSION_HANDSHAKING,
  FTUN_SESSION_ROUTING,
  FTUN_SESSION_RESOLVING,
  FTUN_SESSION_CONNECTING,
  FTUN_SESSION_REPLYING,
  FTUN_SESSION_RELAYING,
  FTUN_SESSION_DRAINING,
  FTUN_SESSION_CLOSING,
  FTUN_SESSION_CLOSED
} ftun_session_state_t;

typedef struct {
  ftun_session_state_t state;
  uint64_t runtime_generation;
  uint32_t outbound_id;
  size_t allowed_count;
  size_t accounted_bytes;
  ftun_error_t terminal_error;
  bool route_pinned;
  bool has_pending_operation;
} ftun_session_info_t;

/* 统一业务会话。
 * 需求 REQ-CORE-001；任务 TASK-CORE-002；目标 0.2.0；验收 TEST-CORE-002。
 * submit 在返回前复制 Metadata 及其域名/候选，保留 active Runtime 和 inbound
 * Stream，并把 generation 固定到接纳时快照。成功后调用方不得销毁 Stream，
 * 直到 Session CLOSED 且 destroy 已释放保留引用。
 */
ftun_status_t ftun_session_submit(ftun_core_t *core,
                                  const ftun_metadata_t *metadata,
                                  ftun_stream_t *inbound,
                                  ftun_session_t **out);

/* 状态严格遵循架构状态机；operation 可为空。若非空，Session 在对应回调调用
 * operation_complete 前一直保留它，且同时最多一个子操作。 */
ftun_status_t ftun_session_transition(ftun_session_t *session,
                                      ftun_session_state_t next,
                                      ftun_operation_t *operation);
/* 只在 ROUTING 固定一次 READY 结果；allowed 必须是已有 resolved 的子集，
 * 没有本地候选时只允许空集合或原目标，禁止扩大候选。 */
ftun_status_t ftun_session_pin_route(ftun_session_t *session,
                                     const ftun_route_result_t *route);
/* 必须由被保留 operation 的 completion 回调调用；错误会关闭 Session。
 * 取消只请求子操作终结，Runtime/Stream 在本函数清零句柄前不会释放。 */
ftun_status_t ftun_session_operation_complete(ftun_session_t *session,
                                               ftun_operation_t *operation,
                                               ftun_error_t result);
/* 入站 adapter 需要先发送错误回复时使用：仅 RESOLVING/CONNECTING 的
 * 非取消终态错误进入 REPLYING，记录错误并保持 inbound 可写。调用方必须
 * 持有有界回复期限，回复完成或超时后 finish/cancel；不能再进入 RELAYING。
 * 已开始关闭、成功及取消沿用 operation_complete 的行为。 */
ftun_status_t ftun_session_operation_complete_for_reply(ftun_session_t *session,
  ftun_operation_t *operation, ftun_error_t result);
/* RESOLVING completion 在清零 operation 前调用。addresses 是解析器返回的
 * 无端口 IPv4，同步复制进 Session 并补 original target 端口；只允许首次
 * 写入，后续路由和出口必须复用，不能以再次解析扩大候选。 */
ftun_status_t ftun_session_store_resolved(
  ftun_session_t *session, ftun_operation_t *operation,
  const ftun_endpoint_t *addresses, size_t address_count);
ftun_status_t ftun_session_finish(ftun_session_t *session,
                                  ftun_error_t result);
ftun_status_t ftun_session_cancel(ftun_session_t *session);

/* 以下输出均借用 Session，到 destroy 为止有效。 */
ftun_status_t ftun_session_get_info(const ftun_session_t *session,
                                    ftun_session_info_t *out);
ftun_status_t ftun_session_get_metadata(const ftun_session_t *session,
                                        const ftun_metadata_t **out);
ftun_status_t ftun_session_get_route(const ftun_session_t *session,
                                     const ftun_route_result_t **out);
ftun_status_t ftun_session_get_runtime(const ftun_session_t *session,
                                       const ftun_runtime_t **out);

/* 仅 CLOSED 且无子操作时销毁；成功归还 Stream/Runtime 引用和全部预算。 */
ftun_status_t ftun_session_destroy(ftun_session_t **session);

#endif
