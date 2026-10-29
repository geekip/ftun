#ifndef FTUN_APP_CLI_RESULT_H
#define FTUN_APP_CLI_RESULT_H

#include "core/limits.h"

typedef struct ftun_cli_result_sink ftun_cli_result_sink_t;
typedef struct ftun_cli_result_ticket ftun_cli_result_ticket_t;

typedef enum {
  FTUN_CLI_RESULT_RELOAD_COMMITTED = 1,
  FTUN_CLI_RESULT_RELOAD_REJECTED,
  FTUN_CLI_RESULT_RELOAD_REQUEST_REJECTED,
  FTUN_CLI_RESULT_STOP_FAILED,
  FTUN_CLI_RESULT_RUN_FAILED
} ftun_cli_result_kind_t;

typedef struct {
  size_t capacity;
  size_t reserved;
  size_t ready;
  uint64_t accepted;
  uint64_t written;
  uint64_t write_failed;
  uint64_t admission_rejected;
  uint64_t rejection_notices;
  uint64_t undelivered;
  bool accepting;
  bool stopping;
  bool exited;
  ftun_budget_resources_t owned_resources;
  size_t budget_metadata_bytes;
} ftun_cli_result_usage_t;

/* descriptor 只借到调用返回；sink 持有独立 duplicate，且不修改共享 OFD 标志。
 * 固定对象/34 槽/1 FD 由 sink 自有 Budget 计量，独立于可更早销毁的
 * Core 根。usage 可与 Core 账本相加；线程栈、allocator/内核内存另计。 */
ftun_status_t ftun_cli_result_sink_create(int descriptor,
                                          ftun_cli_result_sink_t **out);
/* reserve 必须先于异步操作接纳；成功 ticket 只允许 publish 一次。 */
ftun_status_t ftun_cli_result_reserve(ftun_cli_result_sink_t *sink,
                                      ftun_cli_result_ticket_t **out);
/* stop/run 各有一个专用槽，不受 reload 槽耗尽影响。 */
ftun_status_t ftun_cli_result_reserve_terminal(ftun_cli_result_sink_t *sink,
  ftun_cli_result_kind_t kind, ftun_cli_result_ticket_t **out);
/* reserve 失败已计入 admission_rejected；该接口只把拒绝结果交给 writer。
 * 固定容量外仅累加待输出计数，不分配对象。 */
ftun_status_t ftun_cli_result_report_admission_rejected(
  ftun_cli_result_sink_t *sink, ftun_status_t status);
ftun_status_t ftun_cli_result_publish(ftun_cli_result_ticket_t *ticket,
                                      ftun_cli_result_kind_t kind,
                                      ftun_status_t status, uint32_t stage);
/* 未产生用户可见结果时归还尚未发布的 ticket。 */
ftun_status_t ftun_cli_result_abandon(ftun_cli_result_ticket_t *ticket);
ftun_status_t ftun_cli_result_get_usage(ftun_cli_result_sink_t *sink,
                                        ftun_cli_result_usage_t *out);
/* 到期时把完整拥有对象转给 writer，清空调用方指针；迟到 writer 不借用
 * Core、CLI 栈或外部 descriptor。TIMEOUT 只表示结果未在期限内排空。 */
ftun_status_t ftun_cli_result_sink_stop_until(ftun_cli_result_sink_t **sink,
                                              uint64_t deadline_ms);

#endif
