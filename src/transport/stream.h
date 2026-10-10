#ifndef FTUN_TRANSPORT_STREAM_H
#define FTUN_TRANSPORT_STREAM_H
#include "internal/contracts.h"
#include "core/budget.h"
#include "core/operation.h"
#include "util/buffer.h"

typedef struct ftun_stream_write ftun_stream_write_t;

typedef struct {
  /* read 返回 OK 时必须产生 1..capacity 字节；AGAIN/EOF 必须为零。 */
  ftun_status_t (*read)(void *context, void *buffer, size_t capacity,
                        size_t *out_length);
  /* OK 表示接纳 accepted 个前缀字节；返回前不得 complete。
   * 其他状态表示零接纳，且 backend 不得保留 write。 */
  ftun_status_t (*write_start)(void *context, ftun_stream_write_t *write,
                               const ftun_buffer_slice_t *slice,
                               size_t *accepted);
  /* OK 后 backend 不再访问 write；失败时所有权不变，可重试。 */
  ftun_status_t (*write_cancel)(void *context, ftun_stream_write_t *write);
  ftun_status_t (*shutdown_write)(void *context);
  void (*destroy)(void *context);
  void *context;
} ftun_stream_backend_t;

typedef struct {
  ftun_budget_t *budget;
  ftun_operation_queue_t *operations;
  size_t max_pending_writes;
  size_t max_pending_bytes;
  ftun_completion_fn completion;
  void *completion_user;
} ftun_stream_options_t;

typedef struct {
  size_t max_pending_writes;
  size_t max_pending_bytes;
  size_t pending_writes;
  size_t pending_bytes;
  size_t reference_count;
  bool accepting;
  bool in_completion;
  bool write_shutdown;
} ftun_stream_usage_t;

/* 可保留引用的字节流。
 * 需求 REQ-CORE-001；任务 TASK-TRANSPORT-002；目标 0.2.0；验收 TEST-TRANSPORT-002。
 * 同步未接纳不保留 BufferSlice；接纳后 Stream clone 前缀并持有到 operation
 * completion 回调开始。backend 只有在真实消费、写失败或 ACK 后调用 complete，
 * 排入 backend 队列本身不表示原缓冲可释放。全部状态属于 owner loop。
 */
ftun_status_t ftun_stream_create(const ftun_stream_options_t *options,
                                 const ftun_stream_backend_t *backend,
                                 ftun_stream_t **out);
ftun_status_t ftun_stream_write_ref(ftun_stream_t *stream,
                                    const ftun_buffer_slice_t *slice,
                                    size_t *accepted,
                                    ftun_operation_t **out);
ftun_status_t ftun_stream_write_ref_with_completion(
  ftun_stream_t *stream, const ftun_buffer_slice_t *slice,
  ftun_completion_fn completion, void *completion_user,
  size_t *accepted, ftun_operation_t **out);
ftun_status_t ftun_stream_read(ftun_stream_t *stream, void *buffer,
                               size_t capacity, size_t *out_length);
ftun_status_t ftun_stream_shutdown_write(ftun_stream_t *stream);
/* 返回创建时借用的 Budget，供同一 owner loop 的组合器做统一准入。 */
ftun_status_t ftun_stream_budget(ftun_stream_t *stream, ftun_budget_t **out);
/* 组合器可保留 Stream；创建者的初始引用始终由 destroy 消费。 */
ftun_status_t ftun_stream_retain(ftun_stream_t *stream);
ftun_status_t ftun_stream_release(ftun_stream_t **stream);
/* backend 可在 start 返回后重复查询保留的前缀；输出只借用到 complete/cancel。 */
ftun_status_t ftun_stream_write_data(const ftun_stream_write_t *write,
                                     ftun_bytes_t *out);
/* complete 成功后 backend 立即放弃 write，用户回调仍由 operation dispatch 延迟。 */
ftun_status_t ftun_stream_write_complete(ftun_stream_write_t *write,
                                         ftun_error_t error);
/* stop 只关闭新写接纳；在途写由 operation cancel/queue stop 终结。 */
ftun_status_t ftun_stream_stop(ftun_stream_t *stream);
ftun_status_t ftun_stream_get_usage(const ftun_stream_t *stream,
                                    ftun_stream_usage_t *out);
/* 必须先 stop、只有创建者引用且所有 completion 已 dispatch；成功后调用 backend destroy。 */
ftun_status_t ftun_stream_destroy(ftun_stream_t **stream);

#endif
