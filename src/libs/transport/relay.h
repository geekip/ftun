#ifndef FTUN_LIBS_TRANSPORT_RELAY_H
#define FTUN_LIBS_TRANSPORT_RELAY_H
#include "util/types.h"
#include "core/event/loop.h"
#include "libs/transport/stream.h"

#define FTUN_RELAY_DEFAULT_HIGH_WATER 65536u
#define FTUN_RELAY_DEFAULT_LOW_WATER 32768u
#define FTUN_RELAY_DEFAULT_MAX_WORK 64u

typedef struct {
  size_t high_water_bytes;
  size_t low_water_bytes;
  size_t max_work_per_round;
} ftun_relay_options_t;

typedef struct {
  size_t left_to_right_buffered;
  size_t right_to_left_buffered;
  size_t total_read_bytes;
  size_t total_written_bytes;
  uint32_t left_interests;
  uint32_t right_interests;
  ftun_status_t terminal_status;
  bool left_eof;
  bool right_eof;
  bool left_write_shutdown;
  bool right_write_shutdown;
  bool stopped;
  bool complete;
  bool left_buffer_waiting;
  bool right_buffer_waiting;
} ftun_relay_usage_t;

typedef void (*ftun_relay_progress_fn)(void *user);

/* 双向背压中继。
 * 缓冲首次 READ 时才申请；达到高水位暂停源 READ，降至低水位恢复。
 * WRITE 只在未接纳数据或 half-close 返回 AGAIN 时进入 interests。
 * EOF 方向必须先排空已接纳/待接纳数据，再向另一侧 shutdown-write。
 * left/right 由调用方拥有，必须比 relay session 长寿且使用同一 Budget。
 */
ftun_status_t ftun_relay_start(ftun_core_t *core, ftun_stream_t *left,
                               ftun_stream_t *right, ftun_relay_t **out);
ftun_status_t ftun_relay_start_with_options(
  ftun_core_t *core, ftun_stream_t *left, ftun_stream_t *right,
  const ftun_relay_options_t *options, ftun_relay_t **out);
/* Pool 压力解除时 progress 只安排 owner 再推进一次，不得销毁 relay。 */
ftun_status_t ftun_relay_start_with_pool_options(
  ftun_core_t *core, ftun_stream_t *left, ftun_stream_t *right,
  ftun_buffer_pool_t *pool, const ftun_relay_options_t *options,
  ftun_relay_progress_fn progress, void *progress_user, ftun_relay_t **out);
/* events 是新增就绪位；READ 跨配额/背压保留至 AGAIN/EOF。
 * 单次最多执行 options.max_work_per_round 个动作。 */
ftun_status_t ftun_relay_process(ftun_relay_t *relay,
                                 uint32_t left_events,
                                 uint32_t right_events,
                                 size_t *out_work);
ftun_status_t ftun_relay_stop(ftun_relay_t *relay);
ftun_status_t ftun_relay_get_usage(const ftun_relay_t *relay,
                                   ftun_relay_usage_t *out);
ftun_status_t ftun_relay_destroy(ftun_relay_t **relay);

#endif
