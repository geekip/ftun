#ifndef FTUN_UTIL_BUFFER_H
#define FTUN_UTIL_BUFFER_H
#include "internal/contracts.h"
#include "core/budget.h"

typedef struct {
  size_t idle_limit_bytes;
  size_t idle_limit_buffers;
  size_t idle_bytes;
  size_t idle_buffers;
  size_t active_buffers;
} ftun_buffer_pool_usage_t;

/* 引用缓冲与池。
 * 需求 REQ-PERF-001；任务 TASK-UTIL-002；目标 0.2.0；验收 TEST-UTIL-002。
 * 按 256 字节起的 2 次幂分档申请；直接 acquire 不保留闲置对象。
 * pool 同时用字节与对象数限制闲置保留，闲置期仍占用预算。
 * slice 创建时 retain owner，释放 slice 前数据保持有效。
 * 全部可变状态由 owner loop 串行访问；不提供跨线程引用计数。
 */
ftun_status_t ftun_buffer_acquire(ftun_budget_t *budget, size_t capacity, ftun_buffer_t **out);
ftun_status_t ftun_buffer_pool_create(ftun_budget_t *budget, size_t idle_limit_bytes,
                                      size_t idle_limit_buffers,
                                      ftun_buffer_pool_t **out);
ftun_status_t ftun_buffer_pool_acquire(ftun_buffer_pool_t *pool, size_t capacity,
                                       ftun_buffer_t **out);
ftun_status_t ftun_buffer_pool_get_usage(const ftun_buffer_pool_t *pool,
                                         ftun_buffer_pool_usage_t *out);
ftun_status_t ftun_buffer_pool_trim(ftun_buffer_pool_t *pool, size_t target_idle_bytes);
ftun_status_t ftun_buffer_pool_destroy(ftun_buffer_pool_t **pool);
ftun_status_t ftun_buffer_retain(ftun_buffer_t *buffer);
ftun_status_t ftun_buffer_data(ftun_buffer_t *buffer, uint8_t **data, size_t *capacity);
ftun_status_t ftun_buffer_release(ftun_buffer_t **buffer);
ftun_status_t ftun_buffer_slice(ftun_buffer_t *buffer, size_t offset, size_t length,
                                ftun_buffer_slice_t *out);
/* slice 是只能通过 clone 复制的所有权值，不得逐字段或 memcpy 复制。 */
ftun_status_t ftun_buffer_slice_clone(const ftun_buffer_slice_t *source,
                                      ftun_buffer_slice_t *out);
ftun_status_t ftun_buffer_slice_data(const ftun_buffer_slice_t *slice, ftun_bytes_t *out);
ftun_status_t ftun_buffer_slice_release(ftun_buffer_slice_t *slice);
#endif
