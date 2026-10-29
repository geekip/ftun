#ifndef FTUN_LIBS_RESOLVER_CONTROL_CHANNEL_H
#define FTUN_LIBS_RESOLVER_CONTROL_CHANNEL_H

#include "libs/transport/path.h"
#include "libs/resolver/resolver.h"

typedef struct ftun_control_channel ftun_control_channel_t;

/* open 在任务线程调用。context 必须不可变或自行同步，并长寿于全部任务
 * 和迟到清理；不得传入主 owner 的可变 Provider/Runtime。 */
typedef struct {
  ftun_status_t (*open)(void *, ftun_core_t *, const ftun_path_open_request_t *,
    const ftun_path_spec_t *, ftun_operation_t **);
  void *context;
} ftun_control_path_binding_t;

/* 同步控制任务的执行身份。预算借用至整个任务及迟到清理结束；其余字段
 * 按值复制，不借用主 owner 的 Event、Provider 或可变 Runtime。 */
typedef struct {
  ftun_budget_t *budget;
  uint64_t generation;
  uint64_t deadline_ms;
  ftun_dial_purpose_t purpose;
  bool allow_system_resolver;
  ftun_control_path_binding_t path;
} ftun_control_execution_t;

/* 保留外层绝对期限；协议自身超时只能收窄，不得重新延长任务期限。 */
ftun_status_t ftun_control_execution_limit(const ftun_control_execution_t *input,
  uint64_t timeout_ms, ftun_control_execution_t *out);

/* 控制任务专用的同步适配：调用线程拥有独立 Event/Operation/Path，禁止
 * 在数据面 owner 上调用。所有等待使用请求绝对期限，不借用主循环状态。
 * close 失败保留整个对象；调用线程必须继续排空，不能释放仍被回调引用的
 * 状态。外层 Worker 停止期限不依赖这里返回，生产者存活时仍保留 Worker。 */
ftun_status_t ftun_control_channel_create(ftun_budget_t *budget,
  uint64_t generation, uint64_t deadline_ms, ftun_control_channel_t **out);
ftun_status_t ftun_control_channel_create_execution(
  const ftun_control_execution_t *execution, ftun_control_channel_t **out);
/* 一次解析占用一个 Provider/Operation，结果复制为首个 IPv4。工厂与 context
 * 借用至 drain 完成；请求输入只借用至 start 返回。回调不得使用调用方输出。
 * 同一通道只接纳一次解析，loop/operations 和完成函数由本地 owner 注入。 */
ftun_status_t ftun_control_channel_resolve(ftun_control_channel_t *channel,
  const ftun_resolver_provider_ops_t *ops, void *context,
  const ftun_resolver_provider_request_t *request, ftun_endpoint_t *out);
ftun_status_t ftun_control_channel_connect(ftun_control_channel_t *channel,
  const ftun_endpoint_t *endpoint, uint32_t mark, ftun_dial_purpose_t purpose);
ftun_status_t ftun_control_channel_connect_datagram(ftun_control_channel_t *channel,
  const ftun_endpoint_t *endpoint, uint32_t mark, ftun_dial_purpose_t purpose);
ftun_status_t ftun_control_channel_read(void *channel, uint8_t *buffer,
  size_t capacity, size_t *length);
ftun_status_t ftun_control_channel_write(void *channel, const uint8_t *buffer,
  size_t length, size_t *written);
ftun_status_t ftun_control_channel_read_exact(ftun_control_channel_t *channel,
  uint8_t *buffer, size_t length);
ftun_status_t ftun_control_channel_write_all(ftun_control_channel_t *channel,
  const uint8_t *buffer, size_t length);
/* 整包发送等待本地完成，不表示远端收到；允许空报文。接收只保留一包，
 * 调用方缓冲不足时丢弃整包并返回 LIMIT，不交付截断数据。AGAIN 后用 wait
 * 驱动同一 owner；接收源只接受数值 IPv4，不借用回调中的域名存储。 */
ftun_status_t ftun_control_channel_send(ftun_control_channel_t *channel,
  const ftun_endpoint_t *target, const uint8_t *buffer, size_t length);
ftun_status_t ftun_control_channel_receive(ftun_control_channel_t *channel,
  ftun_endpoint_t *source, uint8_t *buffer, size_t capacity, size_t *length);
ftun_status_t ftun_control_channel_wait(ftun_control_channel_t *channel);
ftun_status_t ftun_control_channel_close(ftun_control_channel_t **channel);
/* 只用于生产者线程回收；期限后仍保留取消失败的生产者，不回调主循环。 */
void ftun_control_channel_drain(ftun_control_channel_t **channel);

#endif
