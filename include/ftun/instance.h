#ifndef FTUN_INSTANCE_H
#define FTUN_INSTANCE_H
#include "ftun/errors.h"
#include "ftun/version.h"
#ifdef __cplusplus
extern "C" {
#endif
#include <stddef.h>
#include <stdint.h>
typedef struct ftun_core ftun_core_t;
typedef struct ftun_operation ftun_operation_t;
typedef struct {
  size_t struct_size;
  uint32_t abi_version;
  size_t owned_memory_limit;
  size_t operation_capacity;
  size_t retained_runtime_limit;
  /* Zero selects an internal bounded default.  Descriptor and queue credits
   * are logical admission limits; kernel limits may still be lower. */
  size_t owned_descriptor_limit;
  size_t owned_queue_limit;
  /* 旧代数量之外的独立字节上限；零值取 owned_memory_limit 的一半。 */
  size_t retained_runtime_bytes_limit;
} ftun_core_options_t;
/* create 成功才转移 Core 所有权；失败 *out=NULL，无 fd/线程/回调。 */
ftun_status_t ftun_core_create(const ftun_core_options_t *options, ftun_core_t **out);
/* run 在线程内拥有 loop。正常返回表示完全停止；停止 deadline 到达时返回
 * TIMEOUT 并保留仍被后台调用引用的对象，此后不会再产生用户回调，宿主可在
 * 生产者静默后重试 destroy。 */
ftun_status_t ftun_core_run(ftun_core_t *core, const char *config_path);
/* run 阻塞并使当前线程成为 owner；启动失败可修正后重试。
 * stop 可跨线程请求停止，deadline 为单调绝对毫秒；重复调用可缩短期限。 */
ftun_status_t ftun_core_stop(ftun_core_t *core, uint64_t deadline_ms);
/* CREATED/STOPPED 可销毁；deadline 超时后的 STOPPING 可重试回收，生产者仍
 * 未静默时返回 AGAIN 并保留调用者句柄。NULL 对象销毁为幂等成功。 */
ftun_status_t ftun_core_destroy(ftun_core_t **core);

#ifdef __cplusplus
}
#endif
#endif
