#ifndef FTUN_FTUN_H
#define FTUN_FTUN_H
#include <stddef.h>
#include <stdint.h>
#include "ftun/error.h"
#ifdef __cplusplus
extern "C" {
#endif
#define FTUN_VERSION "1.0.3"
#define FTUN_ABI_VERSION 1u
/* REQ-CAPI-001：只公开宿主边界，不暴露 libev/lwIP/TLS 类型。
 * ABI 1 固定 v1.0.2 已发布布局；options 使用 struct_size 接受较短输入。
 * v1.0.1 的旧 info 布局不在兼容范围内，不能替换链接使用本库。 */
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
typedef struct {
  ftun_status_t status;
  uint32_t stage;
  int native_code;
} ftun_error_t;
typedef void (*ftun_completion_fn)(ftun_operation_t *operation,
                                  ftun_error_t result, void *user);
typedef enum {
  FTUN_CORE_CREATED = 1,
  FTUN_CORE_STARTING,
  FTUN_CORE_RUNNING,
  FTUN_CORE_STOPPING,
  FTUN_CORE_STOPPED
} ftun_core_state_t;
typedef enum {
  FTUN_STAGE_NONE = 0,
  FTUN_STAGE_CONFIG_READ,
  FTUN_STAGE_CONFIG_PREPARE,
  FTUN_STAGE_STATE_RESTORE,
  FTUN_STAGE_COMMIT,
  FTUN_STAGE_CONTROL
} ftun_error_stage_t;
/* get_info 没有输出长度参数，此结构不得追加字段或改变布局。
 * 新的内部统计不通过这个公开输出结构写入。 */
typedef struct {
  ftun_core_state_t state;
  uint64_t generation;
  size_t pending_operations;
  uint64_t owner_rounds;
  uint64_t owner_max_busy_ms;
  uint64_t owner_max_deadline_lateness_ms;
  size_t owner_max_work;
  uint64_t owner_quota_exhaustions;
} ftun_core_info_t;
const char *ftun_version(void);
/* create 成功才转移 Core 所有权；失败 *out=NULL，无 fd/线程/回调。 */
ftun_status_t ftun_core_create(const ftun_core_options_t *options, ftun_core_t **out);
/* run 在线程内拥有 loop。正常返回表示完全停止；停止 deadline 到达时返回
 * TIMEOUT 并保留仍被后台调用引用的对象，此后不会再产生用户回调，宿主可在
 * 生产者静默后重试 destroy。 */
ftun_status_t ftun_core_run(ftun_core_t *core, const char *config_path);
/* run 阻塞并使当前线程成为 owner；启动失败可修正后重试。
 * stop 可跨线程请求停止，deadline 为单调绝对毫秒；重复调用可缩短期限。 */
ftun_status_t ftun_core_stop(ftun_core_t *core, uint64_t deadline_ms);
/* post 可跨线程投递，必须有界；callback 在 owner loop 上执行一次，宿主可
 * 在其中调用 loop-only 接口。成功后 user 保持有效至 callback 返回。
 * out 是借用的操作句柄，仅有效至完成 callback 返回；不得由调用者 free。
 * 同步拒绝不转移 user、不执行 callback、清空 out。 */
ftun_status_t ftun_core_post(ftun_core_t *core, ftun_completion_fn callback, void *user,
                            ftun_operation_t **out);
ftun_status_t ftun_core_reload(ftun_core_t *core, const char *config_path,
                              ftun_completion_fn callback, void *user,
                              ftun_operation_t **out);
/* reload/select 在 owner loop 接纳，异步完成；接纳前复制路径/名称。
 * select 仅改变新连接，检查组/成员及配置代次，不迁移已建立 Session。
 * 两者均可跨线程投递，实际变更只在 owner loop 执行。 */
ftun_status_t ftun_core_select(ftun_core_t *core, const char *group_name,
                              const char *member_name,
                              ftun_completion_fn callback, void *user,
                              ftun_operation_t **out);
/* 只在 owner loop 且借用句柄尚有效时调用；取消请求不提前释放上下文，
 * 完成/取消仲裁后仍恰好一次终结回调，已完成句柄不得再次使用。 */
ftun_status_t ftun_operation_cancel(ftun_operation_t *operation);
ftun_status_t ftun_core_get_info(ftun_core_t *core, ftun_core_info_t *out);
/* CREATED/STOPPED 可销毁；deadline 超时后的 STOPPING 可重试回收，生产者仍
 * 未静默时返回 AGAIN 并保留调用者句柄。NULL 对象销毁为幂等成功。 */
ftun_status_t ftun_core_destroy(ftun_core_t **core);
#ifdef __cplusplus
}
#endif
#endif
