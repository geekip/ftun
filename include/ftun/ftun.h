#ifndef FTUN_FTUN_H
#define FTUN_FTUN_H
#include <stddef.h>
#include <stdint.h>
#include "ftun/error.h"
#ifdef __cplusplus
extern "C" {
#endif
#define FTUN_VERSION "0.1.0-dev"
#define FTUN_ABI_VERSION 1u
/* REQ-CAPI-001 / TASK-DOC-001：只公开宿主边界，不暴露 libev/lwIP/TLS 类型。
 * 当前为设计接口，0.x 不承诺稳定 ABI；功能未实现时同步拒绝且零回调。 */
typedef struct ftun_core ftun_core_t;
typedef struct ftun_operation ftun_operation_t;
typedef struct {
  size_t struct_size;
  uint32_t abi_version;
  size_t owned_memory_limit;
} ftun_core_options_t;
typedef struct {
  ftun_status_t status;
  uint32_t stage;
  int native_code;
} ftun_error_t;
typedef void (*ftun_completion_fn)(ftun_operation_t *operation,
                                  ftun_error_t result, void *user);
const char *ftun_version(void);
/* create 成功才转移 Core 所有权；失败 *out=NULL，无 fd/线程/回调。 */
ftun_status_t ftun_core_create(const ftun_core_options_t *options, ftun_core_t **out);
/* run 在线程内拥有 loop，阻塞到完全停止；返回后不能仍有用户回调。 */
ftun_status_t ftun_core_run(ftun_core_t *core, const char *config_path);
/* stop 在 owner loop 调用；其他线程应经 post 投递。deadline 为单调绝对毫秒。 */
ftun_status_t ftun_core_stop(ftun_core_t *core, uint64_t deadline_ms);
/* post 可跨线程投递，必须有界；callback 在 owner loop 上执行一次，宿主可
 * 在其中调用 loop-only 接口。成功后 user 保持有效至 callback 返回。
 * out 是借用的操作句柄，仅有效至完成 callback 返回；不得由调用者 free。
 * 当前同步拒绝：不转移 user、不执行 callback、清空 out。 */
ftun_status_t ftun_core_post(ftun_core_t *core, ftun_completion_fn callback, void *user,
                            ftun_operation_t **out);
ftun_status_t ftun_core_reload(ftun_core_t *core, const char *config_path,
                              ftun_completion_fn callback, void *user,
                              ftun_operation_t **out);
/* reload/select 在 owner loop 接纳，异步完成；接纳前复制路径/名称。
 * select 仅改变新连接，检查组/成员及配置代次，不迁移已建立 Session。
 * 跨线程调用者先 post，接纳失败零回调，当前骨架均未实现。 */
ftun_status_t ftun_core_select(ftun_core_t *core, const char *group_name,
                              const char *member_name,
                              ftun_completion_fn callback, void *user,
                              ftun_operation_t **out);
/* 只在 owner loop 且借用句柄尚有效时调用；取消请求不提前释放上下文，
 * 完成/取消仲裁后仍恰好一次终结回调，已完成句柄不得再次使用。 */
ftun_status_t ftun_operation_cancel(ftun_operation_t *operation);
/* 仅 CREATED/STOPPED 可销毁；失败保留调用者句柄。NULL 对象销毁为幂等成功。 */
ftun_status_t ftun_core_destroy(ftun_core_t **core);
#ifdef __cplusplus
}
#endif
#endif
