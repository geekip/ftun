#ifndef FTUN_OPERATION_H
#define FTUN_OPERATION_H
#include "ftun/instance.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef void (*ftun_completion_fn)(ftun_operation_t *operation,
                                  ftun_error_t result, void *user);
/* post 可跨线程投递，必须有界；callback 在 owner loop 上执行一次，宿主可
 * 在其中调用 loop-only 接口。成功后 user 保持有效至 callback 返回。
 * out 是借用的操作句柄，仅有效至完成 callback 返回；不得由调用者 free。
 * 同步拒绝不转移 user、不执行 callback、清空 out。 */
ftun_status_t ftun_core_post(ftun_core_t *core, ftun_completion_fn callback, void *user,
                            ftun_operation_t **out);
/* 只在 owner loop 且借用句柄尚有效时调用；取消请求不提前释放上下文，
 * 完成/取消仲裁后仍恰好一次终结回调，已完成句柄不得再次使用。 */
ftun_status_t ftun_operation_cancel(ftun_operation_t *operation);

#ifdef __cplusplus
}
#endif
#endif
