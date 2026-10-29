#ifndef FTUN_PLATFORM_PROCESS_H
#define FTUN_PLATFORM_PROCESS_H
#include "util/types.h"
#include "platform/thread.h"
typedef struct { uint32_t signals, blocked; } ftun_signal_mask_t;
typedef struct { uintptr_t native; } ftun_process_alarm_t;
/* 信号集使用平台无关的位；仅表示当前已消费的进程控制信号。 */
#define FTUN_SIGNAL_HANGUP 1u
#define FTUN_SIGNAL_INTERRUPT 2u
#define FTUN_SIGNAL_TERMINATE 4u
#define FTUN_SIGNAL_USER1 8u
ftun_status_t ftun_signals_block(uint32_t signals, ftun_signal_mask_t *previous);
ftun_status_t ftun_signals_restore(const ftun_signal_mask_t *previous);
ftun_status_t ftun_signal_wait(uint32_t signals, uint32_t *received);
ftun_status_t ftun_thread_signal(ftun_thread_t *thread, uint32_t signal);
/* PID 是单个进程，调用方先完成文本与权限范围校验；native_error 用于诊断。 */
ftun_status_t ftun_process_signal(uint32_t pid, uint32_t signal, int *native_error);
uint32_t ftun_process_id(void);
void ftun_process_exit(int code);
/* alarm 成功后由调用方在唯一 owner 上销毁；不安装或更改信号处理函数。 */
ftun_status_t ftun_process_alarm_start(ftun_process_alarm_t *alarm, uint64_t milliseconds);
void ftun_process_alarm_destroy(ftun_process_alarm_t *alarm);
/* 同步发送服务管理器通知；不拥有 state，不分配或执行重试。 */
ftun_status_t ftun_process_notify(const char *state);
/* 为日志提供非零诊断标识素材；不保证密码学随机性，不可用于认证或密钥。
 * 无全局状态，由调用方发布进程级唯一值；不分配资源、不执行回调。 */
uint64_t ftun_process_boot_token(void);
ftun_status_t ftun_platform_boot_identity(void *buffer, size_t capacity, size_t *length);
size_t ftun_platform_descriptor_limit(size_t requested);
ptrdiff_t ftun_process_executable(char *buffer, size_t capacity);
#endif
