#ifndef FTUN_PLATFORM_THREAD_H
#define FTUN_PLATFORM_THREAD_H
#include "util/types.h"
#if defined(__unix__) || defined(__APPLE__)
#include "platform/posix/thread_types.h"
#else
#error "Synchronization storage is not implemented for this platform"
#endif

/* 同步对象嵌入调用方已准入的存储，不单独分配；初始化失败不产生拥有资源。
 * lock/unlock/wait 的调用方必须遵守锁所有权，违反原生同步不变量立即终止。
 * destroy 由唯一 owner 在所有使用者退出后调用，允许 NULL，不执行回调。 */
ftun_status_t ftun_mutex_init(ftun_mutex_t *mutex);
void ftun_mutex_destroy(ftun_mutex_t *mutex);
void ftun_mutex_lock(ftun_mutex_t *mutex);
/* 不等待：已持锁返回 false；其他同步不变量错误立即终止。 */
bool ftun_mutex_trylock(ftun_mutex_t *mutex);
void ftun_mutex_unlock(ftun_mutex_t *mutex);
ftun_status_t ftun_condition_init(ftun_condition_t *condition);
void ftun_condition_destroy(ftun_condition_t *condition);
void ftun_condition_signal(ftun_condition_t *condition);
void ftun_condition_broadcast(ftun_condition_t *condition);
void ftun_condition_wait(ftun_condition_t *condition, ftun_mutex_t *mutex);
/* 绝对单调毫秒截止时间；UINT64_MAX 无限等待。返回时仍持有 mutex。
 * 唤醒后调用方仍需在锁内检查自己的谓词，超时不表示异步任务已经退出。 */
ftun_status_t ftun_condition_wait_until(ftun_condition_t *condition,
  ftun_mutex_t *mutex, uint64_t deadline_ms);
/* 成功后 thread 拥有 join 责任，argument 借用至 entry 返回；不复制参数。
 * join 成功后资源已回收；由唯一 owner 调用，不可在对应线程内 join。 */
ftun_status_t ftun_thread_create(ftun_thread_t *thread,
  void *(*entry)(void *), void *argument);
ftun_status_t ftun_thread_join(ftun_thread_t *thread);
/* 成功后转交原生线程回收责任；调用方仍负责保持 entry 的参数存活。 */
ftun_status_t ftun_thread_detach(ftun_thread_t *thread);
/* 短暂让出 CPU；信号可提前唤醒，不重新睡眠。 */
void ftun_thread_pause(uint32_t milliseconds);
void ftun_thread_yield(void);
/* 只阻塞当前 writer 线程的 SIGPIPE，不改变进程的信号处置。 */
ftun_status_t ftun_thread_block_sigpipe(void);
#endif
