#include "platform/thread.h"
#include "platform/clock.h"
#include <windows.h>
#include <stdlib.h>

typedef char mutex_fits[(sizeof(SRWLOCK) == sizeof(ftun_mutex_t)) ? 1 : -1];
typedef char condition_fits[(sizeof(CONDITION_VARIABLE) == sizeof(ftun_condition_t)) ? 1 : -1];
ftun_status_t ftun_mutex_init(ftun_mutex_t *mutex)
{
  InitializeSRWLock((PSRWLOCK)mutex);
  return FTUN_OK;
}
void ftun_mutex_destroy(ftun_mutex_t *mutex) { (void)mutex; }
void ftun_mutex_lock(ftun_mutex_t *mutex) { AcquireSRWLockExclusive((PSRWLOCK)mutex); }
void ftun_mutex_unlock(ftun_mutex_t *mutex) { ReleaseSRWLockExclusive((PSRWLOCK)mutex); }
bool ftun_mutex_trylock(ftun_mutex_t *mutex) { return TryAcquireSRWLockExclusive((PSRWLOCK)mutex) != 0; }
ftun_status_t ftun_condition_init(ftun_condition_t *condition)
{
  InitializeConditionVariable((PCONDITION_VARIABLE)condition);
  return FTUN_OK;
}
void ftun_condition_destroy(ftun_condition_t *condition) { (void)condition; }
void ftun_condition_signal(ftun_condition_t *condition) { WakeConditionVariable((PCONDITION_VARIABLE)condition); }
void ftun_condition_broadcast(ftun_condition_t *condition) { WakeAllConditionVariable((PCONDITION_VARIABLE)condition); }
void ftun_condition_wait(ftun_condition_t *condition, ftun_mutex_t *mutex)
{
  if (!SleepConditionVariableSRW((PCONDITION_VARIABLE)condition, (PSRWLOCK)mutex, INFINITE, 0u)) abort();
}
ftun_status_t ftun_condition_wait_until(ftun_condition_t *condition,
  ftun_mutex_t *mutex, uint64_t deadline_ms)
{
  if (deadline_ms == UINT64_MAX) { ftun_condition_wait(condition, mutex); return FTUN_OK; }
  for (;;) {
    uint64_t now = GetTickCount64();
    if (now >= deadline_ms) return FTUN_E_TIMEOUT;
    uint64_t left = deadline_ms - now;
    DWORD timeout = left >= INFINITE ? INFINITE - 1u : (DWORD)left;
    if (SleepConditionVariableSRW((PCONDITION_VARIABLE)condition, (PSRWLOCK)mutex, timeout, 0u)) return FTUN_OK;
    if (GetLastError() != ERROR_TIMEOUT) return FTUN_E_IO;
    /* 原生等待只有32位毫秒，超长期限分段等待，每段重新检查同一绝对期限。 */
  }
}
typedef struct { void *(*entry)(void *); void *argument; HANDLE ready; } thread_start_t;
static DWORD WINAPI thread_entry(void *argument)
{
  thread_start_t start = *(thread_start_t *)argument;
  if (!SetEvent(start.ready)) abort();
  (void)start.entry(start.argument);
  return 0u;
}
ftun_status_t ftun_thread_create(ftun_thread_t *thread, void *(*entry)(void *), void *argument)
{
  thread_start_t start = {entry, argument, CreateEventW(NULL, FALSE, FALSE, NULL)};
  if (start.ready == NULL) return FTUN_E_LIMIT;
  HANDLE native = CreateThread(NULL, 0u, thread_entry, &start, 0u, NULL);
  if (native == NULL) { CloseHandle(start.ready); return FTUN_E_LIMIT; }
  /* 只等启动参数被复制；不等业务入口，detach后原thread存储可立即归还。 */
  if (WaitForSingleObject(start.ready, INFINITE) != WAIT_OBJECT_0) abort();
  CloseHandle(start.ready);
  thread->native = (uintptr_t)native;
  return FTUN_OK;
}
ftun_status_t ftun_thread_join(ftun_thread_t *thread)
{
  if (WaitForSingleObject((HANDLE)thread->native, INFINITE) != WAIT_OBJECT_0) return FTUN_E_IO;
  if (!CloseHandle((HANDLE)thread->native)) return FTUN_E_IO;
  thread->native = 0u;
  return FTUN_OK;
}
ftun_status_t ftun_thread_detach(ftun_thread_t *thread)
{
  if (!CloseHandle((HANDLE)thread->native)) return FTUN_E_IO;
  thread->native = 0u;
  return FTUN_OK;
}
void ftun_thread_pause(uint32_t milliseconds) { Sleep(milliseconds); }
void ftun_thread_yield(void) { (void)SwitchToThread(); }
ftun_status_t ftun_thread_block_sigpipe(void) { return FTUN_OK; }
