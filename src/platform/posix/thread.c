#define _POSIX_C_SOURCE 200809L
#include "platform/thread.h"
#include <sched.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>

static void require_success(int result)
{
  if (result != 0) abort();
}

ftun_status_t ftun_mutex_init(ftun_mutex_t *mutex)
{
  return pthread_mutex_init(&mutex->native, NULL) == 0 ? FTUN_OK : FTUN_E_IO;
}
void ftun_mutex_destroy(ftun_mutex_t *mutex)
{
  if (mutex != NULL) require_success(pthread_mutex_destroy(&mutex->native));
}
void ftun_mutex_lock(ftun_mutex_t *mutex)
{
  require_success(pthread_mutex_lock(&mutex->native));
}
void ftun_mutex_unlock(ftun_mutex_t *mutex)
{
  require_success(pthread_mutex_unlock(&mutex->native));
}
bool ftun_mutex_trylock(ftun_mutex_t *mutex)
{
  int result = pthread_mutex_trylock(&mutex->native);
  if (result == EBUSY) return false;
  require_success(result);
  return true;
}

ftun_status_t ftun_condition_init(ftun_condition_t *condition)
{
  pthread_condattr_t attributes;
  int result = pthread_condattr_init(&attributes);
  if (result != 0) return FTUN_E_IO;
  result = pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC);
  if (result == 0) result = pthread_cond_init(&condition->native, &attributes);
  require_success(pthread_condattr_destroy(&attributes));
  return result == 0 ? FTUN_OK : FTUN_E_IO;
}
void ftun_condition_destroy(ftun_condition_t *condition)
{
  if (condition != NULL) require_success(pthread_cond_destroy(&condition->native));
}
void ftun_condition_signal(ftun_condition_t *condition)
{
  require_success(pthread_cond_signal(&condition->native));
}
void ftun_condition_broadcast(ftun_condition_t *condition)
{
  require_success(pthread_cond_broadcast(&condition->native));
}
void ftun_condition_wait(ftun_condition_t *condition, ftun_mutex_t *mutex)
{
  require_success(pthread_cond_wait(&condition->native, &mutex->native));
}
ftun_status_t ftun_condition_wait_until(ftun_condition_t *condition,
  ftun_mutex_t *mutex, uint64_t deadline_ms)
{
  struct timespec deadline;
  uint64_t seconds;
  int result;
  if (deadline_ms == UINT64_MAX) {
    ftun_condition_wait(condition, mutex);
    return FTUN_OK;
  }
  seconds = deadline_ms / UINT64_C(1000);
  deadline.tv_sec = (time_t)seconds;
  if ((uint64_t)deadline.tv_sec != seconds) return FTUN_E_LIMIT;
  deadline.tv_nsec = (long)((deadline_ms % UINT64_C(1000)) * UINT64_C(1000000));
  result = pthread_cond_timedwait(&condition->native, &mutex->native, &deadline);
  if (result == ETIMEDOUT) return FTUN_E_TIMEOUT;
  return result == 0 ? FTUN_OK : FTUN_E_IO;
}

ftun_status_t ftun_thread_create(ftun_thread_t *thread,
  void *(*entry)(void *), void *argument)
{
  return pthread_create(&thread->native, NULL, entry, argument) == 0 ? FTUN_OK : FTUN_E_IO;
}
ftun_status_t ftun_thread_join(ftun_thread_t *thread)
{
  return pthread_join(thread->native, NULL) == 0 ? FTUN_OK : FTUN_E_IO;
}
ftun_status_t ftun_thread_detach(ftun_thread_t *thread)
{
  return pthread_detach(thread->native) == 0 ? FTUN_OK : FTUN_E_IO;
}
void ftun_thread_pause(uint32_t milliseconds)
{
  struct timespec pause;
  pause.tv_sec = (time_t)(milliseconds / 1000u);
  pause.tv_nsec = (long)(milliseconds % 1000u) * 1000000L;
  if (nanosleep(&pause, NULL) != 0 && errno != EINTR) abort();
}
ftun_status_t ftun_thread_block_sigpipe(void)
{
  sigset_t blocked;
  (void)sigemptyset(&blocked);
  (void)sigaddset(&blocked, SIGPIPE);
  return pthread_sigmask(SIG_BLOCK, &blocked, NULL) == 0 ? FTUN_OK : FTUN_E_IO;
}

void ftun_thread_yield(void)
{
  (void)sched_yield();
}
