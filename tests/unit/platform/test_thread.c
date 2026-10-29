#define _POSIX_C_SOURCE 200809L
#include "platform/thread.h"
#include "platform/clock.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "thread contract failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

static int failure, attribute_destroys;
int __real_pthread_condattr_init(pthread_condattr_t *attributes);
int __real_pthread_condattr_setclock(pthread_condattr_t *attributes, clockid_t clock);
int __real_pthread_condattr_destroy(pthread_condattr_t *attributes);
int __real_pthread_cond_init(pthread_cond_t *condition, const pthread_condattr_t *attributes);
int __real_pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
  void *(*entry)(void *), void *argument);
int __real_pthread_detach(pthread_t thread);
int __wrap_pthread_condattr_init(pthread_condattr_t *attributes)
{
  return failure == 1 ? ENOMEM : __real_pthread_condattr_init(attributes);
}
int __wrap_pthread_condattr_setclock(pthread_condattr_t *attributes, clockid_t clock)
{
  return failure == 2 ? EINVAL : __real_pthread_condattr_setclock(attributes, clock);
}
int __wrap_pthread_condattr_destroy(pthread_condattr_t *attributes)
{
  attribute_destroys++;
  return __real_pthread_condattr_destroy(attributes);
}
int __wrap_pthread_cond_init(pthread_cond_t *condition, const pthread_condattr_t *attributes)
{
  clockid_t clock;
  if (failure == 3) return ENOMEM;
  if (pthread_condattr_getclock(attributes, &clock) != 0 || clock != CLOCK_MONOTONIC) return EINVAL;
  return __real_pthread_cond_init(condition, attributes);
}
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
  void *(*entry)(void *), void *argument)
{
  return failure == 4 ? EAGAIN : __real_pthread_create(thread, attributes, entry, argument);
}
int __wrap_pthread_detach(pthread_t thread)
{
  return failure == 5 ? EINVAL : __real_pthread_detach(thread);
}

typedef struct {
  ftun_mutex_t mutex;
  ftun_condition_t condition;
  unsigned int state;
} shared_t;
static void *peer(void *argument)
{
  shared_t *shared = argument;
  ftun_mutex_lock(&shared->mutex);
  shared->state = 1u;
  ftun_condition_signal(&shared->condition);
  while (shared->state != 2u) ftun_condition_wait(&shared->condition, &shared->mutex);
  shared->state = 3u;
  ftun_condition_broadcast(&shared->condition);
  ftun_mutex_unlock(&shared->mutex);
  return NULL;
}
int main(void)
{
  ftun_mutex_t static_mutex = FTUN_MUTEX_INITIALIZER;
  ftun_condition_t condition;
  ftun_thread_t thread;
  shared_t shared;
  uint64_t now, deadline;
  sigset_t before, after;
  ftun_status_t status;
  unsigned int detached;
  for (failure = 1; failure <= 3; failure++) {
    attribute_destroys = 0;
    CHECK(ftun_condition_init(&condition) == FTUN_E_IO);
    CHECK(attribute_destroys == (failure == 1 ? 0 : 1));
  }
  CHECK(ftun_thread_create(&thread, peer, NULL) == FTUN_E_IO);
  failure = 0;
  ftun_mutex_lock(&static_mutex);
  CHECK(!ftun_mutex_trylock(&static_mutex));
  ftun_mutex_unlock(&static_mutex);
  CHECK(ftun_mutex_trylock(&static_mutex));
  ftun_mutex_unlock(&static_mutex);
  ftun_mutex_destroy(&static_mutex);
  CHECK(ftun_mutex_init(&shared.mutex) == FTUN_OK);
  CHECK(ftun_condition_init(&shared.condition) == FTUN_OK);
  for (detached = 0u; detached <= 1u; detached++) {
    shared.state = 0u;
    ftun_mutex_lock(&shared.mutex);
    CHECK(ftun_monotonic_now(&now) == FTUN_OK);
    /* 绝对的过去时刻立即超时，仍持锁且不改变谓词。 */
    CHECK(ftun_condition_wait_until(&shared.condition, &shared.mutex, now) == FTUN_E_TIMEOUT);
    CHECK(shared.state == 0u);
    CHECK(ftun_thread_create(&thread, peer, &shared) == FTUN_OK);
    if (detached != 0u) {
      CHECK(ftun_thread_detach(&thread) == FTUN_OK);
    } else {
      failure = 5;
      CHECK(ftun_thread_detach(&thread) == FTUN_E_IO);
      failure = 0;
    }
    deadline = now + 2000u;
    do {
      status = ftun_condition_wait_until(&shared.condition, &shared.mutex, deadline);
      CHECK(status == FTUN_OK);
    } while (shared.state != 1u);
    shared.state = 2u;
    ftun_condition_broadcast(&shared.condition);
    while (shared.state != 3u) {
      CHECK(ftun_condition_wait_until(&shared.condition, &shared.mutex, UINT64_MAX) == FTUN_OK);
    }
    ftun_mutex_unlock(&shared.mutex);
    if (detached == 0u) CHECK(ftun_thread_join(&thread) == FTUN_OK);
  }
  ftun_condition_destroy(&shared.condition);
  ftun_mutex_destroy(&shared.mutex);
  ftun_condition_destroy(NULL);
  ftun_mutex_destroy(NULL);
  CHECK(pthread_sigmask(SIG_SETMASK, NULL, &before) == 0);
  CHECK(ftun_thread_block_sigpipe() == FTUN_OK);
  CHECK(pthread_sigmask(SIG_SETMASK, NULL, &after) == 0 && sigismember(&after, SIGPIPE) == 1);
  CHECK(pthread_sigmask(SIG_SETMASK, &before, NULL) == 0);
  return 0;
}
