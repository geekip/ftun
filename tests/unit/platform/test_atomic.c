#include "platform/atomic.h"
#include "platform/thread.h"
#include <stdio.h>

#define CHECK(x) do { if (!(x)) { \
  fprintf(stderr, "atomic contract failed at %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

static void *increment(void *argument)
{
  ftun_atomic_u64_t *counter = argument;
  size_t index;
  for (index = 0u; index < 10000u; index++) {
    ftun_atomic_fetch_add_explicit(counter, UINT64_C(1), FTUN_MEMORY_RELAXED);
  }
  return NULL;
}
int main(void)
{
  ftun_atomic_u64_t counter;
  ftun_atomic_size_t count;
  ftun_atomic_bool_t pending;
  ftun_thread_t threads[4];
  uint64_t expected;
  size_t index;
  ftun_atomic_init(&counter, UINT64_C(0));
  ftun_atomic_init(&count, 0u);
  ftun_atomic_init(&pending, false);
  CHECK(!ftun_atomic_exchange(&pending, true));
  CHECK(ftun_atomic_load(&pending));
  ftun_atomic_store_explicit(&pending, false, FTUN_MEMORY_RELEASE);
  CHECK(!ftun_atomic_load_explicit(&pending, FTUN_MEMORY_ACQUIRE));
  CHECK(ftun_atomic_fetch_add(&count, 3u) == 0u);
  CHECK(ftun_atomic_fetch_sub_explicit(&count, 1u, FTUN_MEMORY_RELAXED) == 3u);
  CHECK(ftun_atomic_load(&count) == 2u);
  expected = UINT64_C(1);
  CHECK(!ftun_atomic_compare_exchange_strong(&counter, &expected, UINT64_C(9)) && expected == 0u);
  CHECK(ftun_atomic_compare_exchange_strong(&counter, &expected, UINT64_C(9)));
  CHECK(ftun_atomic_load(&counter) == UINT64_C(9));
  ftun_atomic_store(&counter, UINT64_C(0));
  for (index = 0u; index < 4u; index++) CHECK(ftun_thread_create(&threads[index], increment, &counter) == FTUN_OK);
  for (index = 0u; index < 4u; index++) CHECK(ftun_thread_join(&threads[index]) == FTUN_OK);
  CHECK(ftun_atomic_load(&counter) == UINT64_C(40000));
  return 0;
}
