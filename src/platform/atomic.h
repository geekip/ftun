#ifndef FTUN_PLATFORM_ATOMIC_H
#define FTUN_PLATFORM_ATOMIC_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* C99 存储，所有并发访问必须经以下原子原语；不得复制活跃对象或直读 value。
 * 由构建探测编译器原子能力，不假定所有目标的 64 位操作均为无锁。 */
typedef struct { bool value; } ftun_atomic_bool_t;
typedef struct { size_t value; } ftun_atomic_size_t;
typedef struct { uint64_t value; } ftun_atomic_u64_t;
#define FTUN_MEMORY_RELAXED __ATOMIC_RELAXED
#define FTUN_MEMORY_ACQUIRE __ATOMIC_ACQUIRE
#define FTUN_MEMORY_RELEASE __ATOMIC_RELEASE
#define FTUN_MEMORY_ACQ_REL __ATOMIC_ACQ_REL
#define FTUN_MEMORY_SEQ_CST __ATOMIC_SEQ_CST
#define ftun_atomic_init(object, initial) __atomic_store_n(&(object)->value, (initial), FTUN_MEMORY_RELAXED)
#define ftun_atomic_load_explicit(object, order) __atomic_load_n(&(object)->value, (order))
#define ftun_atomic_store_explicit(object, desired, order) __atomic_store_n(&(object)->value, (desired), (order))
#define ftun_atomic_exchange_explicit(object, desired, order) __atomic_exchange_n(&(object)->value, (desired), (order))
#define ftun_atomic_fetch_add_explicit(object, amount, order) __atomic_fetch_add(&(object)->value, (amount), (order))
#define ftun_atomic_fetch_sub_explicit(object, amount, order) __atomic_fetch_sub(&(object)->value, (amount), (order))
#define ftun_atomic_load(object) ftun_atomic_load_explicit((object), FTUN_MEMORY_SEQ_CST)
#define ftun_atomic_store(object, desired) ftun_atomic_store_explicit((object), (desired), FTUN_MEMORY_SEQ_CST)
#define ftun_atomic_exchange(object, desired) ftun_atomic_exchange_explicit((object), (desired), FTUN_MEMORY_SEQ_CST)
#define ftun_atomic_fetch_add(object, amount) ftun_atomic_fetch_add_explicit((object), (amount), FTUN_MEMORY_SEQ_CST)
#define ftun_atomic_compare_exchange_strong(object, expected, desired) \
  __atomic_compare_exchange_n(&(object)->value, (expected), (desired), false, FTUN_MEMORY_SEQ_CST, FTUN_MEMORY_SEQ_CST)
#endif
