#ifndef FTUN_PLATFORM_WINDOWS_THREAD_TYPES_H
#define FTUN_PLATFORM_WINDOWS_THREAD_TYPES_H
#include <stdint.h>
/* SRWLOCK/CONDITION_VARIABLE及线程HANDLE的指针宽存储，只由Windows平台操作。 */
typedef struct { uintptr_t native; } ftun_mutex_t;
typedef struct { uintptr_t native; } ftun_condition_t;
typedef struct { uintptr_t native; } ftun_thread_t;
#define FTUN_MUTEX_INITIALIZER {0u}
#endif
