#ifndef FTUN_PLATFORM_POSIX_THREAD_TYPES_H
#define FTUN_PLATFORM_POSIX_THREAD_TYPES_H
#include <pthread.h>

/* 原生存储只由平台实现操作；已初始化的同步对象不可复制。 */
typedef struct { pthread_mutex_t native; } ftun_mutex_t;
typedef struct { pthread_cond_t native; } ftun_condition_t;
typedef struct { pthread_t native; } ftun_thread_t;
#define FTUN_MUTEX_INITIALIZER {PTHREAD_MUTEX_INITIALIZER}
#endif
