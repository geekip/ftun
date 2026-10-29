#ifndef FTUN_PLATFORM_RANDOM_H
#define FTUN_PLATFORM_RANDOM_H
#include "util/types.h"
/* 同步填满调用方缓冲；失败不交付随机密钥，不转用弱随机。 */
ftun_status_t ftun_random_bytes(void *buffer, size_t length);
/* 调用方已准入一个 FD；同步读取系统强随机设备，失败不使用弱随机。 */
ftun_status_t ftun_random_device_bytes(void *buffer, size_t length);
#endif
