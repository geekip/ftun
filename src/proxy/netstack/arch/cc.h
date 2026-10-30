#ifndef FTUN_PROXY_NETSTACK_ARCH_CC_H
#define FTUN_PROXY_NETSTACK_ARCH_CC_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BYTE_ORDER BIG_ENDIAN
#else
#define BYTE_ORDER LITTLE_ENDIAN
#endif

typedef unsigned int sys_prot_t;

/* 协议栈不变量失败立即终止；协议输入错误必须走正常返回路径。 */
#define LWIP_PLATFORM_DIAG(arguments) do { } while (0)
#define LWIP_PLATFORM_ASSERT(message) do { \
  (void)fprintf(stderr, "lwIP assertion: %s\n", (message)); \
  abort(); \
} while (0)

unsigned int ftun_lwip_port_rand(void);
#define LWIP_RAND() ftun_lwip_port_rand()

#endif
