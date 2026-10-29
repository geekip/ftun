#ifndef FTUN_PROXY_NETSTACK_ARCH_PERF_H
#define FTUN_PROXY_NETSTACK_ARCH_PERF_H
#define PERF_START
#define PERF_STOP(message) do { (void)sizeof(message); } while (0)
#endif
