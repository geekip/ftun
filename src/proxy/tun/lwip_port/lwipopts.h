#ifndef FTUN_LWIPOPTS_H
#define FTUN_LWIPOPTS_H

#include <stddef.h>

/* FTUN 只从 owner loop 调用 raw API，不编译 lwIP 的线程、socket 或 netconn API。 */
#define NO_SYS 1
#define SYS_LIGHTWEIGHT_PROT 0
#define LWIP_TIMERS 0
#define LWIP_NETCONN 0
#define LWIP_SOCKET 0
#define LWIP_NETIF_API 0
#define LWIP_TCPIP_CORE_LOCKING 0

/* 所有动态对象都经过 FTUN 预算分配器，避免未计账的静态大池。 */
#define MEM_ALIGNMENT 8U
#define MEM_CUSTOM_ALLOCATOR 1
#define MEMP_MEM_MALLOC 1
#define MEM_CUSTOM_MALLOC ftun_lwip_port_malloc
#define MEM_CUSTOM_CALLOC ftun_lwip_port_calloc
#define MEM_CUSTOM_FREE ftun_lwip_port_free
void *ftun_lwip_port_malloc(size_t size);
void *ftun_lwip_port_calloc(size_t count, size_t size);
void ftun_lwip_port_free(void *pointer);

/* v0.2 的 TUN 数据面只接纳 IPv4 TCP/UDP。 */
#define LWIP_IPV4 1
#define LWIP_IPV6 0
#define LWIP_ARP 0
#define LWIP_ETHERNET 0
#define LWIP_RAW 0
#define LWIP_ICMP 0
#define LWIP_IGMP 0
#define LWIP_DHCP 0
#define LWIP_AUTOIP 0
#define LWIP_DNS 0
#define LWIP_TCP 1
/* 每条 TCP 连接的存活探测由 lwip_adapter 在 accept 时按配置打开（SOF_KEEPALIVE）。 */
#define LWIP_TCP_KEEPALIVE 1
#define LWIP_UDP 1

/* MTU 在 netif 上运行时收紧；编译上限保持常见 1500 字节链路的 MSS。 */
#define TCP_MSS 1460
/* 这些内部覆盖只用于固定拓扑对照构建，不形成运行时配置接口。 */
#ifndef FTUN_LWIP_TCP_WINDOW_MSS
#define FTUN_LWIP_TCP_WINDOW_MSS 44
#endif
#ifndef FTUN_LWIP_WINDOW_SCALE
#define FTUN_LWIP_WINDOW_SCALE 0
#endif
#ifndef FTUN_LWIP_TCP_SEND_WINDOW_MSS
#define FTUN_LWIP_TCP_SEND_WINDOW_MSS FTUN_LWIP_TCP_WINDOW_MSS
#endif
#ifndef FTUN_LWIP_RCV_SCALE
#define FTUN_LWIP_RCV_SCALE 0
#endif
#define TCP_WND (FTUN_LWIP_TCP_WINDOW_MSS * TCP_MSS)
#define TCP_SND_BUF (FTUN_LWIP_TCP_SEND_WINDOW_MSS * TCP_MSS)
#define TCP_SND_QUEUELEN (FTUN_LWIP_TCP_SEND_WINDOW_MSS * 4)
#define LWIP_WND_SCALE FTUN_LWIP_WINDOW_SCALE
#define TCP_RCV_SCALE FTUN_LWIP_RCV_SCALE
#define TCP_QUEUE_OOSEQ 1
#define TCP_LISTEN_BACKLOG 1
#define TCP_DEFAULT_LISTEN_BACKLOG 16
#define TCP_OVERSIZE 0
#define LWIP_TCP_TIMESTAMPS 0

/* 分片重组由 adapter 每秒显式推进，池对象仍由统一预算约束。 */
#define IP_FORWARD 0
#define IP_OPTIONS_ALLOWED 0
#define IP_REASSEMBLY 1
#define IP_REASS_MAXAGE 3
#define IP_REASS_MAX_PBUFS 16
#define IP_FRAG 1
#define IP_FRAG_USES_STATIC_BUF 0
#define PBUF_POOL_SIZE 16
#define PBUF_POOL_BUFSIZE 1536

#define LWIP_STATS 0
#define LWIP_CHECKSUM_ON_COPY 1
#define CHECKSUM_GEN_IP 1
#define CHECKSUM_GEN_UDP 1
#define CHECKSUM_GEN_TCP 1
#define CHECKSUM_CHECK_IP 1
#define CHECKSUM_CHECK_UDP 1
#define CHECKSUM_CHECK_TCP 1

#endif
