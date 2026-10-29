#ifndef FTUN_LIBS_TRANSPORT_NETMON_H
#define FTUN_LIBS_TRANSPORT_NETMON_H
#include "platform/iface.h"
#include "core/event/loop.h"

/* 网络变化事件源：订阅 NETLINK_ROUTE 的链路、IPv4 地址、IPv4 路由和 IPv4 策略
 * 规则四个多播组（规则组让外部删除保护规则也能被察觉），socket 非阻塞，挂在
 * owner 循环上。窗口内的变化合并成“类型位掩码 + 涉及的接口”，窗口结束后由
 * owner 用 take 取走一次。
 *
 * 不做的事：不判断变化是否由本程序自己的路由事务引起。事件只是让消费方提前
 * 检查——恢复调度器的触发和只读核验都是幂等的，不会因为回显形成反馈环；
 * 变化频率仍受 storm 计数监视。 */
#define FTUN_NETMON_DEBOUNCE_MS 500u
/* 判定“反馈环”的窗口与批次上限（候选值）。 */
#define FTUN_NETMON_STORM_WINDOW_MS 60000u
#define FTUN_NETMON_STORM_BATCHES 30u

typedef struct ftun_netmon ftun_netmon_t;

typedef struct {
  uint64_t events;     /* 收到的消息数 */
  uint64_t batches;    /* 交付的合并批次数 */
  uint64_t overflows;  /* 接收缓冲溢出（ENOBUFS）次数 */
  uint64_t storms;     /* 批次频率超限的次数 */
} ftun_netmon_stats_t;

/* 打开订阅并挂到 loop 上。debounce_ms 为 0 取默认值。需要两个事件源额度。 */
ftun_status_t ftun_netmon_create(ftun_event_loop_t *loop, uint64_t debounce_ms,
                                 ftun_netmon_t **out);
ftun_status_t ftun_netmon_destroy(ftun_netmon_t **netmon);
/* 取走已到期的合并变化；没有则 AGAIN。now_ms 用于频率统计。 */
ftun_status_t ftun_netmon_take(ftun_netmon_t *netmon, uint64_t now_ms,
                               ftun_network_change_t *out);
ftun_status_t ftun_netmon_get_stats(const ftun_netmon_t *netmon,
                                    ftun_netmon_stats_t *out);

/* 解析一块 netlink 数据并并入 change；供测试直接使用。返回处理的消息数。 */

#endif
