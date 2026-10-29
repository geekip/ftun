#ifndef FTUN_PLATFORM_IFACE_H
#define FTUN_PLATFORM_IFACE_H
#include "util/types.h"
/* 成功后交付一个非阻塞 FD，调用方准入并负责关闭；不创建线程或分配堆对象。 */
ftun_status_t ftun_iface_subscribe(int *descriptor);
/* LIMIT 表示内核队列溢出；OK 且零长度表示本次被信号中断；EOF 为连接关闭。 */
ftun_status_t ftun_iface_receive(int descriptor, void *data, size_t capacity, size_t *received);
size_t ftun_netmon_parse(const uint8_t *data, size_t length, ftun_network_change_t *change);
#endif
