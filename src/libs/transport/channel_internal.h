#ifndef FTUN_LIBS_TRANSPORT_CHANNEL_INTERNAL_H
#define FTUN_LIBS_TRANSPORT_CHANNEL_INTERNAL_H
#include "libs/transport/channel.h"
/* 仅唯一拥有者使用；零值表示空通道。成功 adopt 消费输入，失败完全保留。
 * 嵌入存储随 owner 准入；destroy 不释放 owner，失败保留可继续清理的句柄。 */
struct ftun_channel {
  ftun_dial_transport_t transport;
  union {
    ftun_stream_t *stream;
    ftun_datagram_t *datagram;
  } data;
};
ftun_status_t ftun_channel_adopt_stream(ftun_channel_t *out, ftun_stream_t **stream);
ftun_status_t ftun_channel_adopt_datagram(ftun_channel_t *out, ftun_datagram_t **datagram);
ftun_status_t ftun_channel_budget(ftun_channel_t *channel, ftun_budget_t **out);
ftun_status_t ftun_channel_destroy(ftun_channel_t *channel);
#endif
