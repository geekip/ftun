#ifndef FTUN_TRANSPORT_SOCKET_PATH_H
#define FTUN_TRANSPORT_SOCKET_PATH_H

#include "transport/path.h"

/* IPv4 直接通道工厂；仅物理 dialer 打开/保护/connect socket。
 * 一个通道至多保留一个后端发送；Stream 接纳整个有界 slice，按实际发送
 * 进度完成，Datagram 仅允许向已授权 peer 整包发送。发送由一个预留的
 * owner 任务源推进，Stream 每次最多发送 64KiB，只有 AGAIN 才订阅 WRITE；
 * stop 撤销尚未派发的任务。接收每轮至多 16 包。
 * Datagram receive 返回 AGAIN/LIMIT 时保留一包并暂停，调用 Path resume
 * 继续；资源不足也暂停并通过 notify 报告。Stream READABLE 通知后暂停
 * 读事件，实际 read 或 Path resume 重新订阅。全部状态归同一 owner。
 * options 的空 budget/operations 使用 dial 输入，容量与回调须显式提供。 */
ftun_status_t ftun_socket_path_open(void *context, ftun_core_t *core,
  const ftun_path_open_request_t *request, const ftun_path_spec_t *spec,
  ftun_operation_t **out);

#endif
