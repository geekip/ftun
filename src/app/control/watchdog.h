#ifndef FTUN_APP_CONTROL_WATCHDOG_H
#define FTUN_APP_CONTROL_WATCHDOG_H
#include "util/types.h"

/* owner 心跳看门狗与服务管理器通知。
 * 心跳全程无锁：看门狗线程只写原子请求序号并调用 owner 登记的唤醒函数，
 * owner 每轮结束回写确认序号。看门狗既不获取 Core 的锁，也不访问业务对象；
 * 因此 owner 死循环、持锁卡死或诊断输出被堵住，都不影响判定和最终退出。
 * 心跳按 owner 登记，v1.0 只登记一个。 */

#define FTUN_WATCHDOG_MAX_OWNERS 4u
#define FTUN_WATCHDOG_EXIT_CODE 4

typedef struct ftun_watchdog ftun_watchdog_t;

typedef struct {
  /* 必须不阻塞、不取锁；可以丢失（下一次心跳会重试）。 */
  void (*wake)(void *context);
  void *context;
} ftun_watchdog_owner_t;

typedef struct {
  /* 0 表示不判定 owner（仍可向服务管理器发送心跳）。 */
  uint32_t timeout_ms;
  /* 判定后给 owner 的停止期限与宽限；二者之和即最终期限。 */
  uint32_t stop_ms;
  uint32_t grace_ms;
  /* 用 SIGALRM 默认处置作独立的最终期限（产品路径）。 */
  bool arm_alarm;
  /* 看门狗线程在最终期限仍存活时调用；NULL 为 _exit(4)。 */
  void (*terminate)(void *context);
  void *terminate_context;
  /* 诊断输出描述符；<0 不输出。 */
  int diagnostic_fd;
} ftun_watchdog_spec_t;

/* timeout_ms==0 且服务管理器没有要求看门狗时，不创建线程，*out 为 NULL。 */
ftun_status_t ftun_watchdog_create(const ftun_watchdog_spec_t *spec,
                                   ftun_watchdog_t **out);
ftun_status_t ftun_watchdog_register(ftun_watchdog_t *watchdog,
                                     const ftun_watchdog_owner_t *owner,
                                     size_t *slot);
/* owner 每轮结束调用。 */
void ftun_watchdog_ack(ftun_watchdog_t *watchdog, size_t slot);
/* owner 每轮开头检查；true 表示看门狗已判定失去响应，应开始停止。 */
bool ftun_watchdog_stop_requested(const ftun_watchdog_t *watchdog);
/* 进入 RUNNING：通知 READY=1 并开始判定。 */
void ftun_watchdog_ready(ftun_watchdog_t *watchdog);
/* 开始停止：通知 STOPPING=1，不再判定。 */
void ftun_watchdog_stopping(ftun_watchdog_t *watchdog);
bool ftun_watchdog_fired(const ftun_watchdog_t *watchdog);
/* 取消最终期限计时器并回收线程；NULL 安全。 */
ftun_status_t ftun_watchdog_destroy(ftun_watchdog_t **watchdog);

/* 向 NOTIFY_SOCKET 发送一条 sd_notify 消息；未设置该变量时什么也不做。
 * 暴露出来供测试直接验证报文。 */
ftun_status_t ftun_watchdog_notify(const char *state);

#endif
