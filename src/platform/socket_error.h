#ifndef FTUN_PLATFORM_SOCKET_ERROR_H
#define FTUN_PLATFORM_SOCKET_ERROR_H

/* 监听 accept 失败的处置分类。平台 errno 只在这里解释，入站监听只按分类
 * 决定重试、跳过、退避或上报，不各自维护错误码白名单。 */
typedef enum {
  FTUN_SOCKET_ACCEPT_RETRY = 1, /* 被信号打断，立即重试。 */
  FTUN_SOCKET_ACCEPT_DRAINED,   /* 当前没有待接纳连接。 */
  FTUN_SOCKET_ACCEPT_SKIP,      /* 单个待接纳连接失败，监听本身仍可用。 */
  FTUN_SOCKET_ACCEPT_BACKOFF,   /* 资源暂缺或未知错误：有界退避后再接纳。 */
  FTUN_SOCKET_ACCEPT_FATAL      /* 监听句柄本身无效，由调用方按故障域处理。 */
} ftun_socket_accept_disposition_t;

ftun_socket_accept_disposition_t ftun_socket_accept_classify(int error_code);

#endif
