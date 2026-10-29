#ifndef FTUN_PLATFORM_LINUX_ROUTE_H
#define FTUN_PLATFORM_LINUX_ROUTE_H
#include "platform/route.h"
#define FTUN_ROUTE_FAMILY_IPV4 2
#define FTUN_ROUTE_FAMILY_IPV6 10
#define FTUN_ROUTE_TABLE_UNSPEC 0u
#define FTUN_ROUTE_TABLE_DEFAULT 253u
#define FTUN_ROUTE_TABLE_MAIN 254u
#define FTUN_ROUTE_TABLE_LOCAL 255u
#define FTUN_LINUX_ROUTE_NAME_BYTES 16u
#define FTUN_LINUX_ROUTE_MAX_RESOURCES 7u
#define FTUN_LINUX_ROUTE_PLAN_MAX_RESOURCES 128u
#define FTUN_LINUX_ROUTE_PROTOCOL 186u
/* 单个资源最多清理的遗留对象数，防止无界循环。 */
#define FTUN_LINUX_ROUTE_SWEEP_LIMIT 16u

typedef enum {
  FTUN_LINUX_ROUTE_ADDRESS = 1,
  FTUN_LINUX_ROUTE_MARK_RULE,
  FTUN_LINUX_ROUTE_DEFAULT,
  FTUN_LINUX_ROUTE_CAPTURE_RULE,
  FTUN_LINUX_ROUTE_BLOCK_IPV6,
  FTUN_LINUX_ROUTE_PROTECT_RULE,
  FTUN_LINUX_ROUTE_OVERLAY,
  FTUN_LINUX_ROUTE_UNREACHABLE
} ftun_route_resource_kind_t;

typedef struct {
  ftun_route_resource_kind_t kind;
  int family;
  char interface_name[FTUN_LINUX_ROUTE_NAME_BYTES];
  uint8_t address[16];
  uint8_t prefix_length;
  uint32_t table;
  uint32_t priority;
  uint32_t mark;
  uint32_t mark_mask;
  uint32_t metric;
  uint8_t protocol;
  /* 仅用于删除请求：放宽选择子，只按家族、优先级（路由为表与前缀）与协议号
   * 清理上次崩溃遗留的过期对象；不属于计划资源，不进入账本。 */
  bool stray;
} ftun_route_resource_t;

struct ftun_route_plan {
  ftun_route_resource_t resources[FTUN_LINUX_ROUTE_PLAN_MAX_RESOURCES];
  size_t resource_count;
  /* 安装前先按放宽的选择子清理同表同优先级的协议号 186 遗留对象。仅在持有
   * 路由表互斥锁（策略事务）时启用，不能用于与其他管理者共享的计划。 */
  bool sweep;
};

struct ftun_route_io {
  ftun_status_t (*apply)(void *context,
                         const ftun_route_resource_t *resource);
  ftun_status_t (*remove)(void *context,
                          const ftun_route_resource_t *resource);
  void *context;
};

typedef enum {
  FTUN_LINUX_ROUTE_REQUEST_QUERY = 1,
  FTUN_LINUX_ROUTE_REQUEST_ADD,
  FTUN_LINUX_ROUTE_REQUEST_REMOVE
} ftun_route_request_kind_t;

typedef struct {
  uint32_t sequence;
  ftun_route_request_kind_t kind;
  ftun_route_resource_t resource;
} ftun_route_request_t;

typedef struct {
  uint32_t sequence;
  ftun_status_t status;
  bool present;
} ftun_route_reply_t;

struct ftun_route_async_io {
  /* submit/receive 均不得阻塞；AGAIN 表示等待下一次 readiness。 */
  ftun_status_t (*submit)(void *context,
                          const ftun_route_request_t *request);
  ftun_status_t (*receive)(void *context, ftun_route_reply_t *reply);
  void *context;
};

/* 原生 Netlink 协议状态嵌入调用方准入的对象，不含事件循环或预算指针。 */
typedef struct {
  int descriptor;
  uint32_t pending_sequence;
  ftun_route_request_kind_t pending_kind;
  ftun_route_resource_t query_resource;
  bool query_present, io_ready, io_error, runnable, write_interest;
} ftun_route_kernel_t;
const ftun_route_io_t *ftun_platform_route_io(void);
ftun_status_t ftun_route_lock_table(uint32_t table, ftun_handle_t *out);
ftun_status_t ftun_platform_route_open(ftun_handle_t *out);
ftun_status_t ftun_platform_route_close(ftun_handle_t descriptor);
ftun_status_t ftun_platform_route_submit(ftun_route_kernel_t *operation,
  const ftun_route_request_t *request);
ftun_status_t ftun_platform_route_receive(ftun_route_kernel_t *operation,
  ftun_route_reply_t *reply);
#endif
