#ifndef FTUN_PLATFORM_LINUX_ROUTE_H
#define FTUN_PLATFORM_LINUX_ROUTE_H
#include "internal/contracts.h"

#define FTUN_LINUX_ROUTE_NAME_BYTES 16u
#define FTUN_LINUX_ROUTE_MAX_RESOURCES 7u
#define FTUN_LINUX_ROUTE_PROTOCOL 186u

typedef enum {
  FTUN_LINUX_ROUTE_ADDRESS = 1,
  FTUN_LINUX_ROUTE_MARK_RULE,
  FTUN_LINUX_ROUTE_DEFAULT,
  FTUN_LINUX_ROUTE_CAPTURE_RULE,
  FTUN_LINUX_ROUTE_BLOCK_IPV6
} ftun_linux_route_resource_kind_t;

typedef struct {
  ftun_linux_route_resource_kind_t kind;
  int family;
  char interface_name[FTUN_LINUX_ROUTE_NAME_BYTES];
  uint8_t address[16];
  uint8_t prefix_length;
  uint32_t table;
  uint32_t priority;
  uint32_t mark;
  uint32_t mark_mask;
  uint8_t protocol;
} ftun_linux_route_resource_t;

typedef struct {
  ftun_status_t (*apply)(void *context,
                         const ftun_linux_route_resource_t *resource);
  ftun_status_t (*remove)(void *context,
                          const ftun_linux_route_resource_t *resource);
  void *context;
} ftun_linux_route_io_t;

struct ftun_route_policy {
  ftun_string_t tun_interface;
  uint8_t tun_ipv4[4];
  uint8_t tun_prefix_length;
  uint32_t route_table;
  uint32_t rule_priority;
  uint32_t protection_mark;
  uint32_t protection_mark_mask;
  bool manage_local;
  ftun_string_t lan_interface;
  bool strict_route;
};

typedef struct {
  size_t resource_count;
  size_t active_count;
  bool strict_route;
} ftun_linux_route_info_t;

/* Linux 路由资源事务。
 * 需求 REQ-GUARD-001；任务 TASK-PLATFORM-002；目标 0.2.0；验收 TEST-PLATFORM-002。
 * 实现路径：记录实例所有权；保护与 TUN 路由按序准备；冲突拒绝、失败反序撤销；本机/LAN 分别验收，退出不改他人规则。
 * 调用边界见 document/ftun.modules.md；不访问配置 AST，不跨线程修改 Session。
 * policy 仅在调用期间借用，成功 transaction 拥有已安装资源记录。
 * 本机范围使用 iif lo，LAN 范围必须显式提供接口；strict-route 只阻断同一范围 IPv6。
 * 冲突返回 rejected；普通失败完成逆序回滚并清空输出。
 * 若回滚本身失败则返回 state-corrupt 并交付 transaction，调用者必须重试 release。
 */
ftun_status_t ftun_linux_route_prepare(const ftun_route_policy_t *policy, ftun_route_transaction_t **out);
/* 测试与受控宿主注入；操作表会复制，context 必须比 transaction 长寿。 */
ftun_status_t ftun_linux_route_prepare_with_io(const ftun_route_policy_t *policy,
                                               const ftun_linux_route_io_t *io,
                                               ftun_route_transaction_t **out);
ftun_status_t ftun_linux_route_get_info(const ftun_route_transaction_t *transaction,
                                        ftun_linux_route_info_t *out);
/* 逆序删除仍活动的自有资源；部分失败保留句柄和失败项供重试。 */
ftun_status_t ftun_linux_route_release(ftun_route_transaction_t **transaction);
#endif
