#ifndef FTUN_PLATFORM_SYSTEM_RESOLVER_H
#define FTUN_PLATFORM_SYSTEM_RESOLVER_H

#include "core/worker.h"
#include "network/socket_policy.h"

#define FTUN_SYSTEM_RESOLVER_MAX_DOMAIN_BYTES 254u
#define FTUN_SYSTEM_RESOLVER_MAX_IPV4_RESULTS 16u

#define FTUN_SYSTEM_RESOLVER_STAGE_ADMISSION 1u
#define FTUN_SYSTEM_RESOLVER_STAGE_PATH 2u
#define FTUN_SYSTEM_RESOLVER_STAGE_QUERY 3u
#define FTUN_SYSTEM_RESOLVER_STAGE_RESULT 4u
#define FTUN_SYSTEM_RESOLVER_STAGE_DEADLINE 5u

typedef struct {
  ftun_string_t domain;
  const ftun_endpoint_t *addresses;
  size_t address_count;
} ftun_system_resolve_result_t;

typedef void (*ftun_system_resolve_completion_fn)(
  ftun_operation_t *operation, ftun_error_t error,
  const ftun_system_resolve_result_t *result, void *user);

/* 检查 libc/NSS 隐藏 socket 的实际路径已由路由隔离、专用身份或等效机制
 * 排除在 FTUN 捕获路径外。只看到非零 mark 不能返回成功。 */
typedef ftun_status_t (*ftun_system_resolver_path_check_fn)(
  void *user, const ftun_socket_policy_t *protection);

typedef struct {
  ftun_worker_t *worker;
  ftun_budget_t *budget;
  ftun_string_t domain;
  ftun_socket_policy_t protection;
  uint64_t deadline_ms;
  ftun_system_resolver_path_check_fn check_path;
  void *path_user;
  ftun_system_resolve_completion_fn completion;
  void *user;
} ftun_system_resolve_request_t;

/* 系统解析适配。
 * libc/NSS 调用只在有界 Worker 上执行，结果由 worker_poll 回到 owner loop。
 * 域名在接纳前复制；成功结果同步借给 completion，最多保留 16 个有序去重
 * IPv4 地址。取消只逻辑终结，无法中断的 libc 调用仍由 Worker 排空。
 * check_path 是强制门禁，调用方必须在 Worker 生命周期内维持所验证的
 * 物理路径隔离；不得把隐藏 socket 假定为自动继承 protection.mark。
 */
ftun_status_t ftun_system_resolve(
  ftun_core_t *core, const ftun_system_resolve_request_t *request,
  ftun_operation_t **out);

/* 测试与受控平台适配入口；execute 在 Worker 线程调用且不得访问 Session。 */
ftun_status_t ftun_system_resolve_with_execute(
  ftun_core_t *core, const ftun_system_resolve_request_t *request,
  ftun_worker_execute_fn execute, ftun_operation_t **out);

#endif
