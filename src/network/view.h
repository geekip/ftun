#ifndef FTUN_NETWORK_VIEW_H
#define FTUN_NETWORK_VIEW_H

#include "internal/contracts.h"

#define FTUN_NETWORK_VIEW_MAX_PREFIXES 64u
#define FTUN_NETWORK_VIEW_MAX_ROUTES 64u
#define FTUN_NETWORK_VIEW_MAX_EXCEPTIONS 32u

typedef enum {
  FTUN_DIAL_PURPOSE_BUSINESS = 1,
  FTUN_DIAL_PURPOSE_PROXY,
  FTUN_DIAL_PURPOSE_DNS,
  FTUN_DIAL_PURPOSE_BOOTSTRAP,
  FTUN_DIAL_PURPOSE_PROBE,
  FTUN_DIAL_PURPOSE_FRS_UPDATE,
  FTUN_DIAL_PURPOSE_MESH_CONTROL,
  FTUN_DIAL_PURPOSE_STUN,
  FTUN_DIAL_PURPOSE_RELAY
} ftun_dial_purpose_t;

#define FTUN_DIAL_PURPOSE_BIT(purpose) \
  (UINT32_C(1) << ((uint32_t)(purpose) - UINT32_C(1)))

typedef enum {
  FTUN_DIAL_DOMAIN_AUTO = 0,
  FTUN_DIAL_DOMAIN_UNDERLAY,
  FTUN_DIAL_DOMAIN_OVERLAY
} ftun_dial_domain_t;

typedef struct {
  uint8_t network[4];
  uint8_t prefix_length;
} ftun_network_prefix_t;

typedef struct {
  ftun_network_prefix_t prefix;
  uint32_t purpose_mask;
} ftun_network_route_t;

typedef struct {
  ftun_endpoint_t endpoint;
  uint32_t purpose_mask;
} ftun_network_underlay_exception_t;

typedef struct {
  uint64_t generation;
  const ftun_network_prefix_t *protected_prefixes;
  size_t protected_prefix_count;
  const ftun_network_route_t *overlay_routes;
  size_t overlay_route_count;
  const ftun_network_underlay_exception_t *underlay_exceptions;
  size_t underlay_exception_count;
} ftun_network_view_spec_t;

typedef struct {
  uint64_t generation;
  size_t protected_prefix_count;
  size_t overlay_route_count;
  size_t underlay_exception_count;
  bool revoked;
} ftun_network_view_info_t;

typedef struct {
  ftun_dial_domain_t domain;
  uint64_t generation;
  uint8_t matched_prefix_length;
  bool protected_target;
  bool purpose_exception;
} ftun_network_dial_decision_t;

/* NetworkView 的策略创建后只读；撤销标志只从 false 转为 true。
 * route 必须完整落在 protected prefix 内；同一
 * prefix/exception 不允许重复，避免发布后的优先级依赖输入顺序。 */
ftun_status_t ftun_network_view_create(const ftun_network_view_spec_t *spec,
                                       ftun_network_view_t **out);
ftun_status_t ftun_network_view_retain(ftun_network_view_t *view);
ftun_status_t ftun_network_view_release(ftun_network_view_t **view);
/* 阻止后续路径授权，不改写策略/代次。控制方还须通知各 owner 的 Provider
 * 取消既有通道；原子标志不使 View 引用计数或 Provider 变为跨线程接口。 */
ftun_status_t ftun_network_view_revoke(ftun_network_view_t *view);
ftun_status_t ftun_network_view_get_info(const ftun_network_view_t *view,
                                         ftun_network_view_info_t *out);
ftun_status_t ftun_network_view_get_protected(
  const ftun_network_view_t *view, size_t index, ftun_network_prefix_t *out);
ftun_status_t ftun_network_view_get_route(
  const ftun_network_view_t *view, size_t index, ftun_network_route_t *out);

/* endpoint 必须已由上层从原 allowed 集合中选出。此函数只缩小路径权限：
 * 受保护但不可达或用途未授权时明确拒绝，绝不回落到 Underlay。 */
ftun_status_t ftun_network_view_select_dial(
  const ftun_network_view_t *view, const ftun_endpoint_t *endpoint,
  ftun_dial_purpose_t purpose, ftun_dial_domain_t requested,
  ftun_network_dial_decision_t *out);

#endif
