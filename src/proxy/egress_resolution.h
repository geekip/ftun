#ifndef FTUN_PROXY_EGRESS_RESOLUTION_H
#define FTUN_PROXY_EGRESS_RESOLUTION_H
#include "libs/resolver/basic.h"

typedef struct ftun_proxy_resolution_job ftun_proxy_resolution_job_t;
typedef struct ftun_proxy_resolution ftun_proxy_resolution_t;
typedef void (*ftun_proxy_resolution_completion_fn)(void *user,
  ftun_error_t error, const ftun_endpoint_t *endpoint);
/* 等待者由已准入session内嵌；移除后生产者不再持有它。 */
typedef struct ftun_proxy_resolution_waiter {
  struct ftun_proxy_resolution_waiter *previous, *next;
  ftun_proxy_resolution_job_t *job;
  ftun_proxy_resolution_completion_fn completion;
  void *user;
} ftun_proxy_resolution_waiter_t;
#endif
