#ifndef FTUN_CORE_STATUS_H
#define FTUN_CORE_STATUS_H
#include "util/types.h"
#include <string.h>

#define FTUN_STATUS_MAX_ITEMS 64u
#define FTUN_STATUS_LABEL_BYTES 256u

typedef enum {
  FTUN_SERVICE_ACTIVE = 0,
  FTUN_SERVICE_DEGRADED,
  FTUN_SERVICE_WAITING,
  FTUN_SERVICE_NOT_READY,
  FTUN_SERVICE_DISABLED,
  FTUN_SERVICE_FAILED
} ftun_service_state_t;

typedef struct {
  ftun_service_state_t state;
  ftun_status_t reason;
  uint64_t retry_at_ms;
} ftun_service_status_t;

typedef struct {
  char text[FTUN_STATUS_LABEL_BYTES];
  bool truncated;
} ftun_status_label_t;

/* 已校验UTF-8名称复制到拥有型快照；截断保留完整字符并显式标记。 */
static inline void ftun_status_label_set_span(ftun_status_label_t *out, const char *text, size_t length)
{
  size_t count = length;
  if (count >= sizeof(out->text)) {
    count = sizeof(out->text) - 1u;
    while (((unsigned char)text[count] & 0xc0u) == 0x80u) --count;
  }
  memcpy(out->text, text, count);
  out->text[count] = '\0';
  out->truncated = count != length;
}

static inline void ftun_status_label_set(ftun_status_label_t *out, const char *text)
{
  ftun_status_label_set_span(out, text, strlen(text));
}

static inline const char *ftun_service_state_name(ftun_service_state_t state)
{
  static const char *const names[] = {"active", "degraded", "waiting", "not-ready", "disabled", "failed"};
  return names[state];
}
#endif
