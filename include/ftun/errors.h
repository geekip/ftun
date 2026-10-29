#ifndef FTUN_ERRORS_H
#define FTUN_ERRORS_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef enum {
  FTUN_OK = 0, FTUN_E_INVALID, FTUN_E_NOT_IMPLEMENTED, FTUN_E_UNSUPPORTED,
  FTUN_E_AGAIN, FTUN_E_EOF, FTUN_E_CANCELLED, FTUN_E_TIMEOUT,
  FTUN_E_LIMIT, FTUN_E_IO, FTUN_E_RESOLVE, FTUN_E_REJECTED,
  FTUN_E_PROTOCOL, FTUN_E_RESTART_REQUIRED, FTUN_E_STALE,
  FTUN_E_STATE_CORRUPT
} ftun_status_t;
const char *ftun_status_name(ftun_status_t status);
typedef struct {
  ftun_status_t status;
  uint32_t stage;
  int native_code;
} ftun_error_t;
typedef enum {
  FTUN_STAGE_NONE = 0,
  FTUN_STAGE_CONFIG_READ,
  FTUN_STAGE_CONFIG_PREPARE,
  FTUN_STAGE_STATE_RESTORE,
  FTUN_STAGE_COMMIT,
  FTUN_STAGE_CONTROL
} ftun_error_stage_t;
#ifdef __cplusplus
}
#endif
#endif
