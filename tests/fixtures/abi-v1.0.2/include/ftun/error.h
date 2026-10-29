#ifndef FTUN_ERROR_H
#define FTUN_ERROR_H
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
#ifdef __cplusplus
}
#endif
#endif
