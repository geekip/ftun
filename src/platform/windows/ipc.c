#include "platform/ipc.h"

ftun_status_t ftun_ipc_connect(const char *path, uint64_t deadline_ms,
  ftun_handle_t *out)
{
  (void)path; (void)deadline_ms;
  *out = -1;
  return FTUN_E_UNSUPPORTED;
}

/* 当前Windows适配只有进程通知；没有带对端用户鉴权的本机IPC。 */
ftun_status_t ftun_ipc_listen(const char *path, ftun_ipc_listener_t *out)
{
  (void)path;
  *out = (ftun_ipc_listener_t)FTUN_IPC_LISTENER_INVALID;
  return FTUN_E_UNSUPPORTED;
}

ftun_status_t ftun_ipc_listener_close(ftun_ipc_listener_t *listener)
{
  (void)listener;
  return FTUN_OK;
}

ftun_status_t ftun_ipc_peer_allowed(ftun_handle_t socket, bool *allowed, uint64_t *user_id)
{
  (void)socket;
  *allowed = false;
  *user_id = UINT64_MAX;
  return FTUN_E_UNSUPPORTED;
}

ftun_status_t ftun_ipc_listener_discard(ftun_ipc_listener_t *listener)
{
  return ftun_ipc_listener_close(listener);
}
