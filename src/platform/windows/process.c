#include "platform/process.h"
#include "platform/random.h"
#include <windows.h>
#include <limits.h>
#include <errno.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static HANDLE signals[4];
static SRWLOCK signal_lock = SRWLOCK_INIT;
static void signal_name(wchar_t name[80], uint32_t pid, size_t index)
{
  (void)swprintf(name, 80u, L"Local\\ftun-%lu-control-%u", (unsigned long)pid, (unsigned int)index);
}
static BOOL WINAPI console_signal(DWORD event)
{
  size_t index;
  if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT) index = 1u;
  else if (event == CTRL_CLOSE_EVENT || event == CTRL_SHUTDOWN_EVENT) index = 2u;
  else return FALSE;
  AcquireSRWLockShared(&signal_lock);
  if (signals[index] != NULL) SetEvent(signals[index]);
  ReleaseSRWLockShared(&signal_lock);
  return TRUE;
}
ftun_status_t ftun_signals_block(uint32_t mask, ftun_signal_mask_t *previous)
{
  previous->signals = mask;
  previous->blocked = 0u;
  AcquireSRWLockExclusive(&signal_lock);
  for (size_t i = 0u; i < 4u; i++) {
    wchar_t name[80];
    signal_name(name, GetCurrentProcessId(), i);
    signals[i] = CreateEventW(NULL, FALSE, FALSE, name);
    if (signals[i] == NULL) {
      for (size_t j = 0u; j < i; j++) { CloseHandle(signals[j]); signals[j] = NULL; }
      ReleaseSRWLockExclusive(&signal_lock);
      return FTUN_E_IO;
    }
  }
  ReleaseSRWLockExclusive(&signal_lock);
  if (SetConsoleCtrlHandler(console_signal, TRUE)) return FTUN_OK;
  (void)ftun_signals_restore(previous);
  return FTUN_E_IO;
}
ftun_status_t ftun_signals_restore(const ftun_signal_mask_t *previous)
{
  (void)previous;
  SetConsoleCtrlHandler(console_signal, FALSE);
  AcquireSRWLockExclusive(&signal_lock);
  for (size_t i = 0u; i < 4u; i++) {
    if (signals[i] != NULL) CloseHandle(signals[i]);
    signals[i] = NULL;
  }
  ReleaseSRWLockExclusive(&signal_lock);
  return FTUN_OK;
}
ftun_status_t ftun_signal_wait(uint32_t mask, uint32_t *received)
{
  HANDLE handles[4];
  uint32_t bits[4];
  DWORD count = 0u;
  for (size_t i = 0u; i < 4u; i++) if ((mask & (1u << i)) != 0u) {
    handles[count] = signals[i];
    bits[count++] = 1u << i;
  }
  DWORD result = WaitForMultipleObjects(count, handles, FALSE, INFINITE);
  if (result >= WAIT_OBJECT_0 + count) return FTUN_E_IO;
  *received = bits[result - WAIT_OBJECT_0];
  return FTUN_OK;
}
ftun_status_t ftun_thread_signal(ftun_thread_t *thread, uint32_t signal)
{
  (void)thread;
  for (size_t i = 0u; i < 4u; i++) if (signal == (1u << i))
    return SetEvent(signals[i]) ? FTUN_OK : FTUN_E_IO;
  return FTUN_E_INVALID;
}
ftun_status_t ftun_process_signal(uint32_t pid, uint32_t signal, int *native_error)
{
  *native_error = 0;
  for (size_t i = 0u; i < 4u; i++) if (signal == (1u << i)) {
    wchar_t name[80];
    signal_name(name, pid, i);
    HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, name);
    if (event == NULL) {
      *native_error = GetLastError() == ERROR_ACCESS_DENIED ? EACCES : ESRCH;
      return FTUN_E_IO;
    }
    BOOL sent = SetEvent(event);
    if (!sent) *native_error = EIO;
    CloseHandle(event);
    return sent ? FTUN_OK : FTUN_E_IO;
  }
  return FTUN_E_INVALID;
}
uint32_t ftun_process_id(void) { return GetCurrentProcessId(); }
void ftun_process_exit(int code) { ExitProcess((UINT)code); }
static void CALLBACK alarm_expired(void *context, BOOLEAN fired)
{
  (void)context; (void)fired;
  ExitProcess(4u);
}
ftun_status_t ftun_process_alarm_start(ftun_process_alarm_t *alarm, uint64_t milliseconds)
{
  HANDLE timer;
  if (milliseconds > MAXDWORD) return FTUN_E_LIMIT;
  if (!CreateTimerQueueTimer(&timer, NULL, alarm_expired, NULL, (DWORD)milliseconds, 0u,
      WT_EXECUTEONLYONCE)) return FTUN_E_IO;
  alarm->native = (uintptr_t)timer;
  return FTUN_OK;
}
void ftun_process_alarm_destroy(ftun_process_alarm_t *alarm)
{
  if (!DeleteTimerQueueTimer(NULL, (HANDLE)alarm->native, INVALID_HANDLE_VALUE)) abort();
  alarm->native = 0u;
}
ftun_status_t ftun_process_notify(const char *state)
{
  (void)state;
  const char *socket = getenv("NOTIFY_SOCKET");
  return socket == NULL || socket[0] == '\0' ? FTUN_OK : FTUN_E_UNSUPPORTED;
}
uint64_t ftun_process_boot_token(void)
{
  uint64_t token = (GetTickCount64() << 16u) ^ GetCurrentProcessId();
  return token == 0u ? 1u : token;
}
ftun_status_t ftun_platform_boot_identity(void *buffer, size_t capacity, size_t *length)
{
  SYSTEM_TIMEOFDAY_INFORMATION info;
  *length = 0u;
  if (capacity < sizeof(info.BootTime)) return FTUN_E_LIMIT;
  if (NtQuerySystemInformation(SystemTimeOfDayInformation, &info, sizeof(info), NULL) != 0) return FTUN_E_IO;
  memcpy(buffer, &info.BootTime, sizeof(info.BootTime));
  *length = sizeof(info.BootTime);
  return FTUN_OK;
}
size_t ftun_platform_descriptor_limit(size_t requested) { return requested; }
ptrdiff_t ftun_process_executable(char *buffer, size_t capacity)
{
  wchar_t path[4096];
  DWORD length = GetModuleFileNameW(NULL, path, 4096u);
  if (length == 0u || length >= 4096u || capacity > INT_MAX) return -1;
  int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path, (int)length,
    buffer, (int)capacity, NULL, NULL);
  return bytes == 0 ? -1 : bytes;
}
