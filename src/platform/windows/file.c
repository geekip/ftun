#include "platform/file.h"
#include "platform/random.h"
#include <windows.h>
#include <limits.h>
#include <io.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define PATH_CHARS 4096u
static ftun_status_t file_error(DWORD error)
{
  if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return FTUN_E_EOF;
  if (error == ERROR_LOCK_VIOLATION || error == ERROR_SHARING_VIOLATION ||
      error == ERROR_NO_DATA || error == ERROR_PIPE_BUSY) return FTUN_E_AGAIN;
  if (error == ERROR_DISK_FULL || error == ERROR_NOT_ENOUGH_MEMORY || error == ERROR_TOO_MANY_OPEN_FILES) return FTUN_E_LIMIT;
  if (error == ERROR_ACCESS_DENIED || error == ERROR_PRIVILEGE_NOT_HELD) return FTUN_E_REJECTED;
  if (error == ERROR_INVALID_NAME || error == ERROR_INVALID_PARAMETER ||
      error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS) return FTUN_E_INVALID;
  return FTUN_E_IO;
}
static ftun_status_t wide_path(const char *path, wchar_t out[PATH_CHARS])
{
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, out, PATH_CHARS) != 0) return FTUN_OK;
  return GetLastError() == ERROR_INSUFFICIENT_BUFFER ? FTUN_E_LIMIT : FTUN_E_INVALID;
}
static HANDLE native_file(ftun_handle_t descriptor) { return (HANDLE)_get_osfhandle((int)descriptor); }
/* 新建日志、临时文件和目录只授予当前用户访问，不继承公共工作目录的宽DACL。 */
typedef struct {
  SECURITY_ATTRIBUTES attributes;
  SECURITY_DESCRIPTOR descriptor;
  union { DWORD alignment; unsigned char bytes[sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + SECURITY_MAX_SID_SIZE]; } acl;
} owner_security_t;
static ftun_status_t owner_security(owner_security_t *security)
{
  HANDLE token;
  union { TOKEN_USER alignment; unsigned char bytes[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE]; } user;
  DWORD length;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return FTUN_E_IO;
  BOOL valid = GetTokenInformation(token, TokenUser, &user, sizeof(user), &length);
  CloseHandle(token);
  if (!valid || !InitializeSecurityDescriptor(&security->descriptor, SECURITY_DESCRIPTOR_REVISION) ||
      !InitializeAcl((PACL)&security->acl, sizeof(security->acl), ACL_REVISION) ||
      !AddAccessAllowedAce((PACL)&security->acl, ACL_REVISION, FILE_ALL_ACCESS, user.alignment.User.Sid) ||
      !SetSecurityDescriptorDacl(&security->descriptor, TRUE, (PACL)&security->acl, FALSE) ||
      !SetSecurityDescriptorControl(&security->descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) return FTUN_E_IO;
  security->attributes = (SECURITY_ATTRIBUTES){sizeof(SECURITY_ATTRIBUTES), &security->descriptor, FALSE};
  return FTUN_OK;
}
static ftun_status_t open_path(const char *path, DWORD access, DWORD creation,
  DWORD flags, bool nofollow, int crt_flags, ftun_handle_t *out)
{
  wchar_t wide[PATH_CHARS];
  owner_security_t security;
  *out = -1;
  ftun_status_t status = wide_path(path, wide);
  if (status == FTUN_OK && creation != OPEN_EXISTING) status = owner_security(&security);
  if (status != FTUN_OK) return status;
  HANDLE file = CreateFileW(wide, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    creation == OPEN_EXISTING ? NULL : &security.attributes, creation,
    flags | (nofollow ? FILE_FLAG_OPEN_REPARSE_POINT : 0u), NULL);
  if (file == INVALID_HANDLE_VALUE) return file_error(GetLastError());
  if (nofollow) {
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(file, &info) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0u) {
      CloseHandle(file);
      return FTUN_E_REJECTED;
    }
  }
  int descriptor = _open_osfhandle((intptr_t)file, crt_flags | _O_BINARY);
  if (descriptor < 0) { CloseHandle(file); return FTUN_E_LIMIT; }
  *out = descriptor;
  return FTUN_OK;
}
ftun_status_t ftun_file_open(const char *path, ftun_file_open_mode_t mode, ftun_handle_t *out)
{
  return open_path(path, mode == FTUN_FILE_APPEND_EXISTING ? FILE_APPEND_DATA | FILE_READ_ATTRIBUTES :
    mode == FTUN_FILE_READ_DIRECTORY ? FILE_READ_ATTRIBUTES : GENERIC_READ,
    OPEN_EXISTING, mode == FTUN_FILE_READ_DIRECTORY ? FILE_FLAG_BACKUP_SEMANTICS : FILE_ATTRIBUTE_NORMAL,
    mode != FTUN_FILE_READ, mode == FTUN_FILE_APPEND_EXISTING ? _O_WRONLY : _O_RDONLY, out);
}
ftun_status_t ftun_file_close(ftun_handle_t descriptor)
{ return _close((int)descriptor) == 0 ? FTUN_OK : FTUN_E_IO; }
ftun_status_t ftun_file_inspect(ftun_handle_t descriptor, ftun_file_info_t *out)
{
  BY_HANDLE_FILE_INFORMATION info;
  if (!GetFileInformationByHandle(native_file(descriptor), &info)) return file_error(GetLastError());
  out->size = ((uint64_t)info.nFileSizeHigh << 32u) | info.nFileSizeLow;
  out->directory = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0u;
  out->regular = !out->directory && GetFileType(native_file(descriptor)) == FILE_TYPE_DISK;
  return FTUN_OK;
}
ftun_status_t ftun_file_inspect_path(const char *path, ftun_file_info_t *out)
{
  ftun_handle_t file;
  ftun_status_t status = open_path(path, FILE_READ_ATTRIBUTES, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS, false, _O_RDONLY, &file);
  if (status != FTUN_OK) return status;
  status = ftun_file_inspect(file, out);
  ftun_status_t closed = ftun_file_close(file);
  return status == FTUN_OK ? closed : status;
}
ptrdiff_t ftun_file_read(ftun_handle_t descriptor, void *buffer, size_t capacity)
{
  DWORD read;
  DWORD count = capacity > MAXDWORD ? MAXDWORD : (DWORD)capacity;
  if (ReadFile(native_file(descriptor), buffer, count, &read, NULL)) return read;
  return GetLastError() == ERROR_BROKEN_PIPE || GetLastError() == ERROR_HANDLE_EOF ? 0 : -1;
}
ptrdiff_t ftun_file_write_some(ftun_handle_t descriptor, const void *buffer, size_t length, ftun_status_t *status)
{
  DWORD written;
  DWORD count = length > MAXDWORD ? MAXDWORD : (DWORD)length;
  if (!WriteFile(native_file(descriptor), buffer, count, &written, NULL)) {
    *status = file_error(GetLastError());
    return -1;
  }
  *status = written == 0u && length != 0u ? FTUN_E_AGAIN : FTUN_OK;
  return written;
}
ftun_status_t ftun_file_sync(ftun_handle_t descriptor, bool data_only)
{
  (void)data_only;
  return FlushFileBuffers(native_file(descriptor)) ? FTUN_OK : file_error(GetLastError());
}
bool ftun_platform_file_is_open(const ftun_file_handle_t *file) { return file->descriptor >= 0; }
ftun_status_t ftun_platform_file_open_append(const char *path, bool truncate,
  ftun_file_handle_t *out, uint64_t *size)
{
  ftun_status_t status = open_path(path, truncate ? GENERIC_WRITE | FILE_READ_ATTRIBUTES :
    FILE_APPEND_DATA | FILE_READ_ATTRIBUTES, truncate ? CREATE_ALWAYS : OPEN_ALWAYS,
    FILE_ATTRIBUTE_NORMAL, true, _O_WRONLY | _O_APPEND, &out->descriptor);
  if (status != FTUN_OK) return status;
  ftun_file_info_t info;
  status = ftun_file_inspect(out->descriptor, &info);
  if (status != FTUN_OK) { ftun_platform_file_close(out); return status; }
  *size = info.size;
  return FTUN_OK;
}
ftun_status_t ftun_platform_file_close(ftun_file_handle_t *file)
{
  ftun_status_t status = ftun_file_close(file->descriptor);
  file->descriptor = -1;
  return status;
}
ftun_status_t ftun_platform_file_write(ftun_file_handle_t *file, ftun_bytes_t contents, size_t *written)
{
  *written = 0u;
  while (*written < contents.length) {
    ftun_status_t status;
    ptrdiff_t count = ftun_file_write_some(file->descriptor, contents.data + *written,
      contents.length - *written, &status);
    if (status != FTUN_OK) return status;
    *written += (size_t)count;
  }
  return FTUN_OK;
}
ftun_status_t ftun_platform_file_rename_if_exists(const char *from, const char *to)
{
  wchar_t source[PATH_CHARS], destination[PATH_CHARS];
  ftun_status_t status = wide_path(from, source);
  if (status == FTUN_OK) status = wide_path(to, destination);
  if (status != FTUN_OK) return status;
  if (MoveFileExW(source, destination, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) return FTUN_OK;
  DWORD error = GetLastError();
  return error == ERROR_FILE_NOT_FOUND ? FTUN_OK : file_error(error);
}
ftun_status_t ftun_platform_file_parent(const char *path, ftun_string_t *out)
{
  const char *slash = NULL;
  for (const char *p = path; *p != '\0'; p++) if (*p == '/' || *p == '\\') slash = p;
  if (path[0] == '\0' || (slash != NULL && slash[1] == '\0')) return FTUN_E_INVALID;
  if (slash == NULL) *out = (ftun_string_t){".", 1u};
  else *out = (ftun_string_t){path, slash == path ? 1u : slash == path + 2 && path[1] == ':' ? 3u : (size_t)(slash - path)};
  return FTUN_OK;
}
ftun_status_t ftun_platform_file_lock_acquire(const char *path, ftun_platform_file_lock_t *out)
{
  ftun_status_t status = open_path(path, GENERIC_READ | GENERIC_WRITE, OPEN_ALWAYS,
    FILE_ATTRIBUTE_NORMAL, true, _O_RDWR, &out->descriptor);
  if (status != FTUN_OK) return status;
  OVERLAPPED offset = {0};
  if (LockFileEx(native_file(out->descriptor), LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
      0u, MAXDWORD, MAXDWORD, &offset)) return FTUN_OK;
  status = file_error(GetLastError());
  ftun_platform_file_close(out);
  return status;
}
ftun_status_t ftun_platform_file_lock_release(ftun_platform_file_lock_t *lock)
{
  OVERLAPPED offset = {0};
  ftun_status_t status = UnlockFileEx(native_file(lock->descriptor), 0u, MAXDWORD, MAXDWORD,
    &offset) ? FTUN_OK : FTUN_E_IO;
  ftun_status_t closed = ftun_platform_file_close(lock);
  return status == FTUN_OK ? closed : status;
}
ftun_status_t ftun_platform_file_write_temporary(char *temporary, ftun_bytes_t contents,
  unsigned int mode, bool *created)
{
  static const char alphabet[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  uint8_t random[6];
  size_t length = strlen(temporary), written;
  ftun_handle_t descriptor;
  (void)mode;
  *created = false;
  if (length < 6u || strcmp(temporary + length - 6u, "XXXXXX") != 0) return FTUN_E_INVALID;
  ftun_status_t status = ftun_random_bytes(random, sizeof(random));
  if (status != FTUN_OK) return status;
  for (size_t i = 0u; i < 6u; i++) temporary[length - 6u + i] = alphabet[random[i] % 62u];
  status = open_path(temporary, GENERIC_WRITE, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
    true, _O_WRONLY, &descriptor);
  if (status != FTUN_OK) return status;
  *created = true;
  ftun_file_handle_t file = {descriptor};
  status = ftun_platform_file_write(&file, contents, &written);
  ftun_status_t closed = ftun_platform_file_close(&file);
  return status == FTUN_OK ? closed : status;
}
void ftun_platform_file_remove_temporary(const char *temporary)
{
  wchar_t path[PATH_CHARS];
  if (wide_path(temporary, path) == FTUN_OK) DeleteFileW(path);
}
ftun_status_t ftun_platform_file_replace(const char *temporary, const char *destination,
  const char *parent, ftun_file_stage_hook_fn hook, void *user, bool *published)
{
  wchar_t source[PATH_CHARS], target[PATH_CHARS];
  ftun_handle_t file = -1, directory = -1;
  *published = false;
  ftun_status_t status = wide_path(temporary, source);
  if (status == FTUN_OK) status = wide_path(destination, target);
  if (status == FTUN_OK) status = open_path(temporary, GENERIC_READ | GENERIC_WRITE, OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL, true, _O_RDWR, &file);
  if (status == FTUN_OK) status = ftun_file_open(parent, FTUN_FILE_READ_DIRECTORY, &directory);
  if (status != FTUN_OK) goto done;
  BY_HANDLE_FILE_INFORMATION from, folder;
  if (!GetFileInformationByHandle(native_file(file), &from) ||
      !GetFileInformationByHandle(native_file(directory), &folder)) { status = FTUN_E_IO; goto done; }
  if ((from.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0u ||
      (folder.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0u ||
      from.dwVolumeSerialNumber != folder.dwVolumeSerialNumber) { status = FTUN_E_INVALID; goto done; }
  status = ftun_file_sync(file, false);
  if (status == FTUN_OK && hook != NULL) status = hook(FTUN_FILE_STAGE_TEMP_SYNCED, user);
  if (status != FTUN_OK) goto done;
  /* 不允许跨卷copy/delete；WRITE_THROUGH是Windows的移动耐久屏障。 */
  if (!MoveFileExW(source, target, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    status = file_error(GetLastError()); goto done;
  }
  *published = true;
  if (hook != NULL) status = hook(FTUN_FILE_STAGE_RENAMED, user);
  if (status == FTUN_OK && hook != NULL) status = hook(FTUN_FILE_STAGE_DIRECTORY_SYNCED, user);
done:
  if (file >= 0 && ftun_file_close(file) != FTUN_OK && status == FTUN_OK) status = FTUN_E_IO;
  if (directory >= 0 && ftun_file_close(directory) != FTUN_OK && status == FTUN_OK) status = FTUN_E_IO;
  return status;
}
ftun_status_t ftun_directory_create(const char *path, unsigned int mode)
{
  wchar_t wide[PATH_CHARS];
  owner_security_t security;
  (void)mode;
  ftun_status_t status = wide_path(path, wide);
  if (status == FTUN_OK) status = owner_security(&security);
  if (status != FTUN_OK) return status;
  return CreateDirectoryW(wide, &security.attributes) ? FTUN_OK : file_error(GetLastError());
}
ftun_status_t ftun_directory_ensure(const char *path, unsigned int mode)
{
  ftun_status_t status = ftun_directory_create(path, mode);
  if (status != FTUN_E_INVALID) return status;
  ftun_file_info_t info;
  status = ftun_file_inspect_path(path, &info);
  return status == FTUN_OK && !info.directory ? FTUN_E_INVALID : status;
}
void ftun_directory_remove(const char *path)
{
  wchar_t wide[PATH_CHARS];
  if (wide_path(path, wide) == FTUN_OK) RemoveDirectoryW(wide);
}
void *ftun_file_map_read(ftun_handle_t descriptor, size_t length)
{
  HANDLE mapping = CreateFileMappingW(native_file(descriptor), NULL, PAGE_READONLY, 0u, 0u, NULL);
  if (mapping == NULL) return NULL;
  void *view = MapViewOfFile(mapping, FILE_MAP_READ, 0u, 0u, length);
  CloseHandle(mapping);
  return view;
}
ftun_status_t ftun_file_unmap(const void *address, size_t length)
{ (void)length; return UnmapViewOfFile(address) ? FTUN_OK : FTUN_E_IO; }
ftun_status_t ftun_file_real_path(const char *path, char *out, size_t capacity)
{
  wchar_t wide[PATH_CHARS], canonical[PATH_CHARS];
  ftun_handle_t descriptor;
  ftun_status_t status = wide_path(path, wide);
  if (status == FTUN_OK) status = open_path(path, FILE_READ_ATTRIBUTES, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS, false, _O_RDONLY, &descriptor);
  if (status != FTUN_OK) return status;
  DWORD length = GetFinalPathNameByHandleW(native_file(descriptor), canonical, PATH_CHARS, FILE_NAME_NORMALIZED);
  ftun_file_close(descriptor);
  if (length == 0u || length >= PATH_CHARS || capacity > INT_MAX) return FTUN_E_LIMIT;
  const wchar_t *start = canonical;
  size_t prefix = 0u;
  if (wcsncmp(start, L"\\\\?\\UNC\\", 8u) == 0) { start += 8u; prefix = 2u; }
  else if (wcsncmp(start, L"\\\\?\\", 4u) == 0) start += 4u;
  if (capacity <= prefix) return FTUN_E_LIMIT;
  int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, start, -1,
    out + prefix, (int)(capacity - prefix), NULL, NULL);
  if (bytes == 0) return FTUN_E_LIMIT;
  if (prefix != 0u) out[0] = out[1] = '/';
  for (char *p = out; *p != '\0'; p++) if (*p == '\\') *p = '/';
  return FTUN_OK;
}
ftun_status_t ftun_user_home(char *storage, size_t capacity, ftun_string_t *home)
{
  wchar_t path[PATH_CHARS];
  DWORD length = GetEnvironmentVariableW(L"USERPROFILE", path, PATH_CHARS);
  if (length == 0u) return FTUN_E_IO;
  if (length >= PATH_CHARS || capacity > INT_MAX) return FTUN_E_AGAIN;
  int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path, -1,
    storage, (int)capacity, NULL, NULL);
  if (bytes == 0) return FTUN_E_AGAIN;
  *home = (ftun_string_t){storage, (size_t)bytes - 1u};
  return FTUN_OK;
}
ftun_status_t ftun_file_duplicate(ftun_handle_t descriptor, ftun_handle_t *out)
{
  *out = _dup((int)descriptor);
  if (*out < 0) return FTUN_E_IO;
  HANDLE file = native_file(*out);
  DWORD mode = PIPE_NOWAIT;
  if (!SetHandleInformation(file, HANDLE_FLAG_INHERIT, 0u) ||
      (GetFileType(file) == FILE_TYPE_PIPE && !SetNamedPipeHandleState(file, &mode, NULL, NULL))) {
    ftun_file_close(*out); *out = -1; return FTUN_E_IO;
  }
  return FTUN_OK;
}
ftun_status_t ftun_file_wait_writable(ftun_handle_t descriptor, uint32_t timeout_ms)
{
  HANDLE file = native_file(descriptor);
  if (GetFileType(file) == FILE_TYPE_PIPE) {
    DWORD mode = PIPE_NOWAIT;
    if (!SetNamedPipeHandleState(file, &mode, NULL, NULL)) return FTUN_E_UNSUPPORTED;
    /* PIPE_NOWAIT无可写等待事件；有界让出CPU，交还writer检查停止期限。 */
    if (timeout_ms != 0u) Sleep(timeout_ms);
    return FTUN_OK;
  }
  DWORD result = WaitForSingleObject(file, timeout_ms);
  return result == WAIT_OBJECT_0 ? FTUN_OK : result == WAIT_TIMEOUT ? FTUN_E_AGAIN : FTUN_E_IO;
}
ftun_status_t ftun_platform_file_write_ready(ftun_handle_t descriptor, ftun_bytes_t contents)
{
  ftun_status_t status = ftun_file_wait_writable(descriptor, 0u);
  if (status != FTUN_OK) return status;
  ptrdiff_t count = ftun_file_write_some(descriptor, contents.data, contents.length, &status);
  return status == FTUN_OK && (size_t)count != contents.length ? FTUN_E_IO : status;
}
int ftun_file_standard_error(void) { return 2; }

static bool path_separator(char value) { return value == '/' || value == '\\'; }
size_t ftun_file_path_root_length(const char *path)
{
  if (path[0] != '\0' && path[1] == ':' && path_separator(path[2])) return 3u;
  if (!path_separator(path[0])) return 0u;
  if (!path_separator(path[1])) return 1u;
  const char *server = path + 2u;
  const char *share = server;
  while (*share != '\0' && !path_separator(*share)) share++;
  if (share == server || *share == '\0') return 0u;
  const char *end = share + 1u;
  while (*end != '\0' && !path_separator(*end)) end++;
  return end == share + 1u ? 0u : (size_t)(end - path) + (*end != '\0' ? 1u : 0u);
}
void ftun_file_path_normalize(char *path)
{
  for (; *path != '\0'; path++) if (*path == '\\') *path = '/';
}

const char *ftun_file_system_ca(void)
{
  const char *configured = getenv("SSL_CERT_FILE");
  return configured != NULL && configured[0] != '\0' ? configured : NULL;
}
