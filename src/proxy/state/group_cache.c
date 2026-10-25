#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "group_cache.h"
#include "config/model.h"
#include "core/budget.h"
#include "core/context.h"
#include "platform/file.h"
#include "util/time.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* REQ-STATE-001 / TASK-STATE-003 / TEST-STATE-003，目标 0.5.0：
 * ftun_group_cache_save 原子写入可丢弃 Group/Health 缓存。 */

#define FTUN_GROUP_CACHE_HEADER_BYTES 40u
#define FTUN_GROUP_CACHE_RECORD_BYTES 24u

static void ftun_cache_u32(uint8_t *out, uint32_t value)
{
  out[0] = (uint8_t)value;
  out[1] = (uint8_t)(value >> 8u);
  out[2] = (uint8_t)(value >> 16u);
  out[3] = (uint8_t)(value >> 24u);
}

static uint32_t ftun_cache_load_u32(const uint8_t *value)
{
  return (uint32_t)value[0] | ((uint32_t)value[1] << 8u) |
    ((uint32_t)value[2] << 16u) | ((uint32_t)value[3] << 24u);
}

static void ftun_cache_u64(uint8_t *out, uint64_t value)
{
  size_t index;
  for (index = 0u; index < 8u; index++) out[index] = (uint8_t)(value >> (index * 8u));
}

static uint64_t ftun_cache_load_u64(const uint8_t *value)
{
  uint64_t result = 0u;
  size_t index;
  for (index = 0u; index < 8u; index++) result |= (uint64_t)value[index] << (index * 8u);
  return result;
}

static uint64_t ftun_cache_hash(uint64_t hash, const void *data, size_t length)
{
  const uint8_t *bytes = (const uint8_t *)data;
  size_t index;
  for (index = 0u; index < length; index++) {
    hash ^= bytes[index];
    hash *= UINT64_C(1099511628211);
  }
  return hash;
}

static uint64_t ftun_cache_checksum(const uint8_t *data, size_t length)
{
  uint64_t hash = UINT64_C(1469598103934665603);
  static const uint8_t zero[8] = {0};
  hash = ftun_cache_hash(hash, data, 32u);
  hash = ftun_cache_hash(hash, zero, sizeof(zero));
  if (length > FTUN_GROUP_CACHE_HEADER_BYTES) {
    hash = ftun_cache_hash(hash, data + FTUN_GROUP_CACHE_HEADER_BYTES,
                           length - FTUN_GROUP_CACHE_HEADER_BYTES);
  }
  return hash;
}

/* CLOCK_MONOTONIC values are comparable across processes in one boot, but not
 * across reboots. Persist a compact boot identity so old health samples become
 * stale after reboot while the selected legal member remains restorable. */
static uint32_t ftun_cache_boot_token(ftun_budget_t *budget)
{
  uint8_t data[64];
  uint64_t hash = UINT64_C(1469598103934665603);
  size_t length = 0u;
  ftun_reservation_t *reservation = NULL;
  ftun_budget_resources_t resources = {0u, 1u, 0u};
  int descriptor, close_status;
  if (budget != NULL && ftun_budget_reserve_resources(budget, resources, &reservation) != FTUN_OK) return 0u;
  descriptor = open("/proc/sys/kernel/random/boot_id",
                        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) { (void)ftun_reservation_release(&reservation); return 0u; }
  while (length < sizeof(data)) {
    ssize_t count = read(descriptor, data + length, sizeof(data) - length);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) break;
    length += (size_t)count;
  }
  close_status = close(descriptor);
  (void)ftun_reservation_release(&reservation);
  if (close_status != 0 || length == 0u) return 0u;
  hash = ftun_cache_hash(hash, data, length);
  {
    uint32_t token = (uint32_t)(hash ^ (hash >> 32u));
    return token == 0u ? 1u : token;
  }
}

static uint64_t ftun_cache_fingerprint_string(uint64_t hash, const char *value)
{
  uint32_t length = value == NULL ? 0u : (uint32_t)strlen(value);
  uint8_t encoded[4];
  ftun_cache_u32(encoded, length);
  hash = ftun_cache_hash(hash, encoded, sizeof(encoded));
  return value == NULL ? hash : ftun_cache_hash(hash, value, length);
}

ftun_status_t ftun_group_cache_fingerprint(const ftun_config_t *config,
                                           uint64_t *out)
{
  uint64_t hash = UINT64_C(1469598103934665603);
  size_t index;
  if (out != NULL) *out = 0u;
  if (config == NULL || out == NULL) return FTUN_E_INVALID;
  hash = ftun_cache_hash(hash, "FTUN-GROUP-CONFIG-1", 19u);
  for (index = 0u; index < config->outbound_count; index++) {
    const ftun_config_outbound_t *item = &config->outbounds[index];
    uint8_t kind = (uint8_t)item->kind;
    size_t member;
    hash = ftun_cache_hash(hash, &kind, sizeof(kind));
    hash = ftun_cache_fingerprint_string(hash, item->name);
    hash = ftun_cache_fingerprint_string(hash, item->server);
    hash = ftun_cache_fingerprint_string(hash, item->username);
    /* 密码参与身份判定，但只进入不可逆指纹。 */
    hash = ftun_cache_fingerprint_string(hash, item->password);
    hash = ftun_cache_fingerprint_string(hash, item->dns_server);
    hash = ftun_cache_fingerprint_string(hash, item->default_member);
    hash = ftun_cache_fingerprint_string(hash, item->url);
    hash = ftun_cache_fingerprint_string(hash, item->interval);
    hash = ftun_cache_fingerprint_string(hash, item->timeout);
    hash = ftun_cache_hash(hash, &item->udp, sizeof(item->udp));
    hash = ftun_cache_hash(hash, &item->tolerance_ms,
                           sizeof(item->tolerance_ms));
    hash = ftun_cache_hash(hash, &item->lazy, sizeof(item->lazy));
    hash = ftun_cache_hash(hash, &item->expected_status,
                           sizeof(item->expected_status));
    for (member = 0u; member < item->members.count; member++) {
      hash = ftun_cache_fingerprint_string(hash, item->members.items[member]);
    }
  }
  *out = hash == 0u ? 1u : hash;
  return FTUN_OK;
}

static int ftun_cache_record_valid(const ftun_runtime_group_record_t *record)
{
  return record != NULL && record->group.data != NULL &&
    record->group.length != 0u && record->group.length <= UINT32_MAX &&
    memchr(record->group.data, '\0', record->group.length) == NULL &&
    record->member.data != NULL && record->member.length != 0u &&
    record->member.length <= UINT32_MAX &&
    memchr(record->member.data, '\0', record->member.length) == NULL &&
    (record->kind == FTUN_RUNTIME_GROUP_SELECT ||
     record->kind == FTUN_RUNTIME_GROUP_URL_TEST);
}

static ftun_status_t ftun_group_cache_encode_snapshot(
  ftun_budget_t *budget, const ftun_group_cache_snapshot_t *snapshot, uint32_t boot_token,
  uint8_t **out, size_t *out_length, ftun_reservation_t **out_reservation)
{
  uint8_t *data;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  size_t length = FTUN_GROUP_CACHE_HEADER_BYTES;
  size_t cursor = FTUN_GROUP_CACHE_HEADER_BYTES;
  size_t index;
  if (out != NULL) *out = NULL;
  if (out_length != NULL) *out_length = 0u;
  if (out_reservation != NULL) *out_reservation = NULL;
  if (snapshot == NULL || out == NULL || out_length == NULL || out_reservation == NULL ||
      snapshot->fingerprint == 0u ||
      snapshot->record_count > FTUN_GROUP_CACHE_MAX_ENTRIES ||
      (snapshot->record_count != 0u && snapshot->records == NULL)) {
    return FTUN_E_INVALID;
  }
  for (index = 0u; index < snapshot->record_count; index++) {
    const ftun_runtime_group_record_t *record = &snapshot->records[index];
    if (!ftun_cache_record_valid(record) ||
        record->group.length > SIZE_MAX - record->member.length ||
        FTUN_GROUP_CACHE_RECORD_BYTES > SIZE_MAX - length ||
        record->group.length + record->member.length >
          SIZE_MAX - length - FTUN_GROUP_CACHE_RECORD_BYTES) return FTUN_E_LIMIT;
    length += FTUN_GROUP_CACHE_RECORD_BYTES + record->group.length +
      record->member.length;
  }
  if (length > FTUN_GROUP_CACHE_MAX_BYTES) return FTUN_E_LIMIT;
  if (budget != NULL) {
    status = ftun_budget_reserve(budget, length, &reservation);
    if (status != FTUN_OK) return status;
  }
  data = (uint8_t *)calloc(1u, length);
  if (data == NULL) { (void)ftun_reservation_release(&reservation); return FTUN_E_LIMIT; }
  memcpy(data, "FTGC", 4u);
  ftun_cache_u32(data + 4u, 1u);
  ftun_cache_u64(data + 8u, snapshot->fingerprint);
  ftun_cache_u64(data + 16u, snapshot->saved_ms);
  ftun_cache_u32(data + 24u, (uint32_t)snapshot->record_count);
  ftun_cache_u32(data + 28u, boot_token);
  for (index = 0u; index < snapshot->record_count; index++) {
    const ftun_runtime_group_record_t *record = &snapshot->records[index];
    uint8_t flags = (uint8_t)((record->degraded ? 1u : 0u) |
      (record->health_valid ? 2u : 0u) |
      (record->health_success ? 4u : 0u));
    ftun_cache_u32(data + cursor, (uint32_t)record->group.length);
    ftun_cache_u32(data + cursor + 4u, (uint32_t)record->member.length);
    data[cursor + 8u] = (uint8_t)record->kind;
    data[cursor + 9u] = flags;
    ftun_cache_u32(data + cursor + 12u, record->latency_ms);
    ftun_cache_u64(data + cursor + 16u, record->observed_ms);
    cursor += FTUN_GROUP_CACHE_RECORD_BYTES;
    memcpy(data + cursor, record->group.data, record->group.length);
    cursor += record->group.length;
    memcpy(data + cursor, record->member.data, record->member.length);
    cursor += record->member.length;
  }
  ftun_cache_u64(data + 32u, ftun_cache_checksum(data, length));
  *out = data;
  *out_length = length;
  *out_reservation = reservation;
  return FTUN_OK;
}

ftun_status_t ftun_group_cache_write_budget(ftun_budget_t *budget,
  const char *path, const ftun_group_cache_snapshot_t *snapshot)
{
  uint8_t *data = NULL;
  size_t length = 0u;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  if (path == NULL || path[0] == '\0') return FTUN_E_INVALID;
  status = ftun_group_cache_encode_snapshot(budget, snapshot,
    ftun_cache_boot_token(budget), &data, &length, &reservation);
  if (status == FTUN_OK) status = ftun_file_write_atomic_budget(budget,
    path, (ftun_bytes_t){data, length}, 0600u, NULL, NULL);
  free(data);
  (void)ftun_reservation_release(&reservation);
  return status;
}

ftun_status_t ftun_group_cache_write(
  const char *path, const ftun_group_cache_snapshot_t *snapshot)
{
  return ftun_group_cache_write_budget(NULL, path, snapshot);
}

static ftun_status_t ftun_cache_read(ftun_budget_t *budget, const char *path,
  uint8_t **out, size_t *out_length, ftun_reservation_t **out_reservation)
{
  struct stat metadata;
  uint8_t *data = NULL;
  size_t offset = 0u;
  int descriptor = -1;
  ftun_reservation_t *reservation = NULL, *fd_reservation = NULL;
  ftun_budget_resources_t resources = {0u, 1u, 0u};
  ftun_status_t status;
  *out = NULL;
  *out_length = 0u;
  *out_reservation = NULL;
  if (path == NULL || path[0] == '\0') return FTUN_E_INVALID;
  if (budget != NULL) {
    status = ftun_budget_reserve_resources(budget, resources, &fd_reservation);
    if (status != FTUN_OK) return status;
  }
  descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) {
    status = errno == ENOENT ? FTUN_E_EOF : FTUN_E_IO;
    goto done;
  }
  if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
      metadata.st_size < (off_t)FTUN_GROUP_CACHE_HEADER_BYTES ||
      (uintmax_t)metadata.st_size > FTUN_GROUP_CACHE_MAX_BYTES) {
    status = FTUN_E_STATE_CORRUPT;
    goto done;
  }
  if (budget != NULL) {
    status = ftun_budget_reserve(budget, (size_t)metadata.st_size, &reservation);
    if (status != FTUN_OK) goto done;
  }
  data = (uint8_t *)malloc((size_t)metadata.st_size);
  if (data == NULL) { status = FTUN_E_LIMIT; goto done; }
  while (offset < (size_t)metadata.st_size) {
    ssize_t count = read(descriptor, data + offset, (size_t)metadata.st_size - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) { status = FTUN_E_IO; goto done; }
    offset += (size_t)count;
  }
  if (close(descriptor) != 0) {
    descriptor = -1;
    status = FTUN_E_IO;
    goto done;
  }
  descriptor = -1;
  *out = data; data = NULL;
  *out_length = offset;
  *out_reservation = reservation; reservation = NULL;
  status = FTUN_OK;
done:
  if (descriptor >= 0) (void)close(descriptor);
  free(data);
  (void)ftun_reservation_release(&reservation);
  (void)ftun_reservation_release(&fd_reservation);
  return status;
}

ftun_status_t ftun_group_cache_load_budget(ftun_budget_t *budget, const char *path,
                                    ftun_group_cache_snapshot_t **out)
{
  ftun_group_cache_snapshot_t *snapshot = NULL;
  ftun_reservation_t *file_reservation = NULL, *reservation = NULL;
  uint8_t *file = NULL;
  size_t length = 0u;
  size_t cursor = FTUN_GROUP_CACHE_HEADER_BYTES;
  size_t allocation;
  size_t strings = 0u;
  size_t index;
  char *text;
  uint32_t count;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (out == NULL) return FTUN_E_INVALID;
  status = ftun_cache_read(budget, path, &file, &length, &file_reservation);
  if (status != FTUN_OK) return status;
  if (memcmp(file, "FTGC", 4u) != 0 || ftun_cache_load_u32(file + 4u) != 1u ||
      ftun_cache_load_u64(file + 32u) != ftun_cache_checksum(file, length)) {
    status = FTUN_E_STATE_CORRUPT;
    goto done;
  }
  count = ftun_cache_load_u32(file + 24u);
  if (count > FTUN_GROUP_CACHE_MAX_ENTRIES) {
    status = FTUN_E_STATE_CORRUPT;
    goto done;
  }
  for (index = 0u; index < count; index++) {
    size_t group_length;
    size_t member_length;
    if (length - cursor < FTUN_GROUP_CACHE_RECORD_BYTES) goto corrupt;
    group_length = ftun_cache_load_u32(file + cursor);
    member_length = ftun_cache_load_u32(file + cursor + 4u);
    if (group_length == 0u || member_length == 0u ||
        (file[cursor + 8u] != FTUN_RUNTIME_GROUP_SELECT &&
         file[cursor + 8u] != FTUN_RUNTIME_GROUP_URL_TEST) ||
        (file[cursor + 9u] & ~7u) != 0u || file[cursor + 10u] != 0u ||
        file[cursor + 11u] != 0u ||
        group_length > length - cursor - FTUN_GROUP_CACHE_RECORD_BYTES ||
        member_length > length - cursor - FTUN_GROUP_CACHE_RECORD_BYTES -
          group_length) goto corrupt;
    cursor += FTUN_GROUP_CACHE_RECORD_BYTES + group_length + member_length;
    if (strings > SIZE_MAX - group_length - member_length - 2u) goto corrupt;
    strings += group_length + member_length + 2u;
  }
  if (cursor != length || count >
      (SIZE_MAX - sizeof(*snapshot) - strings) / sizeof(*snapshot->records)) {
    goto corrupt;
  }
  allocation = sizeof(*snapshot) + (size_t)count * sizeof(*snapshot->records) +
    strings;
  if (budget != NULL) {
    status = ftun_budget_reserve(budget, allocation, &reservation);
    if (status != FTUN_OK) goto done;
  }
  snapshot = (ftun_group_cache_snapshot_t *)calloc(1u, allocation);
  if (snapshot == NULL) {
    status = FTUN_E_LIMIT;
    goto done;
  }
  snapshot->records = (ftun_runtime_group_record_t *)(snapshot + 1u);
  snapshot->record_count = count;
  snapshot->fingerprint = ftun_cache_load_u64(file + 8u);
  snapshot->saved_ms = ftun_cache_load_u64(file + 16u);
  {
    uint32_t stored_boot = ftun_cache_load_u32(file + 28u);
    uint32_t current_boot = ftun_cache_boot_token(budget);
    snapshot->health_clock_valid = stored_boot != 0u &&
      current_boot != 0u && stored_boot == current_boot;
  }
  if (snapshot->fingerprint == 0u) goto corrupt;
  text = (char *)(snapshot->records + count);
  cursor = FTUN_GROUP_CACHE_HEADER_BYTES;
  for (index = 0u; index < count; index++) {
    ftun_runtime_group_record_t *record = &snapshot->records[index];
    size_t group_length = ftun_cache_load_u32(file + cursor);
    size_t member_length = ftun_cache_load_u32(file + cursor + 4u);
    uint8_t flags = file[cursor + 9u];
    record->kind = (ftun_runtime_group_kind_t)file[cursor + 8u];
    record->degraded = (flags & 1u) != 0u;
    record->health_valid = (flags & 2u) != 0u;
    record->health_success = (flags & 4u) != 0u;
    record->latency_ms = ftun_cache_load_u32(file + cursor + 12u);
    record->observed_ms = ftun_cache_load_u64(file + cursor + 16u);
    cursor += FTUN_GROUP_CACHE_RECORD_BYTES;
    record->group.data = text;
    record->group.length = group_length;
    memcpy(text, file + cursor, group_length);
    text[group_length] = '\0';
    text += group_length + 1u;
    cursor += group_length;
    record->member.data = text;
    record->member.length = member_length;
    memcpy(text, file + cursor, member_length);
    text[member_length] = '\0';
    text += member_length + 1u;
    cursor += member_length;
  }
  snapshot->reservation = reservation; reservation = NULL;
  *out = snapshot;
  snapshot = NULL;
  status = FTUN_OK;
  goto done;

corrupt:
  status = FTUN_E_STATE_CORRUPT;
done:
  free(snapshot);
  free(file);
  (void)ftun_reservation_release(&reservation);
  (void)ftun_reservation_release(&file_reservation);
  return status;
}

ftun_status_t ftun_group_cache_load(const char *path, ftun_group_cache_snapshot_t **out)
{
  return ftun_group_cache_load_budget(NULL, path, out);
}

ftun_status_t ftun_group_cache_destroy(ftun_group_cache_snapshot_t **snapshot)
{
  ftun_status_t status;
  if (snapshot == NULL) return FTUN_E_INVALID;
  if (*snapshot == NULL) return FTUN_OK;
  status = ftun_reservation_release(&(*snapshot)->reservation);
  if (status != FTUN_OK) return status;
  free(*snapshot);
  *snapshot = NULL;
  return FTUN_OK;
}

ftun_status_t ftun_group_cache_capture(ftun_core_t *core, ftun_budget_t *budget,
  uint8_t **out, size_t *out_length, ftun_reservation_t **out_reservation)
{
  const ftun_config_t *config = NULL;
  ftun_group_cache_snapshot_t snapshot;
  size_t count = 0u;
  ftun_reservation_t *records_reservation = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (out_length != NULL) *out_length = 0u;
  memset(&snapshot, 0, sizeof(snapshot));
  if (out_reservation != NULL) *out_reservation = NULL;
  if (core == NULL || budget == NULL || out == NULL || out_length == NULL || out_reservation == NULL) {
    return FTUN_E_INVALID;
  }
  status = ftun_runtime_active_config(core, &config);
  if (status != FTUN_OK) return status;
  if (!config->base.state_cache) return FTUN_E_UNSUPPORTED;
  status = ftun_runtime_group_records(core, NULL, 0u, &count);
  if (status != FTUN_E_LIMIT && status != FTUN_OK) return status;
  if (count > FTUN_GROUP_CACHE_MAX_ENTRIES) return FTUN_E_LIMIT;
  if (count != 0u) {
    status = ftun_budget_reserve(budget, count * sizeof(*snapshot.records), &records_reservation);
    if (status != FTUN_OK) return status;
    snapshot.records = (ftun_runtime_group_record_t *)calloc(
      count, sizeof(*snapshot.records));
    if (snapshot.records == NULL) {
      (void)ftun_reservation_release(&records_reservation);
      return FTUN_E_LIMIT;
    }
  }
  snapshot.record_count = count;
  status = ftun_runtime_group_records(core, snapshot.records, count, &count);
  if (status == FTUN_OK) status = ftun_group_cache_fingerprint(
    config, &snapshot.fingerprint);
  if (status == FTUN_OK) status = ftun_monotonic_now(&snapshot.saved_ms);
  if (status == FTUN_OK) {
    status = ftun_group_cache_encode_snapshot(budget, &snapshot, 0u,
      out, out_length, out_reservation);
  }
  free(snapshot.records);
  (void)ftun_reservation_release(&records_reservation);
  return status;
}

ftun_status_t ftun_group_cache_publish(ftun_budget_t *budget, const char *path,
                                        ftun_bytes_t captured)
{
  uint8_t *data;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  if (budget == NULL || path == NULL || path[0] == '\0' || captured.data == NULL ||
      captured.length < FTUN_GROUP_CACHE_HEADER_BYTES ||
      captured.length > FTUN_GROUP_CACHE_MAX_BYTES ||
      memcmp(captured.data, "FTGC", 4u) != 0 ||
      ftun_cache_load_u32(captured.data + 4u) != 1u ||
      ftun_cache_load_u32(captured.data + 28u) != 0u ||
      ftun_cache_load_u64(captured.data + 32u) !=
        ftun_cache_checksum(captured.data, captured.length)) {
    return FTUN_E_INVALID;
  }
  status = ftun_budget_reserve(budget, captured.length, &reservation);
  if (status != FTUN_OK) return status;
  data = (uint8_t *)malloc(captured.length);
  if (data == NULL) { (void)ftun_reservation_release(&reservation); return FTUN_E_LIMIT; }
  memcpy(data, captured.data, captured.length);
  ftun_cache_u32(data + 28u, ftun_cache_boot_token(budget));
  ftun_cache_u64(data + 32u, ftun_cache_checksum(data, captured.length));
  status = ftun_file_write_atomic_budget(budget, path,
    (ftun_bytes_t){data, captured.length}, 0600u, NULL, NULL);
  free(data);
  (void)ftun_reservation_release(&reservation);
  return status;
}

ftun_status_t ftun_group_cache_save(ftun_core_t *core, const char *path)
{
  uint8_t *captured = NULL;
  ftun_budget_t *budget = NULL;
  ftun_reservation_t *reservation = NULL;
  size_t length = 0u;
  ftun_status_t status;
  if (path == NULL || path[0] == '\0') return FTUN_E_INVALID;
  status = ftun_core_context_budget(core, &budget);
  if (status == FTUN_OK) status = ftun_group_cache_capture(core, budget, &captured, &length, &reservation);
  if (status == FTUN_OK) {
    status = ftun_group_cache_publish(budget, path,
      (ftun_bytes_t){captured, length});
  }
  free(captured);
  (void)ftun_reservation_release(&reservation);
  return status;
}
