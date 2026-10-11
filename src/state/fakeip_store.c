#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "fakeip_store.h"
#include "fakeip_store_internal.h"

#include "platform/file.h"
#include "util/hash.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* 需求 REQ-PERSIST-001；任务 TASK-STATE-001；目标 0.3.0；验收 TEST-STATE-001。 */

#define FTUN_FAKEIP_IDENTITY_BYTES 48u
#define FTUN_FAKEIP_LOG_HEADER_BYTES 32u
#define FTUN_FAKEIP_LOG_RECORD_BYTES 32u
#define FTUN_FAKEIP_SNAPSHOT_HEADER_BYTES 48u

struct ftun_fakeip_store {
  char *directory;
  char *reservation_path;
  char *mapping_path;
  ftun_file_lock_t *lock;
  ftun_budget_t *budget;
  ftun_worker_t *worker;
  void (*completion)(ftun_operation_t *, ftun_error_t,
                     ftun_fakeip_store_operation_t, uint64_t, uint32_t,
                     void *);
  void *completion_user;
  ftun_reservation_t *reservation;
  ftun_fakeip_store_identity_t identity;
  uint64_t sequence;
  uint32_t reserved_end;
  uint64_t pending_sequence;
  uint32_t pending_end;
  ftun_fakeip_store_operation_t pending_kind;
  ftun_operation_t *pending_operation;
  int pending;
  int halted;
  int uncertain;
};

static void ftun_store_u32(uint8_t *out, uint32_t value)
{
  out[0] = (uint8_t)(value >> 24u);
  out[1] = (uint8_t)(value >> 16u);
  out[2] = (uint8_t)(value >> 8u);
  out[3] = (uint8_t)value;
}

static uint32_t ftun_load_u32(const uint8_t *value)
{
  return ((uint32_t)value[0] << 24u) |
         ((uint32_t)value[1] << 16u) |
         ((uint32_t)value[2] << 8u) |
         (uint32_t)value[3];
}

static void ftun_store_u64(uint8_t *out, uint64_t value)
{
  size_t index;
  for (index = 0u; index < 8u; index++) {
    out[index] = (uint8_t)(value >> (56u - index * 8u));
  }
}

static uint64_t ftun_load_u64(const uint8_t *value)
{
  uint64_t result = 0u;
  size_t index;
  for (index = 0u; index < 8u; index++) {
    result = (result << 8u) | value[index];
  }
  return result;
}

static uint64_t ftun_store_checksum(const uint8_t *data, size_t length)
{
  uint64_t result = 0u;
  (void)ftun_persistent_hash(1u, (ftun_bytes_t){data, length}, &result);
  return result;
}

static int ftun_store_uuid_valid(const uint8_t uuid[FTUN_FAKEIP_UUID_BYTES])
{
  size_t index;
  unsigned int combined = 0u;
  for (index = 0u; index < FTUN_FAKEIP_UUID_BYTES; index++) combined |= uuid[index];
  return combined != 0u;
}

static int ftun_store_identity_valid(const ftun_fakeip_store_identity_t *identity)
{
  return identity != NULL && ftun_store_uuid_valid(identity->uuid) &&
         identity->first_address < identity->end_address_exclusive;
}

static ftun_status_t ftun_store_path(const char *directory, const char *name,
                                     char **out)
{
  size_t directory_length;
  size_t name_length;
  char *path;
  if (out != NULL) *out = NULL;
  if (directory == NULL || directory[0] == '\0' || name == NULL ||
      out == NULL) return FTUN_E_INVALID;
  directory_length = strlen(directory);
  name_length = strlen(name);
  if (directory_length > SIZE_MAX - name_length - 2u) return FTUN_E_LIMIT;
  path = (char *)malloc(directory_length + name_length + 2u);
  if (path == NULL) return FTUN_E_LIMIT;
  memcpy(path, directory, directory_length);
  path[directory_length] = '/';
  memcpy(path + directory_length + 1u, name, name_length + 1u);
  *out = path;
  return FTUN_OK;
}

static ftun_status_t ftun_store_read_exact(const char *path, uint8_t *data,
                                           size_t length)
{
  int descriptor;
  size_t offset = 0u;
  struct stat status;
  descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) return FTUN_E_STATE_CORRUPT;
  if (fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) ||
      status.st_size < 0 || (uint64_t)status.st_size != (uint64_t)length) {
    (void)close(descriptor);
    return FTUN_E_STATE_CORRUPT;
  }
  while (offset < length) {
    ssize_t result = read(descriptor, data + offset, length - offset);
    if (result < 0 && errno == EINTR) continue;
    if (result <= 0) {
      (void)close(descriptor);
      return FTUN_E_STATE_CORRUPT;
    }
    offset += (size_t)result;
  }
  return close(descriptor) == 0 ? FTUN_OK : FTUN_E_IO;
}

static void ftun_store_identity_encode(
  const ftun_fakeip_store_identity_t *identity,
  uint8_t data[FTUN_FAKEIP_IDENTITY_BYTES])
{
  memset(data, 0, FTUN_FAKEIP_IDENTITY_BYTES);
  memcpy(data, "FTFI", 4u);
  ftun_store_u32(data + 4u, 1u);
  memcpy(data + 8u, identity->uuid, FTUN_FAKEIP_UUID_BYTES);
  ftun_store_u32(data + 24u, identity->first_address);
  ftun_store_u32(data + 28u, identity->end_address_exclusive);
  ftun_store_u32(data + 32u, 1u);
  ftun_store_u64(data + 40u, ftun_store_checksum(data, 40u));
}

static ftun_status_t ftun_store_identity_decode(
  const uint8_t data[FTUN_FAKEIP_IDENTITY_BYTES],
  ftun_fakeip_store_identity_t *out)
{
  if (memcmp(data, "FTFI", 4u) != 0 || ftun_load_u32(data + 4u) != 1u ||
      ftun_load_u32(data + 32u) != 1u || ftun_load_u32(data + 36u) != 0u ||
      ftun_load_u64(data + 40u) != ftun_store_checksum(data, 40u)) {
    return FTUN_E_STATE_CORRUPT;
  }
  memset(out, 0, sizeof(*out));
  memcpy(out->uuid, data + 8u, FTUN_FAKEIP_UUID_BYTES);
  out->first_address = ftun_load_u32(data + 24u);
  out->end_address_exclusive = ftun_load_u32(data + 28u);
  return ftun_store_identity_valid(out) ? FTUN_OK : FTUN_E_STATE_CORRUPT;
}

static void ftun_store_log_header_encode(
  const ftun_fakeip_store_identity_t *identity,
  uint8_t data[FTUN_FAKEIP_LOG_HEADER_BYTES])
{
  memset(data, 0, FTUN_FAKEIP_LOG_HEADER_BYTES);
  memcpy(data, "FTRL", 4u);
  ftun_store_u32(data + 4u, 1u);
  memcpy(data + 8u, identity->uuid, FTUN_FAKEIP_UUID_BYTES);
  ftun_store_u64(data + 24u, ftun_store_checksum(data, 24u));
}

static void ftun_store_snapshot_empty_encode(
  const ftun_fakeip_store_identity_t *identity,
  uint8_t data[FTUN_FAKEIP_SNAPSHOT_HEADER_BYTES])
{
  memset(data, 0, FTUN_FAKEIP_SNAPSHOT_HEADER_BYTES);
  memcpy(data, "FTMP", 4u);
  ftun_store_u32(data + 4u, 1u);
  memcpy(data + 8u, identity->uuid, FTUN_FAKEIP_UUID_BYTES);
  ftun_store_u64(data + 24u, 0u);
  ftun_store_u32(data + 32u, 0u);
  ftun_store_u64(data + 40u, ftun_store_checksum(data, 40u));
}

static ftun_status_t ftun_store_sync_parent(const char *path)
{
  const char *slash = strrchr(path, '/');
  char *parent;
  size_t length;
  int descriptor;
  ftun_status_t result = FTUN_OK;
  if (slash == NULL) {
    parent = (char *)malloc(2u);
    if (parent == NULL) return FTUN_E_LIMIT;
    memcpy(parent, ".", 2u);
  } else {
    length = slash == path ? 1u : (size_t)(slash - path);
    parent = (char *)malloc(length + 1u);
    if (parent == NULL) return FTUN_E_LIMIT;
    memcpy(parent, path, length);
    parent[length] = '\0';
  }
  descriptor = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0 || fsync(descriptor) != 0) result = FTUN_E_IO;
  if (descriptor >= 0 && close(descriptor) != 0) result = FTUN_E_IO;
  free(parent);
  return result;
}

ftun_status_t ftun_fakeip_store_initialize(
  const char *directory, const ftun_fakeip_store_identity_t *identity)
{
  static const uint8_t empty[1] = {0u};
  char *identity_path = NULL;
  char *reservation_path = NULL;
  char *mapping_path = NULL;
  char *lock_path = NULL;
  uint8_t identity_data[FTUN_FAKEIP_IDENTITY_BYTES];
  uint8_t log_data[FTUN_FAKEIP_LOG_HEADER_BYTES];
  uint8_t snapshot_data[FTUN_FAKEIP_SNAPSHOT_HEADER_BYTES];
  ftun_status_t status = FTUN_OK;
  int created = 0;
  if (directory == NULL || directory[0] == '\0' ||
      !ftun_store_identity_valid(identity)) return FTUN_E_INVALID;
  if (mkdir(directory, 0700) != 0) return errno == EEXIST ? FTUN_E_INVALID : FTUN_E_IO;
  created = 1;
  status = ftun_store_path(directory, "identity", &identity_path);
  if (status != FTUN_OK) goto done;
  status = ftun_store_path(directory, "reservations", &reservation_path);
  if (status != FTUN_OK) goto done;
  status = ftun_store_path(directory, "mappings", &mapping_path);
  if (status != FTUN_OK) goto done;
  status = ftun_store_path(directory, "lock", &lock_path);
  if (status != FTUN_OK) goto done;
  ftun_store_identity_encode(identity, identity_data);
  ftun_store_log_header_encode(identity, log_data);
  ftun_store_snapshot_empty_encode(identity, snapshot_data);
  status = ftun_file_write_atomic(identity_path,
    (ftun_bytes_t){identity_data, sizeof(identity_data)}, 0600u);
  if (status != FTUN_OK) goto done;
  status = ftun_file_write_atomic(reservation_path,
    (ftun_bytes_t){log_data, sizeof(log_data)}, 0600u);
  if (status != FTUN_OK) goto done;
  status = ftun_file_write_atomic(mapping_path,
    (ftun_bytes_t){snapshot_data, sizeof(snapshot_data)}, 0600u);
  if (status != FTUN_OK) goto done;
  status = ftun_file_write_atomic(lock_path,
    (ftun_bytes_t){empty, 0u}, 0600u);
  if (status != FTUN_OK) goto done;
  status = ftun_store_sync_parent(directory);

done:
  if (status != FTUN_OK && created) {
    if (identity_path != NULL) (void)unlink(identity_path);
    if (reservation_path != NULL) (void)unlink(reservation_path);
    if (mapping_path != NULL) (void)unlink(mapping_path);
    if (lock_path != NULL) (void)unlink(lock_path);
    (void)rmdir(directory);
  }
  free(identity_path);
  free(reservation_path);
  free(mapping_path);
  free(lock_path);
  return status;
}

static ftun_status_t ftun_store_read_identity(
  const char *path, ftun_fakeip_store_identity_t *out)
{
  uint8_t data[FTUN_FAKEIP_IDENTITY_BYTES];
  ftun_status_t status = ftun_store_read_exact(path, data, sizeof(data));
  return status == FTUN_OK ? ftun_store_identity_decode(data, out) : status;
}

static ftun_status_t ftun_store_read_log(
  const char *path, const ftun_fakeip_store_identity_t *identity,
  uint64_t *out_sequence, uint32_t *out_end)
{
  uint8_t header[FTUN_FAKEIP_LOG_HEADER_BYTES];
  uint8_t record[FTUN_FAKEIP_LOG_RECORD_BYTES];
  struct stat info;
  uint64_t sequence = 0u;
  uint32_t end = identity->first_address;
  int descriptor;
  off_t offset;
  descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) return FTUN_E_STATE_CORRUPT;
  if (fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode) ||
      info.st_size < (off_t)sizeof(header) ||
      ((uint64_t)info.st_size - sizeof(header)) % sizeof(record) != 0u) {
    (void)close(descriptor);
    return FTUN_E_STATE_CORRUPT;
  }
  {
    size_t read_bytes = 0u;
    while (read_bytes < sizeof(header)) {
      ssize_t result = read(descriptor, header + read_bytes,
                            sizeof(header) - read_bytes);
      if (result < 0 && errno == EINTR) continue;
      if (result <= 0) break;
      read_bytes += (size_t)result;
    }
    if (read_bytes != sizeof(header)) {
      (void)close(descriptor);
      return FTUN_E_STATE_CORRUPT;
    }
  }
  if (
      memcmp(header, "FTRL", 4u) != 0 || ftun_load_u32(header + 4u) != 1u ||
      memcmp(header + 8u, identity->uuid, FTUN_FAKEIP_UUID_BYTES) != 0 ||
      ftun_load_u64(header + 24u) != ftun_store_checksum(header, 24u)) {
    (void)close(descriptor);
    return FTUN_E_STATE_CORRUPT;
  }
  for (offset = (off_t)sizeof(header); offset < info.st_size;
       offset += (off_t)sizeof(record)) {
    uint64_t next_sequence;
    uint32_t previous;
    uint32_t next_end;
    size_t read_bytes = 0u;
    while (read_bytes < sizeof(record)) {
      ssize_t result = read(descriptor, record + read_bytes,
                            sizeof(record) - read_bytes);
      if (result < 0 && errno == EINTR) continue;
      if (result <= 0) break;
      read_bytes += (size_t)result;
    }
    if (read_bytes != sizeof(record) ||
        memcmp(record, "FTRR", 4u) != 0 ||
        ftun_load_u32(record + 4u) != 1u ||
        ftun_load_u64(record + 24u) != ftun_store_checksum(record, 24u)) {
      (void)close(descriptor);
      return FTUN_E_STATE_CORRUPT;
    }
    next_sequence = ftun_load_u64(record + 8u);
    previous = ftun_load_u32(record + 16u);
    next_end = ftun_load_u32(record + 20u);
    if (next_sequence != sequence + 1u || previous != end ||
        next_end <= previous || next_end > identity->end_address_exclusive) {
      (void)close(descriptor);
      return FTUN_E_STATE_CORRUPT;
    }
    sequence = next_sequence;
    end = next_end;
  }
  if (close(descriptor) != 0) return FTUN_E_IO;
  *out_sequence = sequence;
  *out_end = end;
  return FTUN_OK;
}

static uint16_t ftun_load_u16(const uint8_t *value)
{
  return (uint16_t)(((uint16_t)value[0] << 8u) | (uint16_t)value[1]);
}

static uint64_t ftun_store_snapshot_checksum(const uint8_t *data,
                                             size_t length)
{
  uint64_t value = UINT64_C(1469598103934665603);
  static const uint8_t prefix[] = {'F', 'T', 'H', 1u};
  size_t index;
  for (index = 0u; index < sizeof(prefix); index++) {
    value ^= prefix[index];
    value *= UINT64_C(1099511628211);
  }
  for (index = 0u; index < 40u; index++) {
    value ^= data[index];
    value *= UINT64_C(1099511628211);
  }
  for (index = FTUN_FAKEIP_SNAPSHOT_HEADER_BYTES; index < length; index++) {
    value ^= data[index];
    value *= UINT64_C(1099511628211);
  }
  return value;
}

static int ftun_store_domain_valid(const uint8_t *domain, size_t length)
{
  size_t start = 0u;
  size_t index;
  if (domain == NULL || length == 0u || length > 253u ||
      domain[length - 1u] == (uint8_t)'.' ||
      memchr(domain, '\0', length) != NULL) return 0;
  for (index = 0u; index <= length; index++) {
    if (index == length || domain[index] == (uint8_t)'.') {
      size_t label_length = index - start;
      size_t cursor;
      if (label_length == 0u || label_length > 63u ||
          domain[start] == (uint8_t)'-' ||
          domain[index - 1u] == (uint8_t)'-') return 0;
      for (cursor = start; cursor < index; cursor++) {
        uint8_t value = domain[cursor];
        if (!((value >= (uint8_t)'a' && value <= (uint8_t)'z') ||
              (value >= (uint8_t)'0' && value <= (uint8_t)'9') ||
              value == (uint8_t)'-')) return 0;
      }
      start = index + 1u;
    }
  }
  return 1;
}

static ftun_status_t ftun_store_snapshot_validate(
  const char *path, const ftun_fakeip_store_identity_t *identity,
  uint64_t durable_sequence, uint32_t reserved_end, ftun_budget_t *budget)
{
  uint8_t *data = NULL;
  ftun_reservation_t *file_reservation = NULL;
  ftun_index_t *domains = NULL;
  ftun_index_t *addresses = NULL;
  struct stat info;
  size_t maximum;
  size_t length;
  size_t offset = 0u;
  size_t cursor;
  size_t index;
  uint32_t count;
  int descriptor;
  ftun_status_t status = FTUN_E_STATE_CORRUPT;
  if (reserved_end < identity->first_address) return FTUN_E_STATE_CORRUPT;
#if SIZE_MAX < UINT64_MAX
  if ((size_t)(reserved_end - identity->first_address) >
      (SIZE_MAX - FTUN_FAKEIP_SNAPSHOT_HEADER_BYTES) / (8u + 253u)) {
    return FTUN_E_LIMIT;
  }
#endif
  maximum = FTUN_FAKEIP_SNAPSHOT_HEADER_BYTES +
    (size_t)(reserved_end - identity->first_address) * (8u + 253u);
  descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) return FTUN_E_STATE_CORRUPT;
  if (fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode) ||
      info.st_size < (off_t)FTUN_FAKEIP_SNAPSHOT_HEADER_BYTES ||
      (uint64_t)info.st_size > (uint64_t)maximum) goto done;
  length = (size_t)info.st_size;
  status = ftun_budget_reserve(budget, length, &file_reservation);
  if (status != FTUN_OK) goto done;
  data = (uint8_t *)malloc(length);
  if (data == NULL) {
    status = FTUN_E_LIMIT;
    goto done;
  }
  while (offset < length) {
    ssize_t result = read(descriptor, data + offset, length - offset);
    if (result < 0 && errno == EINTR) continue;
    if (result <= 0) goto corrupt;
    offset += (size_t)result;
  }
  if (memcmp(data, "FTMP", 4u) != 0 || ftun_load_u32(data + 4u) != 1u ||
      memcmp(data + 8u, identity->uuid, FTUN_FAKEIP_UUID_BYTES) != 0 ||
      ftun_load_u64(data + 24u) > durable_sequence ||
      ftun_load_u32(data + 36u) != 0u ||
      ftun_load_u64(data + 40u) !=
        ftun_store_snapshot_checksum(data, length)) goto corrupt;
  count = ftun_load_u32(data + 32u);
  if (count > reserved_end - identity->first_address) goto corrupt;
  if (count != 0u) {
    status = ftun_index_create(budget, count < 8u ? count : 8u, count,
                               NULL, NULL, &domains);
    if (status != FTUN_OK) goto done;
    status = ftun_index_create(budget, count < 8u ? count : 8u, count,
                               NULL, NULL, &addresses);
    if (status != FTUN_OK) goto done;
  }
  cursor = FTUN_FAKEIP_SNAPSHOT_HEADER_BYTES;
  for (index = 0u; index < count; index++) {
    uint16_t domain_length;
    uint32_t ignored;
    if (cursor > length - 8u) goto corrupt;
    domain_length = ftun_load_u16(data + cursor + 4u);
    if (domain_length == 0u || domain_length > 253u ||
        (size_t)domain_length > length - cursor - 8u ||
        ftun_load_u32(data + cursor) < identity->first_address ||
        ftun_load_u32(data + cursor) >= reserved_end ||
        !ftun_store_domain_valid(data + cursor + 8u, domain_length)) {
      goto corrupt;
    }
    if (ftun_hash_lookup(addresses,
          (ftun_bytes_t){data + cursor, 4u}, &ignored) == FTUN_OK ||
        ftun_hash_lookup(domains,
          (ftun_bytes_t){data + cursor + 8u, domain_length}, &ignored) ==
          FTUN_OK) goto corrupt;
    status = ftun_index_insert(addresses,
      (ftun_bytes_t){data + cursor, 4u}, (uint32_t)index);
    if (status != FTUN_OK) goto done;
    status = ftun_index_insert(domains,
      (ftun_bytes_t){data + cursor + 8u, domain_length}, (uint32_t)index);
    if (status != FTUN_OK) goto done;
    cursor += 8u + domain_length;
  }
  if (cursor != length) goto corrupt;
  status = FTUN_OK;
  goto done;

corrupt:
  status = FTUN_E_STATE_CORRUPT;
done:
  if (descriptor >= 0 && close(descriptor) != 0 && status == FTUN_OK) {
    status = FTUN_E_IO;
  }
  free(data);
  if (ftun_index_destroy(&addresses) != FTUN_OK && status == FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
  }
  if (ftun_index_destroy(&domains) != FTUN_OK && status == FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
  }
  if (ftun_reservation_release(&file_reservation) != FTUN_OK &&
      status == FTUN_OK) status = FTUN_E_STATE_CORRUPT;
  return status;
}

ftun_status_t ftun_fakeip_store_open(const ftun_fakeip_store_options_t *options,
                                     ftun_fakeip_store_t **out)
{
  ftun_fakeip_store_t *store = NULL;
  char *identity_path = NULL;
  char *lock_path = NULL;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  size_t directory_length;
  if (out != NULL) *out = NULL;
  if (options == NULL || options->directory == NULL ||
      options->directory[0] == '\0' || options->budget == NULL ||
      options->worker == NULL || options->completion == NULL || out == NULL) {
    return FTUN_E_INVALID;
  }
  directory_length = strlen(options->directory);
  if (directory_length > SIZE_MAX - sizeof(*store) - 1u) return FTUN_E_LIMIT;
  status = ftun_budget_reserve(options->budget,
                               sizeof(*store) + directory_length + 1u,
                               &reservation);
  if (status != FTUN_OK) return status;
  store = (ftun_fakeip_store_t *)calloc(1u, sizeof(*store));
  if (store == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  store->directory = (char *)malloc(directory_length + 1u);
  if (store->directory == NULL) {
    status = FTUN_E_LIMIT;
    goto fail;
  }
  memcpy(store->directory, options->directory, directory_length + 1u);
  status = ftun_store_path(store->directory, "identity", &identity_path);
  if (status != FTUN_OK) goto fail;
  status = ftun_store_path(store->directory, "reservations",
                           &store->reservation_path);
  if (status != FTUN_OK) goto fail;
  status = ftun_store_path(store->directory, "mappings", &store->mapping_path);
  if (status != FTUN_OK) goto fail;
  status = ftun_store_path(store->directory, "lock", &lock_path);
  if (status != FTUN_OK) goto fail;
  status = ftun_file_lock_acquire(lock_path, &store->lock);
  if (status != FTUN_OK) goto fail;
  status = ftun_store_read_identity(identity_path, &store->identity);
  if (status != FTUN_OK) goto fail;
  status = ftun_store_read_log(store->reservation_path, &store->identity,
                               &store->sequence, &store->reserved_end);
  if (status != FTUN_OK) goto fail;
  status = ftun_store_snapshot_validate(store->mapping_path, &store->identity,
                                        store->sequence, store->reserved_end,
                                        options->budget);
  if (status != FTUN_OK) goto fail;
  store->budget = options->budget;
  store->worker = options->worker;
  store->completion = options->completion;
  store->completion_user = options->user;
  store->reservation = reservation;
  free(identity_path);
  free(lock_path);
  *out = store;
  return FTUN_OK;

fail:
  (void)ftun_file_lock_release(&store->lock);
  free(store->mapping_path);
  free(store->reservation_path);
  free(store->directory);
  free(store);
  free(identity_path);
  free(lock_path);
  (void)ftun_reservation_release(&reservation);
  return status;
}

ftun_status_t ftun_fakeip_store_get_info(const ftun_fakeip_store_t *store,
                                         ftun_fakeip_store_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (store == NULL || out == NULL) return FTUN_E_INVALID;
  out->identity = store->identity;
  out->sequence = store->sequence;
  out->reserved_end = store->reserved_end;
  out->halted = store->halted != 0;
  out->pending = store->pending != 0;
  return FTUN_OK;
}

static void ftun_store_log_record_encode(uint64_t sequence, uint32_t previous,
                                         uint32_t end,
                                         uint8_t data[FTUN_FAKEIP_LOG_RECORD_BYTES])
{
  memset(data, 0, FTUN_FAKEIP_LOG_RECORD_BYTES);
  memcpy(data, "FTRR", 4u);
  ftun_store_u32(data + 4u, 1u);
  ftun_store_u64(data + 8u, sequence);
  ftun_store_u32(data + 16u, previous);
  ftun_store_u32(data + 20u, end);
  ftun_store_u64(data + 24u, ftun_store_checksum(data, 24u));
}

static ftun_status_t ftun_store_append_execute(ftun_bytes_t input,
                                               uint8_t *result,
                                               size_t result_capacity,
                                               size_t *out_result_size)
{
  uint32_t path_length;
  const char *path;
  const uint8_t *record;
  int descriptor;
  size_t offset = 0u;
  struct stat info;
  (void)result;
  if (out_result_size != NULL) *out_result_size = 0u;
  if (input.data == NULL || input.length < 4u + FTUN_FAKEIP_LOG_RECORD_BYTES ||
      result_capacity != 0u || out_result_size == NULL) return FTUN_E_INVALID;
  path_length = ftun_load_u32(input.data);
  if (path_length == 0u || (size_t)path_length > input.length - 4u ||
      input.length != 4u + (size_t)path_length + FTUN_FAKEIP_LOG_RECORD_BYTES ||
      input.data[4u + path_length - 1u] != '\0') return FTUN_E_INVALID;
  path = (const char *)(input.data + 4u);
  record = input.data + 4u + path_length;
  descriptor = open(path, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) return FTUN_E_IO;
  if (fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode)) {
    (void)close(descriptor);
    return FTUN_E_STATE_CORRUPT;
  }
  while (offset < FTUN_FAKEIP_LOG_RECORD_BYTES) {
    ssize_t written = write(descriptor, record + offset,
                            FTUN_FAKEIP_LOG_RECORD_BYTES - offset);
    if (written < 0 && errno == EINTR) continue;
    if (written <= 0) {
      int error_code = errno;
      (void)close(descriptor);
      return error_code == ENOSPC || error_code == EDQUOT ?
        FTUN_E_LIMIT : FTUN_E_IO;
    }
    offset += (size_t)written;
  }
  if (fdatasync(descriptor) != 0) {
    (void)close(descriptor);
    return FTUN_E_IO;
  }
  if (close(descriptor) != 0) return FTUN_E_IO;
  return FTUN_OK;
}

static void ftun_store_reserve_done(ftun_operation_t *operation,
                                    ftun_error_t error, ftun_bytes_t result,
                                    void *user)
{
  ftun_fakeip_store_t *store = (ftun_fakeip_store_t *)user;
  (void)result;
  if (store->pending_operation != operation || !store->pending ||
      store->pending_kind != FTUN_FAKEIP_STORE_RESERVATION) {
    error.status = FTUN_E_STATE_CORRUPT;
  }
  store->pending_operation = NULL;
  store->pending = 0;
  if (error.status == FTUN_OK) {
    store->sequence = store->pending_sequence;
    store->reserved_end = store->pending_end;
  } else {
    store->halted = 1;
    if (error.status == FTUN_E_CANCELLED) store->uncertain = 1;
  }
  store->completion(operation, error, FTUN_FAKEIP_STORE_RESERVATION,
                    store->sequence, store->reserved_end,
                    store->completion_user);
}

ftun_status_t ftun_fakeip_store_reserve(ftun_fakeip_store_t *store,
                                        uint32_t end_exclusive,
                                        ftun_operation_t **out)
{
  ftun_worker_job_t job;
  uint8_t record[FTUN_FAKEIP_LOG_RECORD_BYTES];
  uint8_t *input;
  size_t path_length;
  size_t input_length;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (store == NULL || out == NULL || store->worker == NULL) {
    return FTUN_E_INVALID;
  }
  if (store->halted) return FTUN_E_STATE_CORRUPT;
  if (store->pending) return FTUN_E_AGAIN;
  if (end_exclusive <= store->reserved_end ||
      end_exclusive > store->identity.end_address_exclusive ||
      store->sequence == UINT64_MAX) return FTUN_E_INVALID;
  path_length = strlen(store->reservation_path) + 1u;
  if (path_length > UINT32_MAX ||
      path_length > SIZE_MAX - 4u - sizeof(record)) return FTUN_E_LIMIT;
  input_length = 4u + path_length + sizeof(record);
  input = (uint8_t *)malloc(input_length);
  if (input == NULL) return FTUN_E_LIMIT;
  ftun_store_u32(input, (uint32_t)path_length);
  memcpy(input + 4u, store->reservation_path, path_length);
  ftun_store_log_record_encode(store->sequence + 1u, store->reserved_end,
                               end_exclusive, record);
  memcpy(input + 4u + path_length, record, sizeof(record));
  memset(&job, 0, sizeof(job));
  job.execute = ftun_store_append_execute;
  job.input = (ftun_bytes_t){input, input_length};
  status = ftun_worker_submit(store->worker, &job, ftun_store_reserve_done,
                              store, out);
  free(input);
  if (status != FTUN_OK) return status;
  store->pending_sequence = store->sequence + 1u;
  store->pending_end = end_exclusive;
  store->pending_kind = FTUN_FAKEIP_STORE_RESERVATION;
  store->pending_operation = *out;
  store->pending = 1;
  return FTUN_OK;
}

static ftun_status_t ftun_store_replace_execute(ftun_bytes_t input,
                                                uint8_t *result,
                                                size_t result_capacity,
                                                size_t *out_result_size)
{
  uint32_t path_length;
  const char *path;
  ftun_bytes_t contents;
  (void)result;
  if (out_result_size != NULL) *out_result_size = 0u;
  if (input.data == NULL || input.length < 5u || result_capacity != 0u ||
      out_result_size == NULL) return FTUN_E_INVALID;
  path_length = ftun_load_u32(input.data);
  if (path_length == 0u || (size_t)path_length > input.length - 4u ||
      input.data[4u + path_length - 1u] != '\0') return FTUN_E_INVALID;
  path = (const char *)(input.data + 4u);
  contents.data = input.data + 4u + path_length;
  contents.length = input.length - 4u - path_length;
  return ftun_file_write_atomic(path, contents, 0600u);
}

static void ftun_store_snapshot_done(ftun_operation_t *operation,
                                     ftun_error_t error, ftun_bytes_t result,
                                     void *user)
{
  ftun_fakeip_store_t *store = (ftun_fakeip_store_t *)user;
  (void)result;
  if (store->pending_operation != operation || !store->pending ||
      store->pending_kind != FTUN_FAKEIP_STORE_SNAPSHOT) {
    error.status = FTUN_E_STATE_CORRUPT;
  }
  store->pending_operation = NULL;
  store->pending = 0;
  if (error.status == FTUN_E_CANCELLED) store->uncertain = 1;
  store->completion(operation, error, FTUN_FAKEIP_STORE_SNAPSHOT,
                    store->pending_sequence, store->reserved_end,
                    store->completion_user);
}

ftun_status_t ftun_fakeip_store_snapshot_state(
  ftun_fakeip_store_t *store, const char **path, ftun_budget_t **budget,
  ftun_fakeip_store_info_t *info)
{
  if (path != NULL) *path = NULL;
  if (budget != NULL) *budget = NULL;
  if (store == NULL || path == NULL || budget == NULL || info == NULL) {
    return FTUN_E_INVALID;
  }
  if (ftun_fakeip_store_get_info(store, info) != FTUN_OK) {
    return FTUN_E_STATE_CORRUPT;
  }
  *path = store->mapping_path;
  *budget = store->budget;
  return FTUN_OK;
}

ftun_status_t ftun_fakeip_store_submit_snapshot(
  ftun_fakeip_store_t *store, ftun_bytes_t contents, uint64_t sequence,
  ftun_operation_t **out)
{
  ftun_worker_job_t job;
  uint8_t *input;
  size_t path_length;
  size_t input_length;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (store == NULL || out == NULL || contents.data == NULL ||
      contents.length == 0u || sequence > store->sequence) {
    return FTUN_E_INVALID;
  }
  if (store->pending) return FTUN_E_AGAIN;
  path_length = strlen(store->mapping_path) + 1u;
  if (path_length > UINT32_MAX || contents.length > SIZE_MAX - path_length - 4u) {
    return FTUN_E_LIMIT;
  }
  input_length = 4u + path_length + contents.length;
  input = (uint8_t *)malloc(input_length);
  if (input == NULL) return FTUN_E_LIMIT;
  ftun_store_u32(input, (uint32_t)path_length);
  memcpy(input + 4u, store->mapping_path, path_length);
  memcpy(input + 4u + path_length, contents.data, contents.length);
  memset(&job, 0, sizeof(job));
  job.execute = ftun_store_replace_execute;
  job.input = (ftun_bytes_t){input, input_length};
  status = ftun_worker_submit(store->worker, &job, ftun_store_snapshot_done,
                              store, out);
  free(input);
  if (status != FTUN_OK) return status;
  store->pending_sequence = sequence;
  store->pending_end = store->reserved_end;
  store->pending_kind = FTUN_FAKEIP_STORE_SNAPSHOT;
  store->pending_operation = *out;
  store->pending = 1;
  return FTUN_OK;
}

ftun_status_t ftun_fakeip_store_destroy(ftun_fakeip_store_t **store)
{
  ftun_fakeip_store_t *owned;
  ftun_worker_usage_t usage;
  ftun_reservation_t *reservation;
  ftun_status_t status;
  if (store == NULL) return FTUN_E_INVALID;
  owned = *store;
  if (owned == NULL) return FTUN_OK;
  if (owned->pending) return FTUN_E_AGAIN;
  if (owned->uncertain) {
    status = ftun_worker_get_usage(owned->worker, &usage);
    if (status != FTUN_OK) return status;
    if (usage.tasks != 0u) return FTUN_E_AGAIN;
  }
  status = ftun_file_lock_release(&owned->lock);
  if (status != FTUN_OK) return status;
  reservation = owned->reservation;
  free(owned->mapping_path);
  free(owned->reservation_path);
  free(owned->directory);
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *store = NULL;
  return ftun_reservation_release(&reservation);
}
