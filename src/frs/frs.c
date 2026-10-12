#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "frs.h"

/* TASK-FRS-001 / TEST-FRS-001：只读 FRS 视图与集合绑定，目标 0.4.0。 */

#include "core/budget.h"
#include "core/runtime.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

struct ftun_frs_view {
  const uint8_t *file;
  uint8_t *owned;
  size_t file_bytes;
  size_t reference_count;
  ftun_frs_storage_t storage;
  ftun_frs_layout_t layout;
  ftun_reservation_t *reservation;
};

struct ftun_frs_set {
  ftun_frs_view_t *view;
  uint32_t set_id;
  ftun_frs_set_kind_t kind;
};

static int ftun_frs_permanent_accounted(size_t file_bytes,
                                        size_t section_count,
                                        size_t *out)
{
  size_t section_bytes;
  if (out == NULL || section_count > SIZE_MAX / sizeof(ftun_frs_section_layout_t)) {
    return 0;
  }
  section_bytes = section_count * sizeof(ftun_frs_section_layout_t);
  if (file_bytes > SIZE_MAX - sizeof(ftun_frs_view_t) ||
      section_bytes > SIZE_MAX - sizeof(ftun_frs_view_t) - file_bytes) return 0;
  *out = sizeof(ftun_frs_view_t) + file_bytes + section_bytes;
  return 1;
}

static int ftun_frs_max_accounted(size_t file_bytes, size_t *out)
{
  return ftun_frs_permanent_accounted(
    file_bytes, file_bytes / FTUN_FRS_DIRECTORY_ENTRY_BYTES, out);
}

static ftun_status_t ftun_frs_view_create(const uint8_t *bytes, size_t length,
                                          uint8_t *owned,
                                          ftun_frs_storage_t storage,
                                          ftun_reservation_t *reservation,
                                          ftun_frs_view_t **out)
{
  ftun_frs_layout_t layout;
  ftun_frs_view_t *view;
  ftun_bytes_t file;
  ftun_status_t status;
  memset(&layout, 0, sizeof(layout));
  file.data = bytes;
  file.length = length;
  status = ftun_frs_format_validate(file, &layout);
  if (status != FTUN_OK) return status;
  view = (ftun_frs_view_t *)calloc(1u, sizeof(*view));
  if (view == NULL) {
    ftun_frs_layout_clear(&layout);
    return FTUN_E_LIMIT;
  }
  view->file = bytes;
  view->owned = owned;
  view->file_bytes = length;
  view->reference_count = 1u;
  view->storage = storage;
  view->layout = layout;
  view->reservation = reservation;
  *out = view;
  return FTUN_OK;
}

static ftun_status_t ftun_frs_open_bytes_internal(
  ftun_budget_t *budget, ftun_bytes_t file, ftun_frs_view_t **out)
{
  uint8_t *copy;
  ftun_reservation_t *reservation = NULL;
  ftun_reservation_t *scratch_reservation = NULL;
  size_t accounted;
  size_t scratch;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (out == NULL || file.data == NULL || file.length < FTUN_FRS_HEADER_BYTES) {
    return FTUN_E_INVALID;
  }
  if (budget != NULL) {
    if (!ftun_frs_max_accounted(file.length, &accounted)) return FTUN_E_LIMIT;
    /* 格式校验器的最大并发临时集合是 DFS 颜色与栈，小于文件长度。 */
    scratch = file.length;
    status = ftun_budget_reserve(budget, accounted, &reservation);
    if (status == FTUN_OK) {
      status = ftun_budget_reserve(budget, scratch, &scratch_reservation);
    }
    if (status != FTUN_OK) {
      (void)ftun_reservation_release(&reservation);
      return status;
    }
  }
  copy = (uint8_t *)malloc(file.length);
  if (copy == NULL) {
    (void)ftun_reservation_release(&scratch_reservation);
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  memcpy(copy, file.data, file.length);
  status = ftun_frs_view_create(copy, file.length, copy,
                                FTUN_FRS_STORAGE_MEMORY, reservation, out);
  if (ftun_reservation_release(&scratch_reservation) != FTUN_OK &&
      status == FTUN_OK) status = FTUN_E_STATE_CORRUPT;
  if (status != FTUN_OK) {
    if (out != NULL && *out != NULL) {
      (void)ftun_frs_view_release(out);
      copy = NULL;
      reservation = NULL;
    }
    free(copy);
    (void)ftun_reservation_release(&reservation);
  }
  return status;
}

ftun_status_t ftun_frs_open_bytes(ftun_bytes_t file, ftun_frs_view_t **out)
{
  return ftun_frs_open_bytes_internal(NULL, file, out);
}

ftun_status_t ftun_frs_open_bytes_budget(ftun_budget_t *budget,
                                         ftun_bytes_t file,
                                         ftun_frs_view_t **out)
{
  if (budget == NULL) {
    if (out != NULL) *out = NULL;
    return FTUN_E_INVALID;
  }
  return ftun_frs_open_bytes_internal(budget, file, out);
}

ftun_status_t ftun_frs_view_bind_budget(ftun_frs_view_t *view,
                                        ftun_budget_t *budget)
{
  ftun_reservation_t *reservation = NULL;
  size_t accounted;
  ftun_status_t status;
  if (view == NULL || budget == NULL || view->reservation != NULL ||
      !ftun_frs_permanent_accounted(view->file_bytes,
                                    view->layout.section_count,
                                    &accounted)) return FTUN_E_INVALID;
  status = ftun_budget_reserve(budget, accounted, &reservation);
  if (status != FTUN_OK) return status;
  view->reservation = reservation;
  return FTUN_OK;
}

static ftun_status_t ftun_frs_read_all(int descriptor, uint8_t *data,
                                       size_t length)
{
  size_t offset = 0u;
  while (offset < length) {
    ssize_t result = read(descriptor, data + offset, length - offset);
    if (result < 0 && errno == EINTR) continue;
    if (result <= 0) return FTUN_E_IO;
    offset += (size_t)result;
  }
  return FTUN_OK;
}

ftun_status_t ftun_frs_open_mode(ftun_core_t *core, const char *path,
                                 ftun_frs_open_mode_t mode,
                                 ftun_frs_view_t **out)
{
  ftun_budget_t *budget = NULL;
  ftun_reservation_t *reservation = NULL;
  struct stat info;
  const uint8_t *mapped = MAP_FAILED;
  uint8_t *owned = NULL;
  size_t file_bytes;
  size_t accounted;
  size_t scratch;
  ftun_reservation_t *scratch_reservation = NULL;
  int descriptor = -1;
  ftun_frs_storage_t storage;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (core == NULL || path == NULL || path[0] == '\0' || out == NULL ||
      (mode != FTUN_FRS_OPEN_AUTO && mode != FTUN_FRS_OPEN_READ)) {
    return FTUN_E_INVALID;
  }
  descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) return errno == ENOENT ? FTUN_E_EOF : FTUN_E_IO;
  if (fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode) ||
      info.st_size < (off_t)FTUN_FRS_HEADER_BYTES ||
      (uintmax_t)info.st_size > (uintmax_t)SIZE_MAX) {
    (void)close(descriptor);
    return FTUN_E_PROTOCOL;
  }
  file_bytes = (size_t)info.st_size;
  if (!ftun_frs_max_accounted(file_bytes, &accounted)) {
    (void)close(descriptor);
    return FTUN_E_LIMIT;
  }
  scratch = file_bytes;
  status = ftun_runtime_manager_budget(core, &budget);
  if (status == FTUN_OK) status = ftun_budget_reserve(budget, accounted,
                                                      &reservation);
  if (status == FTUN_OK) status = ftun_budget_reserve(
    budget, scratch, &scratch_reservation);
  if (status != FTUN_OK) {
    (void)close(descriptor);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  if (mode == FTUN_FRS_OPEN_AUTO) {
    mapped = (const uint8_t *)mmap(NULL, file_bytes, PROT_READ, MAP_PRIVATE,
                                   descriptor, 0);
  }
  if (mapped != MAP_FAILED) {
    storage = FTUN_FRS_STORAGE_MMAP;
  } else {
    owned = (uint8_t *)malloc(file_bytes);
    if (owned == NULL) {
      status = FTUN_E_LIMIT;
      goto fail;
    }
    if (lseek(descriptor, 0, SEEK_SET) < 0) {
      status = FTUN_E_IO;
      goto fail;
    }
    status = ftun_frs_read_all(descriptor, owned, file_bytes);
    if (status != FTUN_OK) goto fail;
    mapped = owned;
    storage = FTUN_FRS_STORAGE_READ;
  }
  if (close(descriptor) != 0) {
    descriptor = -1;
    status = FTUN_E_IO;
    goto fail;
  }
  descriptor = -1;
  status = ftun_frs_view_create(mapped, file_bytes, owned, storage,
                                reservation, out);
  if (ftun_reservation_release(&scratch_reservation) != FTUN_OK &&
      status == FTUN_OK) status = FTUN_E_STATE_CORRUPT;
  if (status != FTUN_OK) {
    if (*out != NULL) {
      (void)ftun_frs_view_release(out);
      mapped = MAP_FAILED;
      owned = NULL;
      reservation = NULL;
    }
    goto fail;
  }
  return FTUN_OK;

fail:
  if (descriptor >= 0) (void)close(descriptor);
  if (mapped != MAP_FAILED && owned == NULL) (void)munmap((void *)mapped, file_bytes);
  free(owned);
  (void)ftun_reservation_release(&scratch_reservation);
  (void)ftun_reservation_release(&reservation);
  return status;
}

ftun_status_t ftun_frs_open(ftun_core_t *core, const char *path,
                            ftun_frs_view_t **out)
{
  return ftun_frs_open_mode(core, path, FTUN_FRS_OPEN_AUTO, out);
}

ftun_status_t ftun_frs_view_retain(ftun_frs_view_t *view)
{
  if (view == NULL) return FTUN_E_INVALID;
  if (view->reference_count == SIZE_MAX) return FTUN_E_LIMIT;
  view->reference_count++;
  return FTUN_OK;
}

ftun_status_t ftun_frs_view_release(ftun_frs_view_t **view)
{
  ftun_frs_view_t *owned;
  ftun_status_t status = FTUN_OK;
  ftun_status_t release_status;
  if (view == NULL) return FTUN_E_INVALID;
  owned = *view;
  if (owned == NULL) return FTUN_OK;
  if (owned->reference_count == 0u) return FTUN_E_STATE_CORRUPT;
  owned->reference_count--;
  *view = NULL;
  if (owned->reference_count != 0u) return FTUN_OK;
  ftun_frs_layout_clear(&owned->layout);
  if (owned->storage == FTUN_FRS_STORAGE_MMAP) {
    if (munmap((void *)owned->file, owned->file_bytes) != 0) {
      status = FTUN_E_IO;
    }
  } else {
    free(owned->owned);
  }
  release_status = ftun_reservation_release(&owned->reservation);
  if (status == FTUN_OK) status = release_status;
  memset(owned, 0, sizeof(*owned));
  free(owned);
  return status;
}

ftun_status_t ftun_frs_view_get_info(const ftun_frs_view_t *view,
                                     ftun_frs_view_info_t *out)
{
  const ftun_frs_section_layout_t *sets;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (view == NULL || out == NULL) return FTUN_E_INVALID;
  sets = ftun_frs_layout_section(&view->layout, FTUN_FRS_SECTION_SETS);
  if (sets == NULL) return FTUN_E_STATE_CORRUPT;
  out->file_bytes = view->file_bytes;
  out->set_count = (size_t)sets->count;
  out->reference_count = view->reference_count;
  out->file_checksum = view->layout.file_checksum;
  out->storage = view->storage;
  return FTUN_OK;
}

static int ftun_frs_set_nonempty(const ftun_frs_view_t *view,
                                 const uint8_t *record, uint16_t kind)
{
  uint32_t a_start = ftun_frs_read_u32(record + FTUN_FRS_SET_A_START);
  uint32_t a_count = ftun_frs_read_u32(record + FTUN_FRS_SET_A_COUNT);
  uint32_t c_count = ftun_frs_read_u32(record + FTUN_FRS_SET_C_COUNT);
  uint32_t index;
  if (kind == FTUN_FRS_SET_IP) return a_count != 0u;
  if (c_count != 0u) return 1;
  if (a_count == 0u) return 0;
  {
    const ftun_frs_section_layout_t *nodes = ftun_frs_layout_section(
      &view->layout, FTUN_FRS_SECTION_DOMAIN_NODES);
    if (nodes == NULL) return 0;
    for (index = 0u; index < a_count; index++) {
      const uint8_t *node = view->file + (size_t)nodes->offset +
        ((size_t)a_start - 1u + index) * FTUN_FRS_DOMAIN_NODE_STRIDE;
      if (ftun_frs_read_u32(node + 8u) != 0u) return 1;
    }
  }
  return 0;
}

ftun_status_t ftun_frs_bind(ftun_frs_view_t *view, ftun_frs_set_kind_t kind,
                            ftun_string_t label, ftun_frs_set_t **out)
{
  const ftun_frs_section_layout_t *sets;
  const ftun_frs_section_layout_t *strings;
  size_t index;
  int other_kind = 0;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (view == NULL || out == NULL || label.data == NULL || label.length == 0u ||
      (kind != FTUN_FRS_SET_IP && kind != FTUN_FRS_SET_DOMAIN)) {
    return FTUN_E_INVALID;
  }
  sets = ftun_frs_layout_section(&view->layout, FTUN_FRS_SECTION_SETS);
  strings = ftun_frs_layout_section(&view->layout, FTUN_FRS_SECTION_STRINGS);
  if (sets == NULL || strings == NULL) return FTUN_E_STATE_CORRUPT;
  for (index = 0u; index < sets->count; index++) {
    const uint8_t *record = view->file + (size_t)sets->offset +
      index * FTUN_FRS_SET_STRIDE;
    uint16_t candidate_kind = ftun_frs_read_u16(record + FTUN_FRS_SET_KIND);
    uint64_t offset = ftun_frs_read_u64(record + FTUN_FRS_SET_LABEL_OFFSET);
    uint32_t length = ftun_frs_read_u32(record + FTUN_FRS_SET_LABEL_LENGTH);
    if (label.length != length ||
        memcmp(label.data, view->file + (size_t)strings->offset + (size_t)offset,
               length) != 0) continue;
    if (candidate_kind != (uint16_t)kind) {
      other_kind = 1;
      continue;
    }
    if (!ftun_frs_set_nonempty(view, record, candidate_kind)) {
      return FTUN_E_REJECTED;
    }
    {
      ftun_frs_set_t *set = (ftun_frs_set_t *)calloc(1u, sizeof(*set));
      if (set == NULL) return FTUN_E_LIMIT;
      status = ftun_frs_view_retain(view);
      if (status != FTUN_OK) {
        free(set);
        return status;
      }
      set->view = view;
      set->set_id = (uint32_t)index + 1u;
      set->kind = kind;
      *out = set;
      return FTUN_OK;
    }
  }
  return other_kind ? FTUN_E_UNSUPPORTED : FTUN_E_EOF;
}

ftun_status_t ftun_frs_set_release(ftun_frs_set_t **set)
{
  ftun_frs_set_t *owned;
  ftun_status_t status;
  if (set == NULL) return FTUN_E_INVALID;
  owned = *set;
  if (owned == NULL) return FTUN_OK;
  status = ftun_frs_view_release(&owned->view);
  if (status != FTUN_OK) return status;
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *set = NULL;
  return FTUN_OK;
}

ftun_frs_set_kind_t ftun_frs_set_kind(const ftun_frs_set_t *set)
{
  return set == NULL ? 0 : set->kind;
}

ftun_status_t ftun_frs_set_data(const ftun_frs_set_t *set, ftun_bytes_t *file,
                                const ftun_frs_layout_t **layout,
                                const uint8_t **record)
{
  const ftun_frs_section_layout_t *sets;
  if (file != NULL) memset(file, 0, sizeof(*file));
  if (layout != NULL) *layout = NULL;
  if (record != NULL) *record = NULL;
  if (set == NULL || set->view == NULL || file == NULL || layout == NULL ||
      record == NULL || set->set_id == 0u) return FTUN_E_INVALID;
  sets = ftun_frs_layout_section(&set->view->layout, FTUN_FRS_SECTION_SETS);
  if (sets == NULL || set->set_id > sets->count) return FTUN_E_STATE_CORRUPT;
  file->data = set->view->file;
  file->length = set->view->file_bytes;
  *layout = &set->view->layout;
  *record = set->view->file + (size_t)sets->offset +
    ((size_t)set->set_id - 1u) * FTUN_FRS_SET_STRIDE;
  return FTUN_OK;
}

ftun_status_t ftun_frs_view_bytes(const ftun_frs_view_t *view,
                                  ftun_bytes_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (view == NULL || out == NULL) return FTUN_E_INVALID;
  out->data = view->file;
  out->length = view->file_bytes;
  return FTUN_OK;
}
