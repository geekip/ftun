#ifndef FTUN_FRS_FRS_H
#define FTUN_FRS_FRS_H

#include "frs/format.h"

/* TASK-FRS-001 / TEST-FRS-001：只读 FRS 视图与集合绑定，目标 0.4.0。 */

typedef enum {
  FTUN_FRS_STORAGE_MEMORY = 1,
  FTUN_FRS_STORAGE_MMAP,
  FTUN_FRS_STORAGE_READ
} ftun_frs_storage_t;

typedef enum {
  FTUN_FRS_OPEN_AUTO = 0,
  FTUN_FRS_OPEN_READ
} ftun_frs_open_mode_t;

typedef struct {
  size_t file_bytes;
  size_t set_count;
  size_t reference_count;
  uint64_t file_checksum;
  ftun_frs_storage_t storage;
} ftun_frs_view_info_t;

/* Linux 默认只读 mmap；只有映射不可用或建立失败时才回退有界读取。格式校验
 * 失败不允许换后端重试。open_bytes 用于独立夹具和已下载候选，复制输入。 */
ftun_status_t ftun_frs_open(ftun_core_t *core, const char *path,
                            ftun_frs_view_t **out);
ftun_status_t ftun_frs_open_mode(ftun_core_t *core, const char *path,
                                 ftun_frs_open_mode_t mode,
                                 ftun_frs_view_t **out);
ftun_status_t ftun_frs_open_bytes(ftun_bytes_t file, ftun_frs_view_t **out);
ftun_status_t ftun_frs_view_retain(ftun_frs_view_t *view);
ftun_status_t ftun_frs_view_release(ftun_frs_view_t **view);
ftun_status_t ftun_frs_view_get_info(const ftun_frs_view_t *view,
                                     ftun_frs_view_info_t *out);

/* bind 返回拥有型句柄并保留 view。标签按 UTF-8 原始字节和大小写查找；缺失、
 * 类型不符和空集合分别返回 EOF、UNSUPPORTED、REJECTED。 */
ftun_status_t ftun_frs_bind(ftun_frs_view_t *view, ftun_frs_set_kind_t kind,
                            ftun_string_t label, ftun_frs_set_t **out);
ftun_status_t ftun_frs_set_release(ftun_frs_set_t **set);
ftun_frs_set_kind_t ftun_frs_set_kind(const ftun_frs_set_t *set);

/* matcher 内部借用；生命周期不超过 set 句柄。 */
ftun_status_t ftun_frs_set_data(const ftun_frs_set_t *set, ftun_bytes_t *file,
                                const ftun_frs_layout_t **layout,
                                const uint8_t **record);
ftun_status_t ftun_frs_view_bytes(const ftun_frs_view_t *view,
                                  ftun_bytes_t *out);

#endif
