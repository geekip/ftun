#ifndef FTUN_PROXY_FRS_FRS_H
#define FTUN_PROXY_FRS_FRS_H

#include "proxy/frs/format.h"

/* 只读 FRS 视图与集合绑定。 */

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
 * 失败不允许换后端重试。文件构造失败且撤销映射也失败时，返回原构造错误，
 * out保留仅可release的拥有型句柄；调用方必须接管重试，不能按错误码丢弃。
 * open_bytes 用于独立夹具和已下载候选，复制输入。 */
ftun_status_t ftun_frs_open(ftun_core_t *core, const char *path,
                            ftun_frs_view_t **out);
ftun_status_t ftun_frs_open_mode(ftun_core_t *core, const char *path,
                                 ftun_frs_open_mode_t mode,
                                 ftun_frs_view_t **out);
ftun_status_t ftun_frs_open_bytes(ftun_bytes_t file, ftun_frs_view_t **out);
/* Runtime 拥有的内存视图；预算预留持续到最终释放。输入仍会被复制，
 * 调用返回后即可释放。 */
ftun_status_t ftun_frs_open_bytes_budget(ftun_budget_t *budget,
                                         ftun_bytes_t file,
                                         ftun_frs_view_t **out);
/* Worker 内已创建的拥有型 view 在交给 Runtime 前绑定长期预算。
 * 已绑定同根时幂等，不转移原节点额度；异根拒绝。 */
ftun_status_t ftun_frs_view_bind_budget(ftun_frs_view_t *view,
                                        ftun_budget_t *budget);
ftun_status_t ftun_frs_view_retain(ftun_frs_view_t *view);
/* 最后引用的撤销失败保留句柄与额度，只可重试release；不再接受新引用/读取。 */
ftun_status_t ftun_frs_view_release(ftun_frs_view_t **view);
ftun_status_t ftun_frs_view_get_info(const ftun_frs_view_t *view,
                                     ftun_frs_view_info_t *out);

/* bind 返回拥有型句柄并保留 view。标签按 UTF-8 原始字节和大小写查找；缺失、
 * 类型不符和空集合分别返回 EOF、UNSUPPORTED、REJECTED。 */
ftun_status_t ftun_frs_bind(ftun_frs_view_t *view, ftun_frs_set_kind_t kind,
                            ftun_string_t label, ftun_frs_set_t **out);
/* 每个独立绑定句柄的请求容量，不含共享view；由规则/Runtime的额度覆盖。 */
size_t ftun_frs_set_owned_bytes(void);
ftun_status_t ftun_frs_set_release(ftun_frs_set_t **set);
ftun_frs_set_kind_t ftun_frs_set_kind(const ftun_frs_set_t *set);

/* matcher 内部借用；生命周期不超过 set 句柄。 */
ftun_status_t ftun_frs_set_data(const ftun_frs_set_t *set, ftun_bytes_t *file,
                                const ftun_frs_layout_t **layout,
                                const uint8_t **record);
ftun_status_t ftun_frs_view_bytes(const ftun_frs_view_t *view,
                                  ftun_bytes_t *out);

#endif
