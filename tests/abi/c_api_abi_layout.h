#ifndef FTUN_TEST_C_API_ABI_LAYOUT_H
#define FTUN_TEST_C_API_ABI_LAYOUT_H

#include <stddef.h>
#include <string.h>

#define FTUN_TEST_ABI_ALIGNMENT(type) \
  offsetof(struct { char prefix; type value; }, value)

/* 两个翻译单元分别使用历史头与当前头，比较各自实际生成的布局。 */
static size_t ftun_test_abi_layout(size_t *out, size_t capacity)
{
#define SIZE(type) sizeof(type), FTUN_TEST_ABI_ALIGNMENT(type)
#define FIELD(type, field) offsetof(type, field), sizeof(((type *)0)->field)
  const size_t values[] = {
    FTUN_ABI_VERSION,
    SIZE(ftun_core_options_t),
    FIELD(ftun_core_options_t, struct_size),
    FIELD(ftun_core_options_t, abi_version),
    FIELD(ftun_core_options_t, owned_memory_limit),
    FIELD(ftun_core_options_t, operation_capacity),
    FIELD(ftun_core_options_t, retained_runtime_limit),
    FIELD(ftun_core_options_t, owned_descriptor_limit),
    FIELD(ftun_core_options_t, owned_queue_limit),
    FIELD(ftun_core_options_t, retained_runtime_bytes_limit),
    SIZE(ftun_core_info_t),
    FIELD(ftun_core_info_t, state),
    FIELD(ftun_core_info_t, generation),
    FIELD(ftun_core_info_t, pending_operations),
    FIELD(ftun_core_info_t, owner_rounds),
    FIELD(ftun_core_info_t, owner_max_busy_ms),
    FIELD(ftun_core_info_t, owner_max_deadline_lateness_ms),
    FIELD(ftun_core_info_t, owner_max_work),
    FIELD(ftun_core_info_t, owner_quota_exhaustions),
    SIZE(ftun_error_t), FIELD(ftun_error_t, status),
    FIELD(ftun_error_t, stage), FIELD(ftun_error_t, native_code),
    SIZE(ftun_status_t), SIZE(ftun_core_state_t), SIZE(ftun_error_stage_t),
    SIZE(ftun_completion_fn),
    FTUN_OK, FTUN_E_INVALID, FTUN_E_NOT_IMPLEMENTED, FTUN_E_UNSUPPORTED,
    FTUN_E_AGAIN, FTUN_E_EOF, FTUN_E_CANCELLED, FTUN_E_TIMEOUT,
    FTUN_E_LIMIT, FTUN_E_IO, FTUN_E_RESOLVE, FTUN_E_REJECTED,
    FTUN_E_PROTOCOL, FTUN_E_RESTART_REQUIRED, FTUN_E_STALE,
    FTUN_E_STATE_CORRUPT,
    FTUN_CORE_CREATED, FTUN_CORE_STARTING, FTUN_CORE_RUNNING,
    FTUN_CORE_STOPPING, FTUN_CORE_STOPPED,
    FTUN_STAGE_NONE, FTUN_STAGE_CONFIG_READ, FTUN_STAGE_CONFIG_PREPARE,
    FTUN_STAGE_STATE_RESTORE, FTUN_STAGE_COMMIT, FTUN_STAGE_CONTROL
  };
#undef SIZE
#undef FIELD
  size_t count = sizeof(values) / sizeof(values[0]);
  if (out != NULL && capacity >= count) memcpy(out, values, sizeof(values));
  return count;
}

/* C99 重复声明必须与所包含发行头的函数类型完全兼容。 */
extern const char *ftun_version(void);
extern const char *ftun_status_name(ftun_status_t);
extern ftun_status_t ftun_core_create(const ftun_core_options_t *, ftun_core_t **);
extern ftun_status_t ftun_core_run(ftun_core_t *, const char *);
extern ftun_status_t ftun_core_stop(ftun_core_t *, uint64_t);
extern ftun_status_t ftun_core_post(ftun_core_t *, ftun_completion_fn, void *,
                                     ftun_operation_t **);
extern ftun_status_t ftun_core_reload(ftun_core_t *, const char *,
                                       ftun_completion_fn, void *, ftun_operation_t **);
extern ftun_status_t ftun_core_select(ftun_core_t *, const char *, const char *,
                                       ftun_completion_fn, void *, ftun_operation_t **);
extern ftun_status_t ftun_operation_cancel(ftun_operation_t *);
extern ftun_status_t ftun_core_get_info(ftun_core_t *, ftun_core_info_t *);
extern ftun_status_t ftun_core_destroy(ftun_core_t **);
#endif
