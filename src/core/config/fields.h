#ifndef FTUN_CORE_CONFIG_FIELDS_H
#define FTUN_CORE_CONFIG_FIELDS_H
#include "core/config/document.h"

/* 控制阶段的 JSON 字段读取；owner只用于分配准入和本次构造错误定位，不读取宿主模型。
 * 输入树与字符串同步借用；成功字段由 owner 的 payload 拥有。
 * 部分失败保留已构造字段，由宿主的 payload 析构统一释放。 */
char *ftun_config_string_copy(ftun_config_t *owner, const char *value);
ftun_status_t ftun_config_parse_failure(ftun_config_t *owner, const cJSON *node,
  const char *missing, ftun_status_t status, const char *message);
ftun_status_t ftun_config_check_fields(ftun_config_t *owner, const cJSON *object,
  const char *const *allowed, size_t allowed_count);
ftun_status_t ftun_config_replace_string(ftun_config_t *owner, char **destination,
  const cJSON *object, const char *name, int required);
ftun_status_t ftun_config_optional_bool(ftun_config_t *owner, const cJSON *object, const char *name, bool *value);
ftun_status_t ftun_config_optional_uint(ftun_config_t *owner, const cJSON *object, const char *name,
  uint32_t minimum, uint32_t maximum, uint32_t *value);
ftun_status_t ftun_config_optional_duration(ftun_config_t *owner, const cJSON *object, const char *name,
  bool allow_null, uint32_t *value);
ftun_status_t ftun_config_parse_string_list(ftun_config_t *owner, const cJSON *object,
  const char *name,
  ftun_config_string_list_t *list, int require_nonempty);
/* 仅在文档最终 payload 析构时清空，预算随整个文档释放。 */
void ftun_config_string_list_clear(ftun_config_string_list_t *list);
#endif
