#ifndef FTUN_CORE_CONFIG_FIELDS_H
#define FTUN_CORE_CONFIG_FIELDS_H
#include "core/config/document.h"

/* 控制阶段的 JSON 字段读取；owner 仅用于分配准入，不读取宿主模型。
 * 输入树与字符串同步借用；成功字段由 owner 的 payload 拥有。
 * 部分失败保留已构造字段，由宿主的 payload 析构统一释放。 */
char *ftun_config_string_copy(ftun_config_t *owner, const char *value);
ftun_status_t ftun_config_check_fields(const cJSON *object,
  const char *const *allowed, size_t allowed_count);
ftun_status_t ftun_config_replace_string(ftun_config_t *owner, char **destination,
  const cJSON *item, int required);
ftun_status_t ftun_config_optional_bool(const cJSON *object, const char *name, bool *value);
ftun_status_t ftun_config_optional_uint(const cJSON *object, const char *name,
  uint32_t minimum, uint32_t maximum, uint32_t *value);
ftun_status_t ftun_config_optional_duration(const cJSON *object, const char *name,
  bool allow_null, uint32_t *value);
ftun_status_t ftun_config_parse_string_list(ftun_config_t *owner, const cJSON *item,
  ftun_config_string_list_t *list, int require_nonempty);
/* 仅在文档最终 payload 析构时清空，预算随整个文档释放。 */
void ftun_config_string_list_clear(ftun_config_string_list_t *list);
#endif
