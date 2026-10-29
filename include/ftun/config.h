#ifndef FTUN_CONFIG_H
#define FTUN_CONFIG_H
#include "ftun/operation.h"
#ifdef __cplusplus
extern "C" {
#endif
ftun_status_t ftun_core_reload(ftun_core_t *core, const char *config_path,
                              ftun_completion_fn callback, void *user,
                              ftun_operation_t **out);
/* reload/select 在 owner loop 接纳，异步完成；接纳前复制路径/名称。
 * select 仅改变新连接，检查组/成员及配置代次，不迁移已建立 Session。
 * 两者均可跨线程投递，实际变更只在 owner loop 执行。 */
ftun_status_t ftun_core_select(ftun_core_t *core, const char *group_name,
                              const char *member_name,
                              ftun_completion_fn callback, void *user,
                              ftun_operation_t **out);

#ifdef __cplusplus
}
#endif
#endif
