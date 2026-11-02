#ifndef FTUN_CORE_CONFIG_ERROR_H
#define FTUN_CORE_CONFIG_ERROR_H
#include "util/types.h"

#define FTUN_CONFIG_ERROR_PATH_BYTES 1024u
#define FTUN_CONFIG_ERROR_MESSAGE_BYTES 192u

typedef enum {
  FTUN_CONFIG_STEP_NONE = 0,
  FTUN_CONFIG_STEP_READ,
  FTUN_CONFIG_STEP_PARSE,
  FTUN_CONFIG_STEP_PATHS,
  FTUN_CONFIG_STEP_VALIDATE,
  FTUN_CONFIG_STEP_COMPILE,
  FTUN_CONFIG_STEP_ATTACHMENTS
} ftun_config_step_t;

/* 完全拥有的首次错误；可跨Worker结果和回调按值复制，不借用配置/JSON树。 */
typedef struct {
  ftun_error_t error;
  ftun_config_step_t phase;
  size_t offset;
  bool offset_valid, truncated;
  char pointer[FTUN_CONFIG_ERROR_PATH_BYTES];
  char field[FTUN_CONFIG_ERROR_PATH_BYTES];
  char message[FTUN_CONFIG_ERROR_MESSAGE_BYTES];
} ftun_config_error_t;

struct cJSON;
void ftun_config_error_begin(ftun_config_error_t *error, ftun_config_step_t phase);
/* error可为NULL；非空时须先begin。只保留首个失败，消息使用固定诊断文本。 */
ftun_status_t ftun_config_error_set(ftun_config_error_t *error, ftun_status_t status,
  const char *pointer, const char *message);
#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 4, 5)))
#endif
ftun_status_t ftun_config_error_setf(ftun_config_error_t *error, ftun_status_t status,
  const char *message, const char *format, ...);
/* root为经过深度/长度边界的JSON树，node属于该树；missing为缺失子字段名。
 * 同步借用，返回前复制两种路径；不分配、不I/O。 */
ftun_status_t ftun_config_error_node(ftun_config_error_t *error, ftun_status_t status,
  const struct cJSON *root, const struct cJSON *node, const char *missing,
  const char *message);
/* 将固定记录写入调用方缓冲，不分配；成功返回JSON字节数，失败返回0。 */
size_t ftun_config_error_json(const ftun_config_error_t *error, char *output, size_t capacity);
const char *ftun_config_step_name(ftun_config_step_t step);
#endif
