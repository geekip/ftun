#ifndef FTUN_CORE_CONFIG_DOCUMENT_H
#define FTUN_CORE_CONFIG_DOCUMENT_H
#include "core/limits.h"
#include <cJSON.h>
#define FTUN_CONFIG_MAX_JSON_BYTES (1024u * 1024u)
#define FTUN_CONFIG_MAX_DEPTH 32u
#define FTUN_CONFIG_MAX_NODES 16384u
#define FTUN_CONFIG_MAX_ARRAY_ITEMS 1024u
#define FTUN_CONFIG_MAX_STRING_BYTES FTUN_CONFIG_MAX_JSON_BYTES
#define FTUN_CONFIG_MAX_PATH_BYTES 4096u

typedef struct {
  uint32_t known_modules;
  uint32_t built_modules;
  uint32_t required_modules;
} ftun_config_modules_t;

typedef struct {
  /* 仅在最后一个引用释放时调用；失败保留整个文档，允许调用方继续清理。 */
  ftun_status_t (*prepare_destroy)(ftun_config_t *config);
  /* prepare 与资源释放成功后执行，只释放 payload 内部字段，不释放 config 本体。 */
  void (*destroy)(ftun_config_t *config);
  /* 返回模型拥有的只读段；未知段返回 NULL，借用不超过 config 的生命期。 */
  const void *(*section)(const ftun_config_t *config, uint32_t section_id);
} ftun_config_document_ops_t;

/* 宿主类型的首成员。所有字段归 owner；budget 借用至文档销毁。
 * modules 借用已编译的不可变计划，prepare_destroy 成功后必须撤销。 */
typedef struct {
  size_t reference_count;
  size_t owned_bytes;
  ftun_budget_t *budget;
  ftun_reservation_t reservation;
  const ftun_config_modules_t *modules;
  const ftun_config_document_ops_t *ops;
} ftun_config_document_t;

/* 返回通用拥有信息的只读借用，生命期不超过 config。 */
static inline const ftun_config_document_t *ftun_config_document_header(const ftun_config_t *config)
{
  return (const ftun_config_document_t *)config;
}

typedef struct {
  cJSON *root;
  ftun_reservation_t reservation;
} ftun_config_json_t;

/* 内部构造接口：size 至少包含首部，ops 为静态借用。失败输出为空。
 * 不产生线程或回调；destroy 只在最后一次引用释放时由 owner 调用。 */
ftun_status_t ftun_config_document_create(size_t size, ftun_budget_t *budget,
  const ftun_config_document_ops_t *ops, ftun_config_t **out);
const void *ftun_config_document_section(const ftun_config_t *config, uint32_t section_id);
const ftun_config_modules_t *ftun_config_document_modules(const ftun_config_t *config);
void *ftun_config_allocate(ftun_config_t *config, size_t count, size_t size);
void ftun_config_free_bytes(ftun_config_t *config, void *value, size_t bytes);
ftun_status_t ftun_config_retain(ftun_config_t *config);
ftun_status_t ftun_config_destroy(ftun_config_t **config);

/* 外部 JSON 边界：先核算并准入临时内存，再解析和检查全树。
 * 支持一个 BOM；拒绝重复键、非有限数、无效 UTF-8、深度/节点/长度超限。
 * 成功后 root 由 out 拥有，借用至 close；失败完全回滚，不交付部分树。 */
ftun_status_t ftun_config_json_open(ftun_budget_t *budget, ftun_bytes_t json,
  ftun_config_json_t *out);
void ftun_config_json_close(ftun_config_json_t *document);
#endif
