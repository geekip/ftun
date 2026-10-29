#ifndef FTUN_LIBS_TRANSPORT_CONFIG_H
#define FTUN_LIBS_TRANSPORT_CONFIG_H
#include "core/config/document.h"
#define FTUN_CONFIG_SECTION_CHANNELS 14u
typedef enum {
  FTUN_CHANNEL_CONFIG_SOCKS5 = 1,
  FTUN_CHANNEL_CONFIG_GROUP
} ftun_channel_config_kind_t;
typedef struct {
  ftun_channel_config_kind_t kind;
  const char *name;
  const char *dns_server;
  const char *server;
  const char *username;
  const char *password;
  bool udp;
  ftun_config_string_list_t members;
} ftun_channel_config_t;
/* 宿主在不可变文档上提供窄视图；返回值按值复制，字符串/成员仍借用文档。
 * 不分配、不解析、不调用运行时，index 必须小于 count。 */
typedef struct {
  size_t (*count)(const ftun_config_t *config);
  ftun_channel_config_t (*at)(const ftun_config_t *config, size_t index);
} ftun_channel_catalog_t;
static inline size_t ftun_config_channel_count(const ftun_config_t *config)
{
  const ftun_channel_catalog_t *catalog = ftun_config_document_section(config, FTUN_CONFIG_SECTION_CHANNELS);
  return catalog->count(config);
}
static inline ftun_channel_config_t ftun_config_channel(const ftun_config_t *config, size_t index)
{
  const ftun_channel_catalog_t *catalog = ftun_config_document_section(config, FTUN_CONFIG_SECTION_CHANNELS);
  return catalog->at(config, index);
}
#endif
