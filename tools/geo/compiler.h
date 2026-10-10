#ifndef FTUN_GEO_COMPILER_H
#define FTUN_GEO_COMPILER_H
#include <stddef.h>
#include <stdint.h>
/* REQ-GEO-001：输入源适配不得进入 ftun_core。具体文本语法由用户样例固定。
 * 后续 compiler 使用中间记录集合名/type/value，全部校验成功后才能创建发布产物。
 * 此声明仅定义将来工具内部的值模型，无 Go/protobuf/正则依赖。 */
typedef enum { FTUN_GEO_IPV4_CIDR=1, FTUN_GEO_EXACT=2,
               FTUN_GEO_SUFFIX=3, FTUN_GEO_KEYWORD=4 } ftun_geo_record_kind_t;
typedef struct {
  ftun_geo_record_kind_t kind;
  const char *set_name;
  const char *value;
  size_t source_line;
} ftun_geo_source_record_t;
#endif
