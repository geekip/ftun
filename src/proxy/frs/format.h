#ifndef FTUN_PROXY_FRS_FORMAT_H
#define FTUN_PROXY_FRS_FORMAT_H

#include "internal/contracts.h"

/* TASK-FRS-005 / TEST-FRS-005：FRS 1.0 二进制格式验证，目标 0.4.0。 */

#define FTUN_FRS_HEADER_BYTES 64u
#define FTUN_FRS_DIRECTORY_ENTRY_BYTES 40u
#define FTUN_FRS_SET_STRIDE 64u
#define FTUN_FRS_IPV4_RANGE_STRIDE 8u
#define FTUN_FRS_DOMAIN_NODE_STRIDE 16u
#define FTUN_FRS_DOMAIN_EDGE_STRIDE 16u
#define FTUN_FRS_KEYWORD_STRIDE 16u

#define FTUN_FRS_FEATURE_IPV4 UINT32_C(0x00000001)
#define FTUN_FRS_FEATURE_DOMAIN UINT32_C(0x00000002)
#define FTUN_FRS_FEATURE_KEYWORD UINT32_C(0x00000004)
#define FTUN_FRS_FEATURE_IPV6_RESERVED UINT32_C(0x00000008)

#define FTUN_FRS_SECTION_REQUIRED UINT32_C(1)
#define FTUN_FRS_SECTION_METADATA_BASE UINT32_C(0x80000000)

typedef enum {
  FTUN_FRS_SECTION_SETS = 1,
  FTUN_FRS_SECTION_STRINGS,
  FTUN_FRS_SECTION_IPV4_RANGES,
  FTUN_FRS_SECTION_DOMAIN_NODES,
  FTUN_FRS_SECTION_DOMAIN_EDGES,
  FTUN_FRS_SECTION_KEYWORDS,
  FTUN_FRS_SECTION_IPV6_RANGES_RESERVED
} ftun_frs_section_type_t;

typedef enum {
  FTUN_FRS_SET_IP = 1,
  FTUN_FRS_SET_DOMAIN = 2
} ftun_frs_set_kind_t;

#define FTUN_FRS_SET_ID 0u
#define FTUN_FRS_SET_KIND 4u
#define FTUN_FRS_SET_FLAGS 6u
#define FTUN_FRS_SET_LABEL_OFFSET 8u
#define FTUN_FRS_SET_LABEL_LENGTH 16u
#define FTUN_FRS_SET_RESERVED0 20u
#define FTUN_FRS_SET_A_START 24u
#define FTUN_FRS_SET_A_COUNT 28u
#define FTUN_FRS_SET_B_START 32u
#define FTUN_FRS_SET_B_COUNT 36u
#define FTUN_FRS_SET_C_START 40u
#define FTUN_FRS_SET_C_COUNT 44u
#define FTUN_FRS_SET_ROOT 48u
#define FTUN_FRS_SET_ENCODING 52u
#define FTUN_FRS_SET_RESERVED1 56u

typedef struct {
  uint32_t type;
  uint32_t flags;
  uint32_t stride;
  uint64_t offset;
  uint64_t length;
  uint64_t count;
} ftun_frs_section_layout_t;

typedef struct {
  uint16_t major;
  uint16_t minor;
  uint32_t required_features;
  uint32_t section_count;
  uint64_t file_bytes;
  uint64_t directory_offset;
  uint64_t file_checksum;
  ftun_frs_section_layout_t *sections;
} ftun_frs_layout_t;

uint16_t ftun_frs_read_u16(const uint8_t *data);
uint32_t ftun_frs_read_u32(const uint8_t *data);
uint64_t ftun_frs_read_u64(const uint8_t *data);
void ftun_frs_write_u16(uint8_t *data, uint16_t value);
void ftun_frs_write_u32(uint8_t *data, uint32_t value);
void ftun_frs_write_u64(uint8_t *data, uint64_t value);
uint64_t ftun_frs_xxh64(ftun_bytes_t bytes, uint64_t seed);
uint64_t ftun_frs_file_checksum(ftun_bytes_t file);

const ftun_frs_section_layout_t *ftun_frs_layout_section(
  const ftun_frs_layout_t *layout, uint32_t type);
void ftun_frs_layout_clear(ftun_frs_layout_t *layout);

/* 验证 FRS 1.0 的安全读取不变量。writer 的去重、最小化和确定性布局由
 * 生产端验证器负责，reader 不用它们替代边界和环检查。 */
ftun_status_t ftun_frs_format_validate(ftun_bytes_t file,
                                       ftun_frs_layout_t *out);

#endif
