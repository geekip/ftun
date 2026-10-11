#include "domain.h"

/* TASK-FRS-003 / TEST-FRS-003：域名 radix 与关键词查询，目标 0.4.0。 */

#include <string.h>

static int ftun_frs_domain_valid(ftun_string_t domain)
{
  size_t start = 0u;
  size_t index;
  if (domain.data == NULL || domain.length == 0u || domain.length > 253u) return 0;
  for (index = 0u; index <= domain.length; index++) {
    if (index == domain.length || domain.data[index] == '.') {
      size_t length = index - start;
      size_t cursor;
      if (length == 0u || length > 63u || domain.data[start] == '-' ||
          domain.data[index - 1u] == '-') return 0;
      for (cursor = start; cursor < index; cursor++) {
        unsigned char byte = (unsigned char)domain.data[cursor];
        if (!((byte >= (unsigned char)'a' && byte <= (unsigned char)'z') ||
              (byte >= (unsigned char)'0' && byte <= (unsigned char)'9') ||
              byte == (unsigned char)'-')) return 0;
      }
      start = index + 1u;
    }
  }
  return 1;
}

static int ftun_frs_keyword_match(const char *domain, size_t domain_length,
                                  const uint8_t *keyword, size_t length)
{
  size_t position;
  if (length > domain_length) return 0;
  for (position = 0u; position <= domain_length - length; position++) {
    if (memcmp(domain + position, keyword, length) == 0) return 1;
  }
  return 0;
}

ftun_status_t ftun_frs_domain_contains(const ftun_frs_set_t *set,
                                       ftun_string_t domain, bool *out)
{
  ftun_bytes_t file;
  const ftun_frs_layout_t *layout;
  const ftun_frs_section_layout_t *nodes;
  const ftun_frs_section_layout_t *edges;
  const ftun_frs_section_layout_t *keywords;
  const ftun_frs_section_layout_t *strings;
  const uint8_t *record;
  uint32_t current;
  uint32_t keyword_start;
  uint32_t keyword_count;
  size_t consumed = 0u;
  ftun_status_t status;
  if (out != NULL) *out = false;
  if (set == NULL || out == NULL || ftun_frs_set_kind(set) != FTUN_FRS_SET_DOMAIN ||
      !ftun_frs_domain_valid(domain)) return FTUN_E_INVALID;
  status = ftun_frs_set_data(set, &file, &layout, &record);
  if (status != FTUN_OK) return status;
  nodes = ftun_frs_layout_section(layout, FTUN_FRS_SECTION_DOMAIN_NODES);
  edges = ftun_frs_layout_section(layout, FTUN_FRS_SECTION_DOMAIN_EDGES);
  keywords = ftun_frs_layout_section(layout, FTUN_FRS_SECTION_KEYWORDS);
  strings = ftun_frs_layout_section(layout, FTUN_FRS_SECTION_STRINGS);
  current = ftun_frs_read_u32(record + FTUN_FRS_SET_ROOT);
  while (current != 0u) {
    const uint8_t *node;
    uint32_t flags;
    uint32_t edge_start;
    uint32_t edge_count;
    uint32_t index;
    uint32_t found = 0u;
    if (nodes == NULL || edges == NULL || strings == NULL) {
      return FTUN_E_STATE_CORRUPT;
    }
    node = file.data + (size_t)nodes->offset +
      ((size_t)current - 1u) * FTUN_FRS_DOMAIN_NODE_STRIDE;
    flags = ftun_frs_read_u32(node + 8u);
    if (((flags & 1u) != 0u && consumed == domain.length) ||
        ((flags & 2u) != 0u && (consumed == domain.length ||
         domain.data[domain.length - consumed - 1u] == '.'))) {
      *out = true;
      return FTUN_OK;
    }
    if (consumed == domain.length) break;
    edge_start = ftun_frs_read_u32(node);
    edge_count = ftun_frs_read_u32(node + 4u);
    for (index = 0u; index < edge_count; index++) {
      const uint8_t *edge = file.data + (size_t)edges->offset +
        ((size_t)edge_start - 1u + index) * FTUN_FRS_DOMAIN_EDGE_STRIDE;
      uint64_t offset = ftun_frs_read_u64(edge);
      uint32_t length = ftun_frs_read_u32(edge + 8u);
      size_t cursor;
      if (length > domain.length - consumed) continue;
      for (cursor = 0u; cursor < length; cursor++) {
        if ((uint8_t)domain.data[domain.length - consumed - cursor - 1u] !=
            file.data[(size_t)strings->offset + (size_t)offset + cursor]) break;
      }
      if (cursor == length) {
        found = ftun_frs_read_u32(edge + 12u);
        consumed += length;
        break;
      }
    }
    if (found == 0u) break;
    current = found;
  }
  keyword_start = ftun_frs_read_u32(record + FTUN_FRS_SET_C_START);
  keyword_count = ftun_frs_read_u32(record + FTUN_FRS_SET_C_COUNT);
  if (keyword_count != 0u && (keywords == NULL || strings == NULL)) {
    return FTUN_E_STATE_CORRUPT;
  }
  {
    uint32_t index;
    for (index = 0u; index < keyword_count; index++) {
      const uint8_t *item = file.data + (size_t)keywords->offset +
        ((size_t)keyword_start - 1u + index) * FTUN_FRS_KEYWORD_STRIDE;
      uint64_t offset = ftun_frs_read_u64(item);
      uint32_t length = ftun_frs_read_u32(item + 8u);
      if (ftun_frs_keyword_match(domain.data, domain.length,
            file.data + (size_t)strings->offset + (size_t)offset, length)) {
        *out = true;
        break;
      }
    }
  }
  return FTUN_OK;
}
