#include "proxy/frs/format.h"

/* FRS 1.0 二进制格式验证。 */

#include <stdlib.h>
#include <string.h>

#define FTUN_XXH_PRIME1 UINT64_C(11400714785074694791)
#define FTUN_XXH_PRIME2 UINT64_C(14029467366897019727)
#define FTUN_XXH_PRIME3 UINT64_C(1609587929392839161)
#define FTUN_XXH_PRIME4 UINT64_C(9650029242287828579)
#define FTUN_XXH_PRIME5 UINT64_C(2870177450012600261)

typedef struct {
  uint16_t kind;
  const uint8_t *label;
  uint32_t length;
} ftun_frs_set_key_t;

typedef struct {
  uint32_t node;
  uint32_t edge_index;
} ftun_frs_dfs_frame_t;

uint16_t ftun_frs_read_u16(const uint8_t *data)
{
  return (uint16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8u));
}

uint32_t ftun_frs_read_u32(const uint8_t *data)
{
  return (uint32_t)data[0] | ((uint32_t)data[1] << 8u) |
         ((uint32_t)data[2] << 16u) | ((uint32_t)data[3] << 24u);
}

uint64_t ftun_frs_read_u64(const uint8_t *data)
{
  return (uint64_t)ftun_frs_read_u32(data) |
         ((uint64_t)ftun_frs_read_u32(data + 4u) << 32u);
}

void ftun_frs_write_u32(uint8_t *data, uint32_t value)
{
  data[0] = (uint8_t)value;
  data[1] = (uint8_t)(value >> 8u);
  data[2] = (uint8_t)(value >> 16u);
  data[3] = (uint8_t)(value >> 24u);
}

void ftun_frs_write_u64(uint8_t *data, uint64_t value)
{
  ftun_frs_write_u32(data, (uint32_t)value);
  ftun_frs_write_u32(data + 4u, (uint32_t)(value >> 32u));
}

static uint64_t ftun_frs_rotl64(uint64_t value, unsigned int bits)
{
  return (value << bits) | (value >> (64u - bits));
}

static uint64_t ftun_frs_xxh_round(uint64_t accumulator, uint64_t input)
{
  accumulator += input * FTUN_XXH_PRIME2;
  accumulator = ftun_frs_rotl64(accumulator, 31u);
  return accumulator * FTUN_XXH_PRIME1;
}

static uint64_t ftun_frs_xxh_merge(uint64_t accumulator, uint64_t value)
{
  accumulator ^= ftun_frs_xxh_round(0u, value);
  return accumulator * FTUN_XXH_PRIME1 + FTUN_XXH_PRIME4;
}

uint64_t ftun_frs_xxh64(ftun_bytes_t bytes, uint64_t seed)
{
  const uint8_t *cursor;
  const uint8_t *end;
  uint64_t hash;
  if (bytes.length != 0u && bytes.data == NULL) return 0u;
  cursor = bytes.data;
  end = bytes.data == NULL ? NULL : bytes.data + bytes.length;
  if (bytes.length >= 32u) {
    const uint8_t *limit = end - 32u;
    uint64_t v1 = seed + FTUN_XXH_PRIME1 + FTUN_XXH_PRIME2;
    uint64_t v2 = seed + FTUN_XXH_PRIME2;
    uint64_t v3 = seed;
    uint64_t v4 = seed - FTUN_XXH_PRIME1;
    do {
      v1 = ftun_frs_xxh_round(v1, ftun_frs_read_u64(cursor)); cursor += 8u;
      v2 = ftun_frs_xxh_round(v2, ftun_frs_read_u64(cursor)); cursor += 8u;
      v3 = ftun_frs_xxh_round(v3, ftun_frs_read_u64(cursor)); cursor += 8u;
      v4 = ftun_frs_xxh_round(v4, ftun_frs_read_u64(cursor)); cursor += 8u;
    } while (cursor <= limit);
    hash = ftun_frs_rotl64(v1, 1u) + ftun_frs_rotl64(v2, 7u) +
           ftun_frs_rotl64(v3, 12u) + ftun_frs_rotl64(v4, 18u);
    hash = ftun_frs_xxh_merge(hash, v1);
    hash = ftun_frs_xxh_merge(hash, v2);
    hash = ftun_frs_xxh_merge(hash, v3);
    hash = ftun_frs_xxh_merge(hash, v4);
  } else {
    hash = seed + FTUN_XXH_PRIME5;
  }
  hash += bytes.length;
  while (cursor != NULL && cursor + 8u <= end) {
    hash ^= ftun_frs_xxh_round(0u, ftun_frs_read_u64(cursor));
    hash = ftun_frs_rotl64(hash, 27u) * FTUN_XXH_PRIME1 + FTUN_XXH_PRIME4;
    cursor += 8u;
  }
  if (cursor != NULL && cursor + 4u <= end) {
    hash ^= (uint64_t)ftun_frs_read_u32(cursor) * FTUN_XXH_PRIME1;
    hash = ftun_frs_rotl64(hash, 23u) * FTUN_XXH_PRIME2 + FTUN_XXH_PRIME3;
    cursor += 4u;
  }
  while (cursor != NULL && cursor < end) {
    hash ^= (uint64_t)*cursor++ * FTUN_XXH_PRIME5;
    hash = ftun_frs_rotl64(hash, 11u) * FTUN_XXH_PRIME1;
  }
  hash ^= hash >> 33u;
  hash *= FTUN_XXH_PRIME2;
  hash ^= hash >> 29u;
  hash *= FTUN_XXH_PRIME3;
  return hash ^ (hash >> 32u);
}

uint64_t ftun_frs_file_checksum(ftun_bytes_t file)
{
  size_t cursor = 0u;
  uint64_t hash;
  if (file.data == NULL || file.length < FTUN_FRS_HEADER_BYTES) return 0u;
  if (file.length >= 32u) {
    size_t limit = file.length - 32u;
    uint64_t v1 = FTUN_XXH_PRIME1 + FTUN_XXH_PRIME2;
    uint64_t v2 = FTUN_XXH_PRIME2;
    uint64_t v3 = 0u;
    uint64_t v4 = 0u - FTUN_XXH_PRIME1;
    do {
      uint64_t values[4] = {0u, 0u, 0u, 0u};
      size_t lane;
      for (lane = 0u; lane < 4u; lane++) {
        size_t byte;
        for (byte = 0u; byte < 8u; byte++) {
          size_t offset = cursor + lane * 8u + byte;
          uint8_t value = offset >= 48u && offset < 56u
            ? 0u : file.data[offset];
          values[lane] |= (uint64_t)value << (byte * 8u);
        }
      }
      v1 = ftun_frs_xxh_round(v1, values[0]);
      v2 = ftun_frs_xxh_round(v2, values[1]);
      v3 = ftun_frs_xxh_round(v3, values[2]);
      v4 = ftun_frs_xxh_round(v4, values[3]);
      cursor += 32u;
    } while (cursor <= limit);
    hash = ftun_frs_rotl64(v1, 1u) + ftun_frs_rotl64(v2, 7u) +
           ftun_frs_rotl64(v3, 12u) + ftun_frs_rotl64(v4, 18u);
    hash = ftun_frs_xxh_merge(hash, v1);
    hash = ftun_frs_xxh_merge(hash, v2);
    hash = ftun_frs_xxh_merge(hash, v3);
    hash = ftun_frs_xxh_merge(hash, v4);
  } else {
    hash = FTUN_XXH_PRIME5;
  }
  hash += file.length;
  while (cursor + 8u <= file.length) {
    uint64_t value = 0u;
    size_t byte;
    for (byte = 0u; byte < 8u; byte++) {
      size_t offset = cursor + byte;
      uint8_t item = offset >= 48u && offset < 56u ? 0u : file.data[offset];
      value |= (uint64_t)item << (byte * 8u);
    }
    hash ^= ftun_frs_xxh_round(0u, value);
    hash = ftun_frs_rotl64(hash, 27u) * FTUN_XXH_PRIME1 + FTUN_XXH_PRIME4;
    cursor += 8u;
  }
  if (cursor + 4u <= file.length) {
    uint32_t value = 0u;
    size_t byte;
    for (byte = 0u; byte < 4u; byte++) {
      size_t offset = cursor + byte;
      uint8_t item = offset >= 48u && offset < 56u ? 0u : file.data[offset];
      value |= (uint32_t)item << (byte * 8u);
    }
    hash ^= (uint64_t)value * FTUN_XXH_PRIME1;
    hash = ftun_frs_rotl64(hash, 23u) * FTUN_XXH_PRIME2 + FTUN_XXH_PRIME3;
    cursor += 4u;
  }
  while (cursor < file.length) {
    uint8_t item = cursor >= 48u && cursor < 56u ? 0u : file.data[cursor];
    hash ^= (uint64_t)item * FTUN_XXH_PRIME5;
    hash = ftun_frs_rotl64(hash, 11u) * FTUN_XXH_PRIME1;
    cursor++;
  }
  hash ^= hash >> 33u;
  hash *= FTUN_XXH_PRIME2;
  hash ^= hash >> 29u;
  hash *= FTUN_XXH_PRIME3;
  return hash ^ (hash >> 32u);
}

const ftun_frs_section_layout_t *ftun_frs_layout_section(
  const ftun_frs_layout_t *layout, uint32_t type)
{
  size_t index;
  if (layout == NULL) return NULL;
  for (index = 0u; index < layout->section_count; index++) {
    if (layout->sections[index].type == type) return &layout->sections[index];
  }
  return NULL;
}

void ftun_frs_layout_clear(ftun_frs_layout_t *layout)
{
  if (layout == NULL) return;
  free(layout->sections);
  memset(layout, 0, sizeof(*layout));
}

static int ftun_frs_range(uint64_t offset, uint64_t length, uint64_t total)
{
  return offset <= total && length <= total - offset;
}

static int ftun_frs_span(uint32_t start, uint32_t count, uint64_t total)
{
  uint64_t first;
  if (count == 0u) return start == 0u;
  if (start == 0u) return 0;
  first = (uint64_t)start - 1u;
  return first <= total && (uint64_t)count <= total - first;
}

static uint32_t ftun_frs_expected_stride(uint32_t type)
{
  switch (type) {
    case FTUN_FRS_SECTION_SETS: return FTUN_FRS_SET_STRIDE;
    case FTUN_FRS_SECTION_STRINGS: return 1u;
    case FTUN_FRS_SECTION_IPV4_RANGES: return FTUN_FRS_IPV4_RANGE_STRIDE;
    case FTUN_FRS_SECTION_DOMAIN_NODES: return FTUN_FRS_DOMAIN_NODE_STRIDE;
    case FTUN_FRS_SECTION_DOMAIN_EDGES: return FTUN_FRS_DOMAIN_EDGE_STRIDE;
    case FTUN_FRS_SECTION_KEYWORDS: return FTUN_FRS_KEYWORD_STRIDE;
    default: return 0u;
  }
}

static int ftun_frs_decode_utf8(const uint8_t *text, size_t length,
                                size_t *cursor, uint32_t *out)
{
  uint8_t first;
  uint32_t codepoint;
  size_t remaining;
  if (text == NULL || cursor == NULL || out == NULL || *cursor >= length) return 0;
  first = text[(*cursor)++];
  if (first < 0x80u) {
    *out = first;
    return 1;
  }
  if (first >= 0xc2u && first <= 0xdfu) {
    codepoint = first & 0x1fu;
    remaining = 1u;
  } else if (first >= 0xe0u && first <= 0xefu) {
    codepoint = first & 0x0fu;
    remaining = 2u;
  } else if (first >= 0xf0u && first <= 0xf4u) {
    codepoint = first & 0x07u;
    remaining = 3u;
  } else {
    return 0;
  }
  if (remaining > length - *cursor) return 0;
  while (remaining != 0u) {
    uint8_t next = text[(*cursor)++];
    if ((next & 0xc0u) != 0x80u) return 0;
    codepoint = (codepoint << 6u) | (next & 0x3fu);
    remaining--;
  }
  if ((first == 0xe0u && codepoint < 0x800u) ||
      (first == 0xedu && codepoint >= 0xd800u) ||
      (first == 0xf0u && codepoint < 0x10000u) ||
      codepoint > 0x10ffffu ||
      (codepoint >= 0xd800u && codepoint <= 0xdfffu)) return 0;
  *out = codepoint;
  return 1;
}

static int ftun_frs_unicode_space(uint32_t codepoint)
{
  return (codepoint >= 0x0009u && codepoint <= 0x000du) ||
    codepoint == 0x0020u || codepoint == 0x0085u || codepoint == 0x00a0u ||
    codepoint == 0x1680u || (codepoint >= 0x2000u && codepoint <= 0x200au) ||
    codepoint == 0x2028u || codepoint == 0x2029u || codepoint == 0x202fu ||
    codepoint == 0x205fu || codepoint == 0x3000u;
}

static int ftun_frs_label_valid(const uint8_t *text, size_t length)
{
  size_t cursor = 0u;
  uint32_t first = 0u;
  uint32_t last = 0u;
  if (text == NULL || length == 0u) return 0;
  while (cursor < length) {
    uint32_t codepoint;
    if (!ftun_frs_decode_utf8(text, length, &cursor, &codepoint)) return 0;
    if (first == 0u) first = codepoint;
    last = codepoint;
    if (codepoint == 0x2cu || codepoint <= 0x1fu ||
        (codepoint >= 0x7fu && codepoint <= 0x9fu)) return 0;
  }
  return !ftun_frs_unicode_space(first) && !ftun_frs_unicode_space(last);
}

static int ftun_frs_ascii_index_text(const uint8_t *text, size_t length,
                                     int allow_dot)
{
  size_t index;
  if (text == NULL || length == 0u) return 0;
  for (index = 0u; index < length; index++) {
    uint8_t byte = text[index];
    if (!((byte >= (uint8_t)'a' && byte <= (uint8_t)'z') ||
          (byte >= (uint8_t)'0' && byte <= (uint8_t)'9') ||
          byte == (uint8_t)'-' || (allow_dot && byte == (uint8_t)'.'))) {
      return 0;
    }
  }
  return 1;
}

static int ftun_frs_keyword_text(const uint8_t *text, size_t length)
{
  size_t index;
  if (text == NULL || length == 0u || length > 253u) return 0;
  for (index = 0u; index < length; index++) {
    uint8_t byte = text[index];
    if (byte < 0x21u || byte > 0x7eu ||
        (byte >= (uint8_t)'A' && byte <= (uint8_t)'Z')) return 0;
  }
  return 1;
}

static int ftun_frs_string(ftun_bytes_t file,
                           const ftun_frs_section_layout_t *strings,
                           uint64_t offset, uint32_t length,
                           const uint8_t **out)
{
  if (strings == NULL || out == NULL || offset > strings->length ||
      (uint64_t)length > strings->length - offset) return 0;
  *out = file.data + (size_t)strings->offset + (size_t)offset;
  return 1;
}

static int ftun_frs_set_key_compare(const void *left_value,
                                    const void *right_value)
{
  const ftun_frs_set_key_t *left = (const ftun_frs_set_key_t *)left_value;
  const ftun_frs_set_key_t *right = (const ftun_frs_set_key_t *)right_value;
  size_t common;
  int order;
  if (left->kind != right->kind) return left->kind < right->kind ? -1 : 1;
  common = left->length < right->length ? left->length : right->length;
  order = memcmp(left->label, right->label, common);
  if (order != 0) return order;
  if (left->length == right->length) return 0;
  return left->length < right->length ? -1 : 1;
}

static ftun_status_t ftun_frs_validate_ipv4(
  ftun_bytes_t file, const ftun_frs_section_layout_t *ranges,
  uint32_t start, uint32_t count)
{
  uint32_t index;
  uint32_t previous = 0u;
  if (!ftun_frs_span(start, count, ranges == NULL ? 0u : ranges->count)) {
    return FTUN_E_PROTOCOL;
  }
  for (index = 0u; index < count; index++) {
    const uint8_t *record = file.data + (size_t)ranges->offset +
      ((size_t)start - 1u + index) * FTUN_FRS_IPV4_RANGE_STRIDE;
    uint32_t lo = ftun_frs_read_u32(record);
    uint32_t hi = ftun_frs_read_u32(record + 4u);
    if (lo > hi || (index != 0u && lo < previous)) return FTUN_E_PROTOCOL;
    previous = lo;
  }
  return FTUN_OK;
}

static ftun_status_t ftun_frs_validate_domain(
  ftun_bytes_t file, const ftun_frs_section_layout_t *nodes,
  const ftun_frs_section_layout_t *edges,
  const ftun_frs_section_layout_t *keywords,
  const ftun_frs_section_layout_t *strings, uint32_t node_start,
  uint32_t node_count, uint32_t edge_start, uint32_t edge_count,
  uint32_t keyword_start, uint32_t keyword_count, uint32_t root)
{
  uint8_t *colors = NULL;
  ftun_frs_dfs_frame_t *stack = NULL;
  uint32_t index;
  ftun_status_t status = FTUN_OK;
  if (!ftun_frs_span(node_start, node_count, nodes == NULL ? 0u : nodes->count) ||
      !ftun_frs_span(edge_start, edge_count, edges == NULL ? 0u : edges->count) ||
      !ftun_frs_span(keyword_start, keyword_count,
                     keywords == NULL ? 0u : keywords->count)) {
    return FTUN_E_PROTOCOL;
  }
  if (node_count == 0u) {
    if (edge_count != 0u || root != 0u) return FTUN_E_PROTOCOL;
  } else if (root != node_start) {
    return FTUN_E_PROTOCOL;
  }
  for (index = 0u; index < edge_count; index++) {
    const uint8_t *edge = file.data + (size_t)edges->offset +
      ((size_t)edge_start - 1u + index) * FTUN_FRS_DOMAIN_EDGE_STRIDE;
    const uint8_t *label;
    uint64_t label_offset = ftun_frs_read_u64(edge);
    uint32_t label_length = ftun_frs_read_u32(edge + 8u);
    uint32_t child = ftun_frs_read_u32(edge + 12u);
    if (!ftun_frs_string(file, strings, label_offset, label_length, &label) ||
        !ftun_frs_ascii_index_text(label, label_length, 1) ||
        child < node_start || child - node_start >= node_count) {
      return FTUN_E_PROTOCOL;
    }
  }
  for (index = 0u; index < node_count; index++) {
    const uint8_t *node = file.data + (size_t)nodes->offset +
      ((size_t)node_start - 1u + index) * FTUN_FRS_DOMAIN_NODE_STRIDE;
    uint32_t first = ftun_frs_read_u32(node);
    uint32_t count = ftun_frs_read_u32(node + 4u);
    uint32_t flags = ftun_frs_read_u32(node + 8u);
    uint32_t edge_index;
    uint8_t previous_first = 0u;
    if ((flags & ~UINT32_C(3)) != 0u || ftun_frs_read_u32(node + 12u) != 0u ||
        !ftun_frs_span(first, count, edges == NULL ? 0u : edges->count) ||
        (count != 0u && (first < edge_start || first - edge_start >= edge_count ||
         count > edge_count - (first - edge_start))) ||
        (index == 0u && flags != 0u)) return FTUN_E_PROTOCOL;
    for (edge_index = 0u; edge_index < count; edge_index++) {
      const uint8_t *edge = file.data + (size_t)edges->offset +
        ((size_t)first - 1u + edge_index) * FTUN_FRS_DOMAIN_EDGE_STRIDE;
      const uint8_t *label = file.data + (size_t)strings->offset +
        (size_t)ftun_frs_read_u64(edge);
      if (edge_index != 0u && label[0] <= previous_first) return FTUN_E_PROTOCOL;
      previous_first = label[0];
    }
  }
  for (index = 0u; index < keyword_count; index++) {
    const uint8_t *record = file.data + (size_t)keywords->offset +
      ((size_t)keyword_start - 1u + index) * FTUN_FRS_KEYWORD_STRIDE;
    const uint8_t *text;
    uint64_t offset = ftun_frs_read_u64(record);
    uint32_t length = ftun_frs_read_u32(record + 8u);
    if (ftun_frs_read_u32(record + 12u) != 0u ||
        !ftun_frs_string(file, strings, offset, length, &text) ||
        !ftun_frs_keyword_text(text, length)) return FTUN_E_PROTOCOL;
  }
  if (node_count == 0u) return FTUN_OK;
  colors = (uint8_t *)calloc(node_count, 1u);
  stack = (ftun_frs_dfs_frame_t *)calloc(node_count, sizeof(*stack));
  if (colors == NULL || stack == NULL) {
    status = FTUN_E_LIMIT;
    goto done;
  }
  for (index = 0u; index < node_count && status == FTUN_OK; index++) {
    size_t depth = 0u;
    if (colors[index] != 0u) continue;
    colors[index] = 1u;
    stack[depth].node = node_start + index;
    stack[depth].edge_index = 0u;
    depth++;
    while (depth != 0u) {
      ftun_frs_dfs_frame_t *frame = &stack[depth - 1u];
      const uint8_t *node = file.data + (size_t)nodes->offset +
        ((size_t)frame->node - 1u) * FTUN_FRS_DOMAIN_NODE_STRIDE;
      uint32_t first = ftun_frs_read_u32(node);
      uint32_t count = ftun_frs_read_u32(node + 4u);
      if (frame->edge_index == count) {
        colors[frame->node - node_start] = 2u;
        depth--;
        continue;
      }
      {
        const uint8_t *edge = file.data + (size_t)edges->offset +
          ((size_t)first - 1u + frame->edge_index++) * FTUN_FRS_DOMAIN_EDGE_STRIDE;
        uint32_t child = ftun_frs_read_u32(edge + 12u);
        uint8_t color = colors[child - node_start];
        if (color == 1u) {
          status = FTUN_E_PROTOCOL;
          break;
        }
        if (color == 0u) {
          colors[child - node_start] = 1u;
          stack[depth].node = child;
          stack[depth].edge_index = 0u;
          depth++;
        }
      }
    }
  }

done:
  free(stack);
  free(colors);
  return status;
}

static ftun_status_t ftun_frs_validate_sets(ftun_bytes_t file,
                                             ftun_frs_layout_t *layout)
{
  const ftun_frs_section_layout_t *sets =
    ftun_frs_layout_section(layout, FTUN_FRS_SECTION_SETS);
  const ftun_frs_section_layout_t *strings =
    ftun_frs_layout_section(layout, FTUN_FRS_SECTION_STRINGS);
  const ftun_frs_section_layout_t *ranges =
    ftun_frs_layout_section(layout, FTUN_FRS_SECTION_IPV4_RANGES);
  const ftun_frs_section_layout_t *nodes =
    ftun_frs_layout_section(layout, FTUN_FRS_SECTION_DOMAIN_NODES);
  const ftun_frs_section_layout_t *edges =
    ftun_frs_layout_section(layout, FTUN_FRS_SECTION_DOMAIN_EDGES);
  const ftun_frs_section_layout_t *keywords =
    ftun_frs_layout_section(layout, FTUN_FRS_SECTION_KEYWORDS);
  ftun_frs_set_key_t *keys = NULL;
  uint32_t features = 0u;
  size_t index;
  ftun_status_t status = FTUN_OK;
  if (sets == NULL || sets->count > UINT32_MAX ||
      (sets->count != 0u && strings == NULL) ||
      (strings != NULL && strings->count != strings->length)) return FTUN_E_PROTOCOL;
  if (sets->count > SIZE_MAX / sizeof(*keys)) return FTUN_E_LIMIT;
  if (sets->count != 0u) {
    keys = (ftun_frs_set_key_t *)calloc((size_t)sets->count, sizeof(*keys));
    if (keys == NULL) return FTUN_E_LIMIT;
  }
  for (index = 0u; index < sets->count; index++) {
    const uint8_t *record = file.data + (size_t)sets->offset +
      index * FTUN_FRS_SET_STRIDE;
    const uint8_t *label;
    uint32_t set_id = ftun_frs_read_u32(record + FTUN_FRS_SET_ID);
    uint16_t kind = ftun_frs_read_u16(record + FTUN_FRS_SET_KIND);
    uint16_t flags = ftun_frs_read_u16(record + FTUN_FRS_SET_FLAGS);
    uint64_t label_offset = ftun_frs_read_u64(record + FTUN_FRS_SET_LABEL_OFFSET);
    uint32_t label_length = ftun_frs_read_u32(record + FTUN_FRS_SET_LABEL_LENGTH);
    uint32_t a_start = ftun_frs_read_u32(record + FTUN_FRS_SET_A_START);
    uint32_t a_count = ftun_frs_read_u32(record + FTUN_FRS_SET_A_COUNT);
    uint32_t b_start = ftun_frs_read_u32(record + FTUN_FRS_SET_B_START);
    uint32_t b_count = ftun_frs_read_u32(record + FTUN_FRS_SET_B_COUNT);
    uint32_t c_start = ftun_frs_read_u32(record + FTUN_FRS_SET_C_START);
    uint32_t c_count = ftun_frs_read_u32(record + FTUN_FRS_SET_C_COUNT);
    uint32_t root = ftun_frs_read_u32(record + FTUN_FRS_SET_ROOT);
    uint32_t encoding = ftun_frs_read_u32(record + FTUN_FRS_SET_ENCODING);
    if (set_id != index + 1u || flags != 0u ||
        ftun_frs_read_u32(record + FTUN_FRS_SET_RESERVED0) != 0u ||
        ftun_frs_read_u64(record + FTUN_FRS_SET_RESERVED1) != 0u ||
        !ftun_frs_string(file, strings, label_offset, label_length, &label) ||
        !ftun_frs_label_valid(label, label_length)) {
      status = FTUN_E_PROTOCOL;
      break;
    }
    keys[index].kind = kind;
    keys[index].label = label;
    keys[index].length = label_length;
    if (kind == FTUN_FRS_SET_IP) {
      features |= FTUN_FRS_FEATURE_IPV4;
      if (encoding != 1u || b_start != 0u || b_count != 0u ||
          c_start != 0u || c_count != 0u || root != 0u) {
        status = FTUN_E_PROTOCOL;
        break;
      }
      status = ftun_frs_validate_ipv4(file, ranges, a_start, a_count);
    } else if (kind == FTUN_FRS_SET_DOMAIN) {
      features |= FTUN_FRS_FEATURE_DOMAIN;
      if (c_count != 0u) features |= FTUN_FRS_FEATURE_KEYWORD;
      if (encoding != 2u) {
        status = FTUN_E_PROTOCOL;
        break;
      }
      status = ftun_frs_validate_domain(file, nodes, edges, keywords, strings,
                                        a_start, a_count, b_start, b_count,
                                        c_start, c_count, root);
    } else {
      status = FTUN_E_PROTOCOL;
    }
    if (status != FTUN_OK) break;
  }
  if (status == FTUN_OK && sets->count > 1u) {
    qsort(keys, (size_t)sets->count, sizeof(*keys), ftun_frs_set_key_compare);
    for (index = 1u; index < sets->count; index++) {
      if (ftun_frs_set_key_compare(&keys[index - 1u], &keys[index]) == 0) {
        status = FTUN_E_PROTOCOL;
        break;
      }
    }
  }
  if (status == FTUN_OK && features != layout->required_features) {
    status = FTUN_E_PROTOCOL;
  }
  free(keys);
  return status;
}

ftun_status_t ftun_frs_format_validate(ftun_bytes_t file,
                                       ftun_frs_layout_t *out)
{
  static const uint8_t magic[8] = {'F', 'T', 'U', 'N', 'F', 'R', 'S', 0};
  uint64_t directory_bytes;
  uint64_t directory_end;
  uint64_t previous_end;
  size_t index;
  ftun_frs_layout_t layout;
  ftun_status_t status = FTUN_E_PROTOCOL;
  if (out != NULL) memset(out, 0, sizeof(*out));
  memset(&layout, 0, sizeof(layout));
  if (file.data == NULL || out == NULL || file.length < FTUN_FRS_HEADER_BYTES) {
    return FTUN_E_INVALID;
  }
  if (memcmp(file.data, magic, sizeof(magic)) != 0 ||
      ftun_frs_read_u16(file.data + 8u) != 1u ||
      ftun_frs_read_u16(file.data + 10u) != 0u ||
      ftun_frs_read_u32(file.data + 12u) != FTUN_FRS_HEADER_BYTES ||
      ftun_frs_read_u64(file.data + 24u) != file.length ||
      ftun_frs_read_u64(file.data + 32u) != FTUN_FRS_HEADER_BYTES ||
      ftun_frs_read_u64(file.data + 40u) != 0u ||
      ftun_frs_read_u64(file.data + 56u) != 0u) return FTUN_E_PROTOCOL;
  layout.required_features = ftun_frs_read_u32(file.data + 16u);
  if ((layout.required_features & FTUN_FRS_FEATURE_IPV6_RESERVED) != 0u) {
    return FTUN_E_UNSUPPORTED;
  }
  if ((layout.required_features & ~(FTUN_FRS_FEATURE_IPV4 |
        FTUN_FRS_FEATURE_DOMAIN | FTUN_FRS_FEATURE_KEYWORD)) != 0u) {
    return FTUN_E_UNSUPPORTED;
  }
  layout.section_count = ftun_frs_read_u32(file.data + 20u);
  layout.file_bytes = ftun_frs_read_u64(file.data + 24u);
  layout.directory_offset = ftun_frs_read_u64(file.data + 32u);
  layout.file_checksum = ftun_frs_read_u64(file.data + 48u);
  layout.major = 1u;
  layout.minor = 0u;
  if (layout.section_count == 0u) {
    return FTUN_E_PROTOCOL;
  }
  directory_bytes = (uint64_t)layout.section_count * FTUN_FRS_DIRECTORY_ENTRY_BYTES;
  if (!ftun_frs_range(layout.directory_offset, directory_bytes, file.length)) {
    return FTUN_E_PROTOCOL;
  }
  directory_end = layout.directory_offset + directory_bytes;
  layout.sections = (ftun_frs_section_layout_t *)calloc(
    layout.section_count, sizeof(*layout.sections));
  if (layout.sections == NULL) return FTUN_E_LIMIT;
  previous_end = directory_end;
  for (index = 0u; index < layout.section_count; index++) {
    const uint8_t *entry = file.data + (size_t)layout.directory_offset +
      index * FTUN_FRS_DIRECTORY_ENTRY_BYTES;
    ftun_frs_section_layout_t *section = &layout.sections[index];
    uint32_t expected;
    section->type = ftun_frs_read_u32(entry);
    section->flags = ftun_frs_read_u32(entry + 4u);
    section->offset = ftun_frs_read_u64(entry + 8u);
    section->length = ftun_frs_read_u64(entry + 16u);
    section->count = ftun_frs_read_u64(entry + 24u);
    section->stride = ftun_frs_read_u32(entry + 32u);
    if (ftun_frs_read_u32(entry + 36u) != 0u ||
        (index != 0u && section->type <= layout.sections[index - 1u].type) ||
        section->offset < previous_end ||
        !ftun_frs_range(section->offset, section->length, file.length)) goto done;
    expected = ftun_frs_expected_stride(section->type);
    if (section->type == FTUN_FRS_SECTION_IPV6_RANGES_RESERVED) {
      status = FTUN_E_UNSUPPORTED;
      goto done;
    }
    if (expected != 0u) {
      if (section->flags != FTUN_FRS_SECTION_REQUIRED ||
          section->stride != expected ||
          section->count > UINT64_MAX / expected ||
          section->length != section->count * expected ||
          (section->count > UINT32_MAX &&
           section->type != FTUN_FRS_SECTION_STRINGS)) {
        goto done;
      }
    } else if (section->type >= FTUN_FRS_SECTION_METADATA_BASE) {
      if (section->flags != 0u || section->stride != 1u ||
          section->count != section->length) goto done;
    } else {
      goto done;
    }
    previous_end = section->offset + section->length;
  }
  if (previous_end != file.length ||
      ftun_frs_layout_section(&layout, FTUN_FRS_SECTION_SETS) == NULL ||
      ftun_frs_file_checksum(file) != layout.file_checksum) goto done;
  status = ftun_frs_validate_sets(file, &layout);
  if (status != FTUN_OK) goto done;
  *out = layout;
  return FTUN_OK;

done:
  ftun_frs_layout_clear(&layout);
  return status;
}
