#include "frs_fixture.h"

#include "proxy/frs/format.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void put16(uint8_t *data, uint16_t value)
{
  data[0] = (uint8_t)value;
  data[1] = (uint8_t)(value >> 8u);
}

static void put32(uint8_t *data, uint32_t value)
{
  data[0] = (uint8_t)value;
  data[1] = (uint8_t)(value >> 8u);
  data[2] = (uint8_t)(value >> 16u);
  data[3] = (uint8_t)(value >> 24u);
}

static void put64(uint8_t *data, uint64_t value)
{
  put32(data, (uint32_t)value);
  put32(data + 4u, (uint32_t)(value >> 32u));
}

static void directory(uint8_t *file, size_t index, uint32_t type,
                      uint64_t offset, uint64_t length, uint64_t count,
                      uint32_t stride)
{
  uint8_t *entry = file + 64u + index * 40u;
  put32(entry, type);
  put32(entry + 4u, 1u);
  put64(entry + 8u, offset);
  put64(entry + 16u, length);
  put64(entry + 24u, count);
  put32(entry + 32u, stride);
}

static void set_record(uint8_t *record, uint32_t id, uint16_t kind,
                       uint64_t label_offset, uint32_t label_length,
                       uint32_t a_start, uint32_t a_count,
                       uint32_t b_start, uint32_t b_count,
                       uint32_t c_start, uint32_t c_count,
                       uint32_t root, uint32_t encoding)
{
  put32(record, id);
  put16(record + 4u, kind);
  put64(record + 8u, label_offset);
  put32(record + 16u, label_length);
  put32(record + 24u, a_start);
  put32(record + 28u, a_count);
  put32(record + 32u, b_start);
  put32(record + 36u, b_count);
  put32(record + 40u, c_start);
  put32(record + 44u, c_count);
  put32(record + 48u, root);
  put32(record + 52u, encoding);
}

int ftun_test_frs_fixture(uint8_t **out, size_t *length)
{
  static const uint8_t strings[] = {
    'C','N', 'a','d','s', 'e','m','p','t','y',
    'g','r','o','.','e','l','p','m','a','x','e',
    'm','o','c','.','e','l','p','m','a','x','e',
    't','r','a','c','k',
    0xe5,0x85,0xb3,0xe9,0x94,0xae,0xe8,0xaf,0x8d,
    0xf0,0x9f,0x9a,0x80
  };
  const size_t file_bytes = 808u;
  uint8_t *file;
  uint8_t *sets;
  uint8_t *nodes;
  uint8_t *edges;
  uint8_t *keywords;
  ftun_bytes_t bytes;
  if (out == NULL || length == NULL) return 0;
  *out = NULL;
  *length = 0u;
  file = (uint8_t *)calloc(file_bytes, 1u);
  if (file == NULL) return 0;
  memcpy(file, "FTUNFRS", 7u);
  put16(file + 8u, 1u);
  put16(file + 10u, 0u);
  put32(file + 12u, 64u);
  put32(file + 16u, 7u);
  put32(file + 20u, 6u);
  put64(file + 24u, file_bytes);
  put64(file + 32u, 64u);
  directory(file, 0u, 1u, 304u, 320u, 5u, 64u);
  directory(file, 1u, 2u, 624u, sizeof(strings), sizeof(strings), 1u);
  directory(file, 2u, 3u, 680u, 16u, 2u, 8u);
  directory(file, 3u, 4u, 696u, 48u, 3u, 16u);
  directory(file, 4u, 5u, 744u, 32u, 2u, 16u);
  directory(file, 5u, 6u, 776u, 32u, 2u, 16u);
  sets = file + 304u;
  set_record(sets, 1u, 1u, 0u, 2u, 1u, 2u, 0u, 0u, 0u, 0u, 0u, 1u);
  set_record(sets + 64u, 2u, 1u, 5u, 5u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u);
  set_record(sets + 128u, 3u, 2u, 0u, 2u, 1u, 3u, 1u, 2u, 1u, 1u, 1u, 2u);
  set_record(sets + 192u, 4u, 2u, 5u, 5u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 2u);
  set_record(sets + 256u, 5u, 2u, 37u, 13u, 0u, 0u, 0u, 0u, 2u, 1u, 0u, 2u);
  memcpy(file + 624u, strings, sizeof(strings));
  put32(file + 680u, UINT32_C(0x0a000000));
  put32(file + 684u, UINT32_C(0x0affffff));
  put32(file + 688u, UINT32_C(0xc0000200));
  put32(file + 692u, UINT32_C(0xc00002ff));
  nodes = file + 696u;
  put32(nodes, 1u);
  put32(nodes + 4u, 2u);
  put32(nodes + 16u + 8u, 2u);
  put32(nodes + 32u + 8u, 1u);
  edges = file + 744u;
  put64(edges, 10u);
  put32(edges + 8u, 11u);
  put32(edges + 12u, 2u);
  put64(edges + 16u, 21u);
  put32(edges + 24u, 11u);
  put32(edges + 28u, 3u);
  keywords = file + 776u;
  put64(keywords, 2u);
  put32(keywords + 8u, 3u);
  put64(keywords + 16u, 32u);
  put32(keywords + 24u, 5u);
  bytes.data = file;
  bytes.length = file_bytes;
  put64(file + 48u, ftun_frs_file_checksum(bytes));
  *out = file;
  *length = file_bytes;
  return 1;
}

int ftun_test_write_file(const char *path, const uint8_t *data, size_t length)
{
  FILE *file;
  if (path == NULL || data == NULL) return 0;
  file = fopen(path, "wb");
  if (file == NULL) return 0;
  if (fwrite(data, 1u, length, file) != length || fclose(file) != 0) return 0;
  return 1;
}
