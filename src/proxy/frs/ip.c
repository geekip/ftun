#include "ip.h"

/* IPv4 合并区间查询。 */

ftun_status_t ftun_frs_ip_contains(const ftun_frs_set_t *set,
                                   const uint8_t ipv4[4], bool *out)
{
  ftun_bytes_t file;
  const ftun_frs_layout_t *layout;
  const ftun_frs_section_layout_t *ranges;
  const uint8_t *record;
  uint32_t start;
  uint32_t count;
  uint32_t value;
  uint32_t low = 0u;
  uint32_t high;
  ftun_status_t status;
  if (out != NULL) *out = false;
  if (set == NULL || ipv4 == NULL || out == NULL ||
      ftun_frs_set_kind(set) != FTUN_FRS_SET_IP) return FTUN_E_INVALID;
  status = ftun_frs_set_data(set, &file, &layout, &record);
  if (status != FTUN_OK) return status;
  ranges = ftun_frs_layout_section(layout, FTUN_FRS_SECTION_IPV4_RANGES);
  start = ftun_frs_read_u32(record + FTUN_FRS_SET_A_START);
  count = ftun_frs_read_u32(record + FTUN_FRS_SET_A_COUNT);
  if (count == 0u || ranges == NULL) return FTUN_E_STATE_CORRUPT;
  value = ((uint32_t)ipv4[0] << 24u) | ((uint32_t)ipv4[1] << 16u) |
          ((uint32_t)ipv4[2] << 8u) | (uint32_t)ipv4[3];
  high = count;
  while (low < high) {
    uint32_t middle = low + (high - low) / 2u;
    const uint8_t *range = file.data + (size_t)ranges->offset +
      ((size_t)start - 1u + middle) * FTUN_FRS_IPV4_RANGE_STRIDE;
    if (ftun_frs_read_u32(range) <= value) low = middle + 1u;
    else high = middle;
  }
  if (low != 0u) {
    const uint8_t *range = file.data + (size_t)ranges->offset +
      ((size_t)start - 1u + low - 1u) * FTUN_FRS_IPV4_RANGE_STRIDE;
    *out = value <= ftun_frs_read_u32(range + 4u);
  }
  return FTUN_OK;
}
