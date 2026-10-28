#include "fuzz_common.h"

#include "frs_fixture.h"
#include "proxy/frs/domain.h"
#include "proxy/frs/format.h"
#include "proxy/frs/ip.h"
#include "proxy/frs/frs.h"

#include <stdlib.h>
#include <string.h>

/* FRS 规则文件读取。校验和不可能被随机变异碰对，所以每个输入跑两遍：原样（检查
 * 校验和/头部拒绝路径），以及重写校验和后（让变异进入目录、区段和索引的解析）。 */
/* 通过校验的文件继续走绑定和查询：标签取固定装置里的 "CN" 和输入自带的前几个字节。 */
static void probe_sets(ftun_frs_view_t *view)
{
  static const ftun_frs_set_kind_t kinds[] = {FTUN_FRS_SET_IP, FTUN_FRS_SET_DOMAIN};
  static const uint8_t address[4] = {1u, 2u, 3u, 4u};
  size_t index;
  for (index = 0u; index < sizeof(kinds) / sizeof(kinds[0]); index++) {
    ftun_frs_set_t *set = NULL;
    ftun_status_t status = ftun_frs_bind(view, kinds[index], (ftun_string_t){"CN", 2u}, &set);
    FUZZ_NOT_CORRUPT(status);
    if (status != FTUN_OK) {
      FUZZ_REQUIRE(set == NULL);
      continue;
    }
    {
      bool contained = false;
      status = kinds[index] == FTUN_FRS_SET_IP
        ? ftun_frs_ip_contains(set, address, &contained)
        : ftun_frs_domain_contains(set, (ftun_string_t){"example.cn", 10u}, &contained);
      FUZZ_NOT_CORRUPT(status);
    }
    FUZZ_REQUIRE(ftun_frs_set_release(&set) == FTUN_OK);
  }
}

static void validate_and_open(const uint8_t *data, size_t size)
{
  ftun_frs_layout_t layout;
  ftun_frs_view_t *view = NULL;
  ftun_status_t status;
  memset(&layout, 0, sizeof(layout));
  status = ftun_frs_format_validate((ftun_bytes_t){data, size}, &layout);
  FUZZ_NOT_CORRUPT(status);
  ftun_frs_layout_clear(&layout);
  status = ftun_frs_open_bytes((ftun_bytes_t){data, size}, &view);
  FUZZ_NOT_CORRUPT(status);
  if (status == FTUN_OK) {
    FUZZ_REQUIRE(view != NULL);
    probe_sets(view);
    FUZZ_REQUIRE(ftun_frs_view_release(&view) == FTUN_OK);
  } else {
    FUZZ_REQUIRE(view == NULL);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  uint8_t *copy;
  validate_and_open(data, size);
  if (size < FTUN_FRS_HEADER_BYTES) return 0;
  copy = (uint8_t *)malloc(size);
  FUZZ_REQUIRE(copy != NULL);
  memcpy(copy, data, size);
  memset(copy + 48u, 0, sizeof(uint64_t));
  ftun_frs_write_u64(copy + 48u, ftun_frs_file_checksum((ftun_bytes_t){copy, size}));
  validate_and_open(copy, size);
  free(copy);
  return 0;
}

void ftun_fuzz_seeds(ftun_fuzz_seed_fn add)
{
  uint8_t *fixture = NULL;
  size_t length = 0u;
  if (ftun_test_frs_fixture(&fixture, &length)) {
    add(fixture, length);
    free(fixture);
  }
}
