#define _POSIX_C_SOURCE 200809L

#include "frs_fixture.h"

#include "core/limits.h"
#include "proxy/runtime_state.h"
#include "proxy/frs/domain.h"
#include "proxy/frs/format.h"
#include "proxy/frs/frs.h"
#include "proxy/frs/ip.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x) do { \
  if (!(x)) { fprintf(stderr, "frs contract failed: %s\n", #x); return 1; } \
} while (0)

static ftun_string_t text(const char *value)
{
  ftun_string_t result;
  result.data = value;
  result.length = strlen(value);
  return result;
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

static void update_checksum(uint8_t *fixture, size_t fixture_bytes)
{
  put64(fixture + 48u,
        ftun_frs_file_checksum((ftun_bytes_t){fixture, fixture_bytes}));
}

static int check_graph_variants(void)
{
#define GRAPH_CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "frs graph contract failed: %s\n", #x); \
    free(fixture); \
    return 0; \
  } \
} while (0)
  uint8_t *fixture = NULL;
  size_t fixture_bytes = 0u;
  ftun_frs_view_t *view = NULL;

  GRAPH_CHECK(ftun_test_frs_fixture(&fixture, &fixture_bytes));

  /* 共享子节点会让节点 2 断连；两种结构都明确允许。 */
  put32(fixture + 744u + 12u, 3u);
  update_checksum(fixture, fixture_bytes);
  GRAPH_CHECK(ftun_frs_open_bytes((ftun_bytes_t){fixture, fixture_bytes}, &view) ==
              FTUN_OK);
  GRAPH_CHECK(ftun_frs_view_release(&view) == FTUN_OK && view == NULL);

  /* 根节点自环必须在不越过栈边界的前提下被拒绝。 */
  put32(fixture + 744u + 12u, 1u);
  update_checksum(fixture, fixture_bytes);
  GRAPH_CHECK(ftun_frs_open_bytes((ftun_bytes_t){fixture, fixture_bytes}, &view) ==
              FTUN_E_PROTOCOL && view == NULL);

  /* root -> 节点 2 -> root 构成长环。 */
  free(fixture);
  fixture = NULL;
  GRAPH_CHECK(ftun_test_frs_fixture(&fixture, &fixture_bytes));
  put32(fixture + 696u + 16u, 2u);
  put32(fixture + 696u + 20u, 1u);
  put32(fixture + 744u + 16u + 12u, 1u);
  update_checksum(fixture, fixture_bytes);
  GRAPH_CHECK(ftun_frs_open_bytes((ftun_bytes_t){fixture, fixture_bytes}, &view) ==
              FTUN_E_PROTOCOL && view == NULL);

  /* 子节点标识必须在索引颜色数组前完成检查。 */
  free(fixture);
  fixture = NULL;
  GRAPH_CHECK(ftun_test_frs_fixture(&fixture, &fixture_bytes));
  put32(fixture + 744u + 12u, 4u);
  update_checksum(fixture, fixture_bytes);
  GRAPH_CHECK(ftun_frs_open_bytes((ftun_bytes_t){fixture, fixture_bytes}, &view) ==
              FTUN_E_PROTOCOL && view == NULL);
  free(fixture);
#undef GRAPH_CHECK
  return 1;
}

int main(int argc, char **argv)
{
  uint8_t *fixture = NULL;
  size_t fixture_bytes = 0u;
  ftun_frs_view_t *view = NULL;
  ftun_frs_set_t *ip = NULL;
  ftun_frs_set_t *domain = NULL;
  ftun_frs_set_t *unicode = NULL;
  ftun_frs_set_t *missing = NULL;
  ftun_frs_view_info_t info;
  bool matched = false;
  uint8_t address[4] = {10u, 1u, 2u, 3u};
  char directory[] = "/tmp/ftun-frs-XXXXXX";
  char path[256];
  ftun_budget_t *budget = NULL;
  ftun_core_t *core = NULL;
  ftun_frs_view_t *mapped = NULL;
  ftun_frs_view_t *read_view = NULL;
  ftun_budget_usage_t budget_usage;
  if (argc == 3 && strcmp(argv[1], "--write") == 0) {
    CHECK(ftun_test_frs_fixture(&fixture, &fixture_bytes));
    CHECK(ftun_test_write_file(argv[2], fixture, fixture_bytes));
    free(fixture);
    return 0;
  }
  CHECK(argc == 1);
  CHECK(check_graph_variants());
  CHECK(ftun_test_frs_fixture(&fixture, &fixture_bytes));
  CHECK(ftun_frs_xxh64((ftun_bytes_t){NULL, 0u}, 0u) ==
        UINT64_C(0xef46db3751d8e999));
  CHECK(ftun_frs_open_bytes((ftun_bytes_t){fixture, fixture_bytes}, &view) == FTUN_OK);
  CHECK(ftun_frs_view_get_info(view, &info) == FTUN_OK);
  CHECK(info.file_bytes == fixture_bytes && info.set_count == 5u &&
        info.storage == FTUN_FRS_STORAGE_MEMORY && info.reference_count == 1u);
  CHECK(ftun_frs_bind(view, FTUN_FRS_SET_IP, text("CN"), &ip) == FTUN_OK);
  CHECK(ftun_frs_bind(view, FTUN_FRS_SET_DOMAIN, text("CN"), &domain) == FTUN_OK);
  CHECK(ftun_frs_bind(view, FTUN_FRS_SET_DOMAIN, text("关键词🚀"), &unicode) == FTUN_OK);
  CHECK(ftun_frs_bind(view, FTUN_FRS_SET_IP, text("cn"), &missing) == FTUN_E_EOF);
  CHECK(ftun_frs_bind(view, FTUN_FRS_SET_IP, text("关键词🚀"), &missing) ==
        FTUN_E_UNSUPPORTED);
  CHECK(ftun_frs_bind(view, FTUN_FRS_SET_IP, text("empty"), &missing) ==
        FTUN_E_REJECTED);
  CHECK(ftun_frs_ip_contains(ip, address, &matched) == FTUN_OK && matched);
  address[0] = 11u;
  CHECK(ftun_frs_ip_contains(ip, address, &matched) == FTUN_OK && !matched);
  CHECK(ftun_frs_domain_contains(domain, text("example.com"), &matched) == FTUN_OK && matched);
  CHECK(ftun_frs_domain_contains(domain, text("www.example.org"), &matched) == FTUN_OK && matched);
  CHECK(ftun_frs_domain_contains(domain, text("badexample.org"), &matched) == FTUN_OK && !matched);
  CHECK(ftun_frs_domain_contains(domain, text("myadsnode.net"), &matched) == FTUN_OK && matched);
  CHECK(ftun_frs_domain_contains(unicode, text("track.example"), &matched) == FTUN_OK && matched);
  CHECK(ftun_frs_domain_contains(domain, text("Example.com"), &matched) == FTUN_E_INVALID);
  {
    uint32_t state = UINT32_C(0x2468ace1);
    size_t iteration;
    for (iteration = 0u; iteration < 100000u; iteration++) {
      bool expected;
      state ^= state << 13u;
      state ^= state >> 17u;
      state ^= state << 5u;
      address[0] = (uint8_t)(state >> 24u);
      address[1] = (uint8_t)(state >> 16u);
      address[2] = (uint8_t)(state >> 8u);
      address[3] = (uint8_t)state;
      expected = address[0] == 10u ||
        (address[0] == 192u && address[1] == 0u && address[2] == 2u);
      CHECK(ftun_frs_ip_contains(ip, address, &matched) == FTUN_OK &&
            matched == expected);
    }
  }
  CHECK(ftun_frs_view_release(&view) == FTUN_OK && view == NULL);
  address[0] = 10u;
  CHECK(ftun_frs_ip_contains(ip, address, &matched) == FTUN_OK && matched);
  CHECK(ftun_frs_set_release(&ip) == FTUN_OK);
  CHECK(ftun_frs_set_release(&domain) == FTUN_OK);
  CHECK(ftun_frs_set_release(&unicode) == FTUN_OK);

  CHECK(ftun_budget_create(NULL, fixture_bytes * 4u, 0u, &budget) == FTUN_OK);
  CHECK(ftun_frs_open_bytes_budget(budget,
        (ftun_bytes_t){fixture, fixture_bytes}, &view) == FTUN_OK);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK &&
        budget_usage.used > fixture_bytes);
  CHECK(ftun_frs_view_release(&view) == FTUN_OK && view == NULL);
  CHECK(ftun_budget_get_usage(budget, &budget_usage) == FTUN_OK &&
        budget_usage.used == 0u);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);

  fixture[40] = 1u;
  CHECK(ftun_frs_open_bytes((ftun_bytes_t){fixture, fixture_bytes}, &view) ==
        FTUN_E_PROTOCOL && view == NULL);
  fixture[40] = 0u;
  fixture[48] ^= 1u;
  CHECK(ftun_frs_open_bytes((ftun_bytes_t){fixture, fixture_bytes}, &view) ==
        FTUN_E_PROTOCOL && view == NULL);
  fixture[48] ^= 1u;

  CHECK(mkdtemp(directory) != NULL);
  CHECK(snprintf(path, sizeof(path), "%s/rules.frs", directory) > 0);
  CHECK(ftun_test_write_file(path, fixture, fixture_bytes));
  CHECK(ftun_budget_create(NULL, fixture_bytes * 8u, fixture_bytes,
                           &budget) == FTUN_OK);
  CHECK(ftun_runtime_manager_create(budget, 2u, &core) == FTUN_OK);
  CHECK(ftun_frs_open(core, path, &mapped) == FTUN_OK);
  CHECK(ftun_frs_view_get_info(mapped, &info) == FTUN_OK &&
        info.storage == FTUN_FRS_STORAGE_MMAP);
  CHECK(ftun_frs_open_mode(core, path, FTUN_FRS_OPEN_READ, &read_view) == FTUN_OK);
  CHECK(ftun_frs_view_get_info(read_view, &info) == FTUN_OK &&
        info.storage == FTUN_FRS_STORAGE_READ);
  CHECK(ftun_frs_view_release(&mapped) == FTUN_OK);
  CHECK(ftun_frs_view_release(&read_view) == FTUN_OK);
  CHECK(ftun_runtime_manager_destroy(&core) == FTUN_OK);
  CHECK(ftun_budget_destroy(&budget) == FTUN_OK);
  CHECK(unlink(path) == 0 && rmdir(directory) == 0);
  free(fixture);
  return 0;
}
