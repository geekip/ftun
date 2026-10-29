#include "proxy/outbound/reject.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(__linux__)
#include <dirent.h>
#endif

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "outbound reject contract failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

#if defined(__linux__)
static int open_fd_count(void)
{
  DIR *directory = opendir("/proc/self/fd");
  struct dirent *entry;
  int count = 0;
  if (directory == NULL) return -1;
  while ((entry = readdir(directory)) != NULL) {
    if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
      count++;
    }
  }
  if (closedir(directory) != 0) return -1;
  return count;
}
#endif

static ftun_metadata_t business_metadata(uint8_t network)
{
  ftun_metadata_t metadata;
  memset(&metadata, 0, sizeof(metadata));
  metadata.generation = 3u;
  metadata.known_fields = FTUN_META_PORT | FTUN_META_NETWORK;
  metadata.network = network;
  metadata.original_target.kind = FTUN_ADDRESS_IPV4;
  metadata.original_target.address[0] = 192u;
  metadata.original_target.address[1] = 0u;
  metadata.original_target.address[2] = 2u;
  metadata.original_target.address[3] = 8u;
  metadata.original_target.port = 443u;
  return metadata;
}

static int test_actions(void)
{
  ftun_metadata_t metadata = business_metadata(1u);
  ftun_reject_result_t result;
  CHECK(ftun_reject_classify(&metadata, false, &result) == FTUN_OK);
  CHECK(result.action == FTUN_REJECT_TCP_REFUSE &&
        result.terminal_status == FTUN_E_REJECTED && result.dns_rcode == 0u);
  CHECK(ftun_reject_request(&metadata) == FTUN_E_REJECTED);

  metadata.network = 2u;
  CHECK(ftun_reject_classify(&metadata, false, &result) == FTUN_OK);
  CHECK(result.action == FTUN_REJECT_UDP_DROP &&
        result.terminal_status == FTUN_E_REJECTED && result.dns_rcode == 0u);
  CHECK(ftun_reject_request(&metadata) == FTUN_E_REJECTED);

  memset(&metadata, 0, sizeof(metadata));
  metadata.generation = 3u;
  metadata.known_fields = FTUN_META_DOMAIN;
  metadata.domain.data = "query.example";
  metadata.domain.length = strlen(metadata.domain.data);
  metadata.domain_source = FTUN_DOMAIN_EXPLICIT;
  CHECK(ftun_reject_classify(&metadata, true, &result) == FTUN_OK);
  CHECK(result.action == FTUN_REJECT_DNS_REFUSED &&
        result.terminal_status == FTUN_E_REJECTED && result.dns_rcode == 5u);
  return 0;
}

static int test_invalid_boundaries(void)
{
  ftun_metadata_t metadata = business_metadata(1u);
  ftun_reject_result_t result;
  memset(&result, 0xa5, sizeof(result));
  metadata.known_fields &= ~FTUN_META_NETWORK;
  CHECK(ftun_reject_classify(&metadata, false, &result) == FTUN_E_INVALID);
  CHECK(result.action == 0 && result.terminal_status == FTUN_OK &&
        result.dns_rcode == 0u);
  metadata.known_fields |= FTUN_META_NETWORK;
  metadata.network = 0u;
  CHECK(ftun_reject_classify(&metadata, false, &result) == FTUN_E_INVALID);
  metadata.network = 3u;
  CHECK(ftun_reject_classify(&metadata, false, &result) == FTUN_E_INVALID);
  metadata.network = 1u;
  CHECK(ftun_reject_classify(&metadata, true, &result) == FTUN_E_INVALID);
  metadata.known_fields |= UINT32_C(0x80000000);
  CHECK(ftun_reject_classify(&metadata, false, &result) == FTUN_E_INVALID);
  CHECK(ftun_reject_classify(NULL, false, &result) == FTUN_E_INVALID);
  CHECK(ftun_reject_classify(&metadata, false, NULL) == FTUN_E_INVALID);
  CHECK(ftun_reject_request(NULL) == FTUN_E_INVALID);
  return 0;
}

static int test_no_socket_side_effect(void)
{
#if defined(__linux__)
  ftun_metadata_t metadata = business_metadata(1u);
  ftun_reject_result_t result;
  int before = open_fd_count();
  int after;
  size_t index;
  CHECK(before >= 0);
  for (index = 0u; index < 10000u; index++) {
    metadata.network = (index & 1u) == 0u ? 1u : 2u;
    CHECK(ftun_reject_classify(&metadata, false, &result) == FTUN_OK);
  }
  after = open_fd_count();
  CHECK(after == before);
#endif
  return 0;
}

int main(void)
{
  CHECK(test_actions() == 0);
  CHECK(test_invalid_boundaries() == 0);
  CHECK(test_no_socket_side_effect() == 0);
  return 0;
}
