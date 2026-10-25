#define _POSIX_C_SOURCE 200809L

#include "app/cli/internal.h"

#include "config/config.h"
#include "config/parser.h"
#if defined(FTUN_HAVE_MODULE_FAKEIP)
#include "proxy/state/fakeip_store.h"
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if defined(FTUN_HAVE_MODULE_FAKEIP)
#include <sys/random.h>
#endif

#if defined(FTUN_HAVE_MODULE_FAKEIP)
static ftun_status_t ftun_cli_random_uuid(ftun_budget_t *budget,
  uint8_t uuid[FTUN_FAKEIP_UUID_BYTES])
{
  size_t offset = 0u;
  while (offset < FTUN_FAKEIP_UUID_BYTES) {
    ssize_t count = getrandom(uuid + offset,
                              FTUN_FAKEIP_UUID_BYTES - offset, 0u);
    if (count > 0) {
      offset += (size_t)count;
    } else if (count < 0 && errno == EINTR) {
      continue;
    } else {
      ftun_reservation_t *reservation = NULL;
      ftun_budget_resources_t resources = {0u, 1u, 0u};
      ftun_status_t status = ftun_budget_reserve_resources(budget, resources, &reservation);
      int descriptor;
      int closed;
      if (status != FTUN_OK) return status;
      descriptor = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
      if (descriptor < 0) {
        (void)ftun_reservation_release(&reservation);
        return FTUN_E_IO;
      }
      while (offset < FTUN_FAKEIP_UUID_BYTES) {
        count = read(descriptor, uuid + offset,
                     FTUN_FAKEIP_UUID_BYTES - offset);
        if (count > 0) offset += (size_t)count;
        else if (count < 0 && errno == EINTR) continue;
        else break;
      }
      closed = close(descriptor);
      (void)ftun_reservation_release(&reservation);
      if (closed != 0 || offset != FTUN_FAKEIP_UUID_BYTES) return FTUN_E_IO;
    }
  }
  uuid[6] = (uint8_t)((uuid[6] & 0x0fu) | 0x40u);
  uuid[8] = (uint8_t)((uuid[8] & 0x3fu) | 0x80u);
  return FTUN_OK;
}

static int ftun_cli_fakeip_range(const char *range,
                                 uint32_t *first, uint32_t *end)
{
  struct in_addr address;
  const char *slash;
  char ip[INET_ADDRSTRLEN];
  char *tail = NULL;
  unsigned long prefix;
  size_t length;
  uint32_t host;
  uint32_t mask;
  uint32_t network;
  uint32_t broadcast;
  if (range == NULL || first == NULL || end == NULL ||
      (slash = strchr(range, '/')) == NULL) return 0;
  length = (size_t)(slash - range);
  if (length == 0u || length >= sizeof(ip)) return 0;
  memcpy(ip, range, length);
  ip[length] = '\0';
  errno = 0;
  prefix = strtoul(slash + 1u, &tail, 10);
  if (errno != 0 || tail == slash + 1u || *tail != '\0' || prefix > 32u ||
      inet_pton(AF_INET, ip, &address) != 1) return 0;
  host = ntohl(address.s_addr);
  mask = prefix == 0u ? 0u : UINT32_MAX << (32u - (unsigned int)prefix);
  network = host & mask;
  broadcast = network | ~mask;
  if (host != network || network == UINT32_MAX ||
      network + 1u >= broadcast) return 0;
  *first = network + 1u;
  *end = broadcast;
  return 1;
}
#endif

int ftun_cli_fakeip_init(const char *path)
{
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  ftun_cli_checked_config_t checked = {0};
  ftun_config_t *config = NULL;
  ftun_fakeip_store_identity_t identity;
  char *directory = NULL;
  ftun_reservation_t *directory_reservation = NULL;
  size_t length;
  ftun_status_t status = ftun_cli_check_config(path, 0, &checked);
  if (status != FTUN_OK) {
    (void)ftun_cli_checked_config_destroy(&checked);
    return ftun_cli_error("fakeip init", status);
  }
  config = checked.config;
  if (!config->dns.enable || !config->dns.fake_ip.enable ||
      !config->dns.fake_ip.persist || config->base.cache_file == NULL) {
    (void)ftun_cli_checked_config_destroy(&checked);
    fputs("ftun: fakeip init: persistent FakeIP is not enabled\n", stderr);
    return 1;
  }
  memset(&identity, 0, sizeof(identity));
  if (!ftun_cli_fakeip_range(config->dns.fake_ip.range,
                             &identity.first_address,
                             &identity.end_address_exclusive) ||
      (status = ftun_cli_random_uuid(config->budget, identity.uuid)) != FTUN_OK) {
    (void)ftun_cli_checked_config_destroy(&checked);
    return ftun_cli_error("fakeip init", status == FTUN_OK ? FTUN_E_IO : status);
  }
  length = strlen(config->base.cache_file);
  if (length > SIZE_MAX - sizeof(".fakeip")) {
    (void)ftun_cli_checked_config_destroy(&checked);
    return ftun_cli_error("fakeip init", FTUN_E_LIMIT);
  }
  status = ftun_budget_reserve(config->budget, length + sizeof(".fakeip"), &directory_reservation);
  if (status != FTUN_OK) {
    (void)ftun_cli_checked_config_destroy(&checked);
    return ftun_cli_error("fakeip init", status);
  }
  directory = (char *)malloc(length + sizeof(".fakeip"));
  if (directory == NULL) {
    (void)ftun_reservation_release(&directory_reservation);
    (void)ftun_cli_checked_config_destroy(&checked);
    return ftun_cli_error("fakeip init", FTUN_E_LIMIT);
  }
  memcpy(directory, config->base.cache_file, length);
  memcpy(directory + length, ".fakeip", sizeof(".fakeip"));
  status = ftun_fakeip_store_initialize_budget(config->budget, directory, &identity);
  if (status == FTUN_OK) printf("FakeIP state initialized: %s\n", directory);
  free(directory);
  (void)ftun_reservation_release(&directory_reservation);
  {
    ftun_status_t cleanup_status = ftun_cli_checked_config_destroy(&checked);
    if (status == FTUN_OK) status = cleanup_status;
  }
  return status == FTUN_OK ? 0 : ftun_cli_error("fakeip init", status);
#else
  (void)path;
  return ftun_cli_error("fakeip init", FTUN_E_UNSUPPORTED);
#endif
}
