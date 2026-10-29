#define _POSIX_C_SOURCE 200809L

#include "app/cli/internal.h"

#include "app/config/config.h"
#include "app/config/parser.h"
#include "util/ip.h"
#include "platform/random.h"
#if defined(FTUN_HAVE_MODULE_FAKEIP)
#include "proxy/fakeip/store.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(FTUN_HAVE_MODULE_FAKEIP)
#endif

#if defined(FTUN_HAVE_MODULE_FAKEIP)
static ftun_status_t ftun_cli_random_uuid(ftun_budget_t *budget,
  uint8_t uuid[FTUN_FAKEIP_UUID_BYTES])
{
  ftun_status_t status;
  status = ftun_random_bytes(uuid, FTUN_FAKEIP_UUID_BYTES);
  if (status != FTUN_OK) {
    ftun_reservation_t reservation = {0};
    status = ftun_budget_reserve_resources(budget,
      (ftun_budget_resources_t){0u, 1u, 0u}, &reservation);
    if (status != FTUN_OK) return status;
    status = ftun_random_device_bytes(uuid, FTUN_FAKEIP_UUID_BYTES);
    ftun_reservation_release(&reservation);
    if (status != FTUN_OK) return status;
  }
  uuid[6] = (uint8_t)((uuid[6] & 0x0fu) | 0x40u);
  uuid[8] = (uint8_t)((uuid[8] & 0x3fu) | 0x80u);
  return FTUN_OK;
}

static int ftun_cli_fakeip_range(const char *range,
                                 uint32_t *first, uint32_t *end)
{
  ftun_cidr_t cidr;
  return range != NULL && first != NULL && end != NULL &&
         ftun_cidr_parse(range, strlen(range), true, &cidr) &&
         ftun_cidr_ipv4_hosts(&cidr, first, end);
}
#endif

int ftun_cli_fakeip_init(const char *path)
{
#if defined(FTUN_HAVE_MODULE_FAKEIP)
  ftun_cli_checked_config_t checked = {0};
  ftun_config_t *config = NULL;
  ftun_fakeip_store_identity_t identity;
  char *directory = NULL;
  ftun_reservation_t directory_reservation = (ftun_reservation_t){0};
  size_t length;
  ftun_status_t status = ftun_cli_check_config(path, 0, &checked);
  if (status != FTUN_OK) {
    (void)ftun_cli_checked_config_destroy(&checked);
    return ftun_cli_error("fakeip init", status);
  }
  config = checked.config;
  if (!config->dns.enable || !config->dns.fake_ip.enable ||
      !config->dns.fake_ip.persist || config->base.proxy.cache_file == NULL) {
    (void)ftun_cli_checked_config_destroy(&checked);
    fputs("ftun: fakeip init: persistent FakeIP is not enabled\n", stderr);
    return 1;
  }
  memset(&identity, 0, sizeof(identity));
  if (!ftun_cli_fakeip_range(config->dns.fake_ip.range,
                             &identity.first_address,
                             &identity.end_address_exclusive) ||
      (status = ftun_cli_random_uuid(config->document.budget, identity.uuid)) != FTUN_OK) {
    (void)ftun_cli_checked_config_destroy(&checked);
    return ftun_cli_error("fakeip init", status == FTUN_OK ? FTUN_E_IO : status);
  }
  length = strlen(config->base.proxy.cache_file);
  if (length > SIZE_MAX - sizeof(".fakeip")) {
    (void)ftun_cli_checked_config_destroy(&checked);
    return ftun_cli_error("fakeip init", FTUN_E_LIMIT);
  }
  status = ftun_budget_reserve(config->document.budget, length + sizeof(".fakeip"), &directory_reservation);
  if (status != FTUN_OK) {
    (void)ftun_cli_checked_config_destroy(&checked);
    return ftun_cli_error("fakeip init", status);
  }
  directory = (char *)malloc(length + sizeof(".fakeip"));
  if (directory == NULL) {
    ftun_reservation_release(&directory_reservation);
    (void)ftun_cli_checked_config_destroy(&checked);
    return ftun_cli_error("fakeip init", FTUN_E_LIMIT);
  }
  memcpy(directory, config->base.proxy.cache_file, length);
  memcpy(directory + length, ".fakeip", sizeof(".fakeip"));
  status = ftun_fakeip_store_initialize_budget(config->document.budget, directory, &identity);
  if (status == FTUN_OK) printf("FakeIP state initialized: %s\n", directory);
  free(directory);
  ftun_reservation_release(&directory_reservation);
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
