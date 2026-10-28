#include "proxy/dns/fakeip.h"

#include "util/hash.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
  char *domain;
  size_t domain_length;
  uint32_t address;
  size_t references;
  ftun_reservation_t *reservation;
} ftun_fakeip_entry_t;

struct ftun_fakeip_service {
  ftun_budget_t *budget;
  ftun_fakeip_store_t *store;
  ftun_index_t *domains;
  ftun_index_t *addresses;
  ftun_fakeip_entry_t *entries;
  ftun_reservation_t *reservation;
  uint8_t uuid[FTUN_FAKEIP_UUID_BYTES];
  uint64_t sequence;
  uint32_t first_address;
  uint32_t end_address_exclusive;
  uint32_t next_address;
  uint32_t durable_end;
  size_t max_entries;
  size_t entry_count;
  size_t references;
  int persistent;
  int halted;
};

struct ftun_fakeip_handle {
  ftun_fakeip_service_t *service;
  ftun_reservation_t *reservation;
  uint32_t entry;
};

static int ftun_fakeip_domain_normalize(ftun_string_t input,
                                        char output[254], size_t *out_length)
{
  size_t effective = input.length;
  size_t start = 0u;
  size_t index;
  if (input.data == NULL || input.length == 0u || input.length > 254u ||
      memchr(input.data, '\0', input.length) != NULL) return 0;
  if (input.data[effective - 1u] == '.') effective--;
  if (effective == 0u || effective > 253u) return 0;
  for (index = 0u; index <= effective; index++) {
    if (index == effective || input.data[index] == '.') {
      size_t length = index - start;
      size_t cursor;
      if (length == 0u || length > 63u || input.data[start] == '-' ||
          input.data[index - 1u] == '-') return 0;
      for (cursor = start; cursor < index; cursor++) {
        unsigned char byte = (unsigned char)input.data[cursor];
        if (byte >= (unsigned char)'A' && byte <= (unsigned char)'Z') {
          byte = (unsigned char)(byte + ('a' - 'A'));
        }
        if (!((byte >= (unsigned char)'a' && byte <= (unsigned char)'z') ||
              (byte >= (unsigned char)'0' && byte <= (unsigned char)'9') ||
              byte == (unsigned char)'-')) return 0;
        output[cursor] = (char)byte;
      }
      if (index < effective) output[index] = '.';
      start = index + 1u;
    }
  }
  output[effective] = '\0';
  *out_length = effective;
  return 1;
}

static ftun_bytes_t ftun_fakeip_address_key(uint32_t address,
                                            uint8_t bytes[4])
{
  bytes[0] = (uint8_t)(address >> 24u);
  bytes[1] = (uint8_t)(address >> 16u);
  bytes[2] = (uint8_t)(address >> 8u);
  bytes[3] = (uint8_t)address;
  return (ftun_bytes_t){bytes, 4u};
}

static ftun_status_t ftun_fakeip_add(ftun_fakeip_service_t *service,
                                     const char *domain, size_t domain_length,
                                     uint32_t address)
{
  ftun_fakeip_entry_t *entry;
  ftun_reservation_t *reservation = NULL;
  uint8_t address_bytes[4];
  ftun_bytes_t domain_key = {(const uint8_t *)domain, domain_length};
  ftun_bytes_t address_key = ftun_fakeip_address_key(address, address_bytes);
  char *copy;
  uint32_t ignored;
  ftun_status_t status;
  if (service->entry_count >= service->max_entries ||
      service->entry_count > UINT32_MAX) return FTUN_E_LIMIT;
  if (ftun_hash_lookup(service->domains, domain_key, &ignored) == FTUN_OK ||
      ftun_hash_lookup(service->addresses, address_key, &ignored) == FTUN_OK) {
    return FTUN_E_STATE_CORRUPT;
  }
  status = ftun_budget_reserve(service->budget, domain_length + 1u,
                               &reservation);
  if (status != FTUN_OK) return status;
  copy = (char *)malloc(domain_length + 1u);
  if (copy == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  memcpy(copy, domain, domain_length);
  copy[domain_length] = '\0';
  status = ftun_index_insert(service->domains, domain_key,
                             (uint32_t)service->entry_count);
  if (status != FTUN_OK) goto fail;
  status = ftun_index_insert(service->addresses, address_key,
                             (uint32_t)service->entry_count);
  if (status != FTUN_OK) {
    (void)ftun_index_remove(service->domains, domain_key, NULL);
    goto fail;
  }
  entry = &service->entries[service->entry_count++];
  entry->domain = copy;
  entry->domain_length = domain_length;
  entry->address = address;
  entry->reservation = reservation;
  return FTUN_OK;

fail:
  free(copy);
  (void)ftun_reservation_release(&reservation);
  return status;
}

static ftun_status_t ftun_fakeip_refresh(ftun_fakeip_service_t *service)
{
  ftun_fakeip_store_info_t info;
  ftun_status_t status;
  if (!service->persistent) return FTUN_OK;
  status = ftun_fakeip_store_get_info(service->store, &info);
  if (status != FTUN_OK) return status;
  if (memcmp(info.identity.uuid, service->uuid, FTUN_FAKEIP_UUID_BYTES) != 0 ||
      info.identity.first_address != service->first_address ||
      info.identity.end_address_exclusive != service->end_address_exclusive ||
      info.reserved_end < service->durable_end || info.sequence < service->sequence) {
    service->halted = 1;
    return FTUN_E_STATE_CORRUPT;
  }
  service->durable_end = info.reserved_end;
  service->sequence = info.sequence;
  if (info.halted) service->halted = 1;
  return FTUN_OK;
}

ftun_status_t ftun_fakeip_service_create(
  const ftun_fakeip_service_options_t *options,
  ftun_fakeip_service_t **out)
{
  ftun_fakeip_service_t *service = NULL;
  ftun_fakeip_store_info_t store_info;
  ftun_reservation_t *reservation = NULL;
  size_t bytes;
  size_t initial_capacity;
  size_t index;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (options == NULL || options->budget == NULL || options->max_entries == 0u ||
      options->max_entries > UINT32_MAX || out == NULL) return FTUN_E_INVALID;
  if (options->max_entries > (SIZE_MAX - sizeof(*service)) /
                              sizeof(ftun_fakeip_entry_t)) return FTUN_E_LIMIT;
  bytes = sizeof(*service) +
          options->max_entries * sizeof(ftun_fakeip_entry_t);
  status = ftun_budget_reserve(options->budget, bytes, &reservation);
  if (status != FTUN_OK) return status;
  service = (ftun_fakeip_service_t *)calloc(1u, sizeof(*service));
  if (service == NULL) goto limit;
  service->entries = (ftun_fakeip_entry_t *)calloc(options->max_entries,
                                                    sizeof(*service->entries));
  if (service->entries == NULL) goto limit;
  service->budget = options->budget;
  service->store = options->store;
  service->reservation = reservation;
  service->max_entries = options->max_entries;
  initial_capacity = options->max_entries < 8u ? options->max_entries : 8u;
  status = ftun_index_create(options->budget, initial_capacity,
                             options->max_entries, NULL, NULL,
                             &service->domains);
  if (status != FTUN_OK) goto fail;
  status = ftun_index_create(options->budget, initial_capacity,
                             options->max_entries, NULL, NULL,
                             &service->addresses);
  if (status != FTUN_OK) goto fail;
  if (options->store != NULL) {
    if (options->snapshot == NULL) {
      status = FTUN_E_INVALID;
      goto fail;
    }
    status = ftun_fakeip_store_get_info(options->store, &store_info);
    if (status != FTUN_OK) goto fail;
    service->persistent = 1;
    memcpy(service->uuid, store_info.identity.uuid, FTUN_FAKEIP_UUID_BYTES);
    service->first_address = store_info.identity.first_address;
    service->end_address_exclusive = store_info.identity.end_address_exclusive;
    service->durable_end = store_info.reserved_end;
    service->next_address = store_info.reserved_end;
    service->sequence = store_info.sequence;
    service->halted = store_info.halted;
    if (memcmp(options->snapshot->uuid, service->uuid,
               FTUN_FAKEIP_UUID_BYTES) != 0 ||
        options->snapshot->sequence > service->sequence ||
        options->snapshot->mapping_count > service->max_entries) {
      status = FTUN_E_STATE_CORRUPT;
      goto fail;
    }
    for (index = 0u; index < options->snapshot->mapping_count; index++) {
      const ftun_fakeip_mapping_t *mapping = &options->snapshot->mappings[index];
      char normalized[254];
      size_t normalized_length = 0u;
      if (mapping->address < service->first_address ||
          mapping->address >= service->durable_end ||
          !ftun_fakeip_domain_normalize(mapping->domain, normalized,
                                        &normalized_length) ||
          normalized_length != mapping->domain.length ||
          memcmp(normalized, mapping->domain.data, normalized_length) != 0) {
        status = FTUN_E_STATE_CORRUPT;
        goto fail;
      }
      status = ftun_fakeip_add(service, normalized, normalized_length,
                               mapping->address);
      if (status != FTUN_OK) {
        status = FTUN_E_STATE_CORRUPT;
        goto fail;
      }
    }
  } else {
    if (options->snapshot != NULL ||
        options->first_address >= options->end_address_exclusive) {
      status = FTUN_E_INVALID;
      goto fail;
    }
    service->first_address = options->first_address;
    service->end_address_exclusive = options->end_address_exclusive;
    service->next_address = options->first_address;
    service->durable_end = options->end_address_exclusive;
  }
  *out = service;
  return FTUN_OK;

limit:
  status = FTUN_E_LIMIT;
fail:
  if (service != NULL) {
    size_t cursor;
    (void)ftun_index_destroy(&service->addresses);
    (void)ftun_index_destroy(&service->domains);
    for (cursor = 0u; cursor < service->entry_count; cursor++) {
      free(service->entries[cursor].domain);
      (void)ftun_reservation_release(&service->entries[cursor].reservation);
    }
    free(service->entries);
    free(service);
  }
  (void)ftun_reservation_release(&reservation);
  return status;
}

ftun_status_t ftun_fakeip_service_get_info(const ftun_fakeip_service_t *service,
                                           ftun_fakeip_service_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (service == NULL || out == NULL) return FTUN_E_INVALID;
  out->first_address = service->first_address;
  out->end_address_exclusive = service->end_address_exclusive;
  out->next_address = service->next_address;
  out->durable_end = service->durable_end;
  out->max_entries = service->max_entries;
  out->entries = service->entry_count;
  out->references = service->references;
  out->persistent = service->persistent != 0;
  out->halted = service->halted != 0;
  return FTUN_OK;
}

static ftun_status_t ftun_fakeip_handle_create(ftun_fakeip_service_t *service,
                                               uint32_t entry_index,
                                               ftun_fakeip_handle_t **out)
{
  ftun_fakeip_handle_t *handle;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  status = ftun_budget_reserve(service->budget, sizeof(*handle), &reservation);
  if (status != FTUN_OK) return status;
  handle = (ftun_fakeip_handle_t *)calloc(1u, sizeof(*handle));
  if (handle == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  handle->service = service;
  handle->entry = entry_index;
  handle->reservation = reservation;
  service->entries[entry_index].references++;
  service->references++;
  *out = handle;
  return FTUN_OK;
}

ftun_status_t ftun_fakeip_service_acquire(ftun_fakeip_service_t *service,
                                          ftun_string_t domain,
                                          ftun_fakeip_handle_t **out)
{
  char normalized[254];
  size_t length;
  uint32_t entry_index;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (service == NULL || out == NULL ||
      !ftun_fakeip_domain_normalize(domain, normalized, &length)) {
    return FTUN_E_INVALID;
  }
  status = ftun_hash_lookup(service->domains,
    (ftun_bytes_t){(const uint8_t *)normalized, length}, &entry_index);
  if (status == FTUN_OK) return ftun_fakeip_handle_create(service, entry_index, out);
  if (status != FTUN_E_EOF) return status;
  status = ftun_fakeip_refresh(service);
  if (status != FTUN_OK) return status;
  if (service->halted) return FTUN_E_STATE_CORRUPT;
  if (service->entry_count >= service->max_entries ||
      service->next_address >= service->end_address_exclusive) return FTUN_E_LIMIT;
  if (service->next_address >= service->durable_end) {
    return service->persistent ? FTUN_E_AGAIN : FTUN_E_LIMIT;
  }
  entry_index = (uint32_t)service->entry_count;
  status = ftun_fakeip_add(service, normalized, length, service->next_address);
  if (status != FTUN_OK) return status;
  service->next_address++;
  status = ftun_fakeip_handle_create(service, entry_index, out);
  if (status != FTUN_OK) {
    /* 映射身份已经发布到服务，不能因 handle 内存不足回收或复用。 */
    return status;
  }
  return FTUN_OK;
}

ftun_status_t ftun_fakeip_reverse(ftun_fakeip_service_t *service,
                                  uint32_t address,
                                  ftun_fakeip_handle_t **out)
{
  uint8_t address_bytes[4];
  uint32_t entry_index;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (service == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_hash_lookup(service->addresses,
                            ftun_fakeip_address_key(address, address_bytes),
                            &entry_index);
  if (status != FTUN_OK) return status;
  return ftun_fakeip_handle_create(service, entry_index, out);
}

ftun_status_t ftun_fakeip_handle_get(const ftun_fakeip_handle_t *handle,
                                     uint32_t *address,
                                     ftun_string_t *domain)
{
  const ftun_fakeip_entry_t *entry;
  if (address != NULL) *address = 0u;
  if (domain != NULL) memset(domain, 0, sizeof(*domain));
  if (handle == NULL || handle->service == NULL || address == NULL ||
      domain == NULL || handle->entry >= handle->service->entry_count) {
    return FTUN_E_INVALID;
  }
  entry = &handle->service->entries[handle->entry];
  *address = entry->address;
  domain->data = entry->domain;
  domain->length = entry->domain_length;
  return FTUN_OK;
}

ftun_status_t ftun_fakeip_handle_release(ftun_fakeip_handle_t **handle)
{
  ftun_fakeip_handle_t *owned;
  ftun_fakeip_service_t *service;
  ftun_reservation_t *reservation;
  if (handle == NULL) return FTUN_E_INVALID;
  owned = *handle;
  if (owned == NULL) return FTUN_OK;
  service = owned->service;
  if (service == NULL || owned->entry >= service->entry_count ||
      service->references == 0u ||
      service->entries[owned->entry].references == 0u) {
    return FTUN_E_STATE_CORRUPT;
  }
  service->entries[owned->entry].references--;
  service->references--;
  reservation = owned->reservation;
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *handle = NULL;
  return ftun_reservation_release(&reservation);
}

ftun_status_t ftun_fakeip_service_snapshot(ftun_fakeip_service_t *service,
                                           ftun_fakeip_snapshot_t **out)
{
  ftun_fakeip_snapshot_t *snapshot;
  ftun_reservation_t *reservation = NULL;
  uint8_t *block;
  size_t mapping_bytes;
  size_t domain_bytes = 0u;
  size_t allocation;
  size_t index;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (service == NULL || out == NULL || !service->persistent) {
    return FTUN_E_INVALID;
  }
  status = ftun_fakeip_refresh(service);
  if (status != FTUN_OK) return status;
  if (service->entry_count > SIZE_MAX / sizeof(ftun_fakeip_mapping_t)) {
    return FTUN_E_LIMIT;
  }
  mapping_bytes = service->entry_count * sizeof(ftun_fakeip_mapping_t);
  for (index = 0u; index < service->entry_count; index++) {
    if (domain_bytes > SIZE_MAX - service->entries[index].domain_length - 1u) {
      return FTUN_E_LIMIT;
    }
    domain_bytes += service->entries[index].domain_length + 1u;
  }
  if (sizeof(*snapshot) > SIZE_MAX - mapping_bytes ||
      sizeof(*snapshot) + mapping_bytes > SIZE_MAX - domain_bytes) {
    return FTUN_E_LIMIT;
  }
  allocation = sizeof(*snapshot) + mapping_bytes + domain_bytes;
  status = ftun_budget_reserve(service->budget, allocation, &reservation);
  if (status != FTUN_OK) return status;
  block = (uint8_t *)calloc(1u, allocation);
  if (block == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  snapshot = (ftun_fakeip_snapshot_t *)block;
  snapshot->mappings = (ftun_fakeip_mapping_t *)(block + sizeof(*snapshot));
  block += sizeof(*snapshot) + mapping_bytes;
  memcpy(snapshot->uuid, service->uuid, FTUN_FAKEIP_UUID_BYTES);
  snapshot->sequence = service->sequence;
  snapshot->mapping_count = service->entry_count;
  snapshot->reservation = reservation;
  snapshot->owned_block = snapshot;
  for (index = 0u; index < service->entry_count; index++) {
    const ftun_fakeip_entry_t *entry = &service->entries[index];
    snapshot->mappings[index].address = entry->address;
    snapshot->mappings[index].domain.data = (const char *)block;
    snapshot->mappings[index].domain.length = entry->domain_length;
    memcpy(block, entry->domain, entry->domain_length + 1u);
    block += entry->domain_length + 1u;
  }
  *out = snapshot;
  return FTUN_OK;
}

ftun_status_t ftun_fakeip_service_destroy(ftun_fakeip_service_t **service)
{
  ftun_fakeip_service_t *owned;
  ftun_reservation_t *reservation;
  size_t index;
  if (service == NULL) return FTUN_E_INVALID;
  owned = *service;
  if (owned == NULL) return FTUN_OK;
  if (owned->references != 0u) return FTUN_E_AGAIN;
  if (ftun_index_destroy(&owned->addresses) != FTUN_OK ||
      ftun_index_destroy(&owned->domains) != FTUN_OK) {
    return FTUN_E_STATE_CORRUPT;
  }
  for (index = 0u; index < owned->entry_count; index++) {
    ftun_reservation_t *entry_reservation = owned->entries[index].reservation;
    free(owned->entries[index].domain);
    if (ftun_reservation_release(&entry_reservation) != FTUN_OK) {
      return FTUN_E_STATE_CORRUPT;
    }
  }
  reservation = owned->reservation;
  free(owned->entries);
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *service = NULL;
  return ftun_reservation_release(&reservation);
}

ftun_status_t ftun_fakeip_acquire(ftun_fakeip_service_t *service,
                                  ftun_string_t domain,
                                  ftun_fakeip_handle_t **out)
{
  if (out != NULL) *out = NULL;
  if (service == NULL || out == NULL) return FTUN_E_INVALID;
  return ftun_fakeip_service_acquire(service, domain, out);
}
