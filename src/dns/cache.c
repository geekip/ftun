#include "cache.h"

#include "util/hash.h"
#include "util/time.h"

#include <stdlib.h>
#include <string.h>

/* 需求 REQ-DNSWIRE-001；任务 TASK-DNS-006；目标 0.3.0；验收 TEST-DNS-006。 */

#define FTUN_DNS_CACHE_KEY_BYTES (FTUN_DNS_MAX_NAME_BYTES + 33u)

typedef struct {
  uint8_t *key;
  size_t key_length;
  uint8_t *wire;
  size_t wire_length;
  size_t *ttl_offsets;
  uint32_t *ttls;
  size_t ttl_count;
  uint64_t stored_ms;
  uint64_t expires_ms;
  ftun_dns_cache_kind_t kind;
  ftun_status_t failure;
  ftun_reservation_t *reservation;
  void *owned_block;
  int occupied;
} ftun_dns_cache_entry_t;

struct ftun_dns_cache {
  ftun_budget_t *budget;
  ftun_index_t *index;
  ftun_dns_cache_entry_t *entries;
  ftun_reservation_t *reservation;
  ftun_dns_cache_now_fn now;
  void *now_user;
  size_t capacity;
  size_t entry_count;
};

static uint16_t ftun_cache_u16(const uint8_t *data)
{
  return (uint16_t)(((uint16_t)data[0] << 8u) | (uint16_t)data[1]);
}

static uint32_t ftun_cache_u32(const uint8_t *data)
{
  return ((uint32_t)data[0] << 24u) | ((uint32_t)data[1] << 16u) |
         ((uint32_t)data[2] << 8u) | (uint32_t)data[3];
}

static void ftun_cache_put_u32(uint8_t *data, uint32_t value)
{
  data[0] = (uint8_t)(value >> 24u);
  data[1] = (uint8_t)(value >> 16u);
  data[2] = (uint8_t)(value >> 8u);
  data[3] = (uint8_t)value;
}

static uint64_t ftun_cache_default_now(void *user)
{
  uint64_t now = 0u;
  (void)user;
  (void)ftun_monotonic_now(&now);
  return now;
}

static int ftun_cache_name_valid(ftun_dns_name_t name)
{
  size_t cursor = 0u;
  if (name.data == NULL || name.length == 0u ||
      name.length > FTUN_DNS_MAX_NAME_BYTES) return 0;
  while (cursor < name.length) {
    uint8_t length = name.data[cursor++];
    if (length == 0u) return cursor == name.length;
    if (length > 63u || (size_t)length > name.length - cursor) return 0;
    cursor += (size_t)length;
  }
  return 0;
}

static void ftun_cache_u64(uint8_t *data, uint64_t value)
{
  size_t index;
  for (index = 0u; index < 8u; index++) {
    data[index] = (uint8_t)(value >> ((7u - index) * 8u));
  }
}

static ftun_status_t ftun_cache_key(const ftun_dns_query_t *query,
                                    uint8_t output[FTUN_DNS_CACHE_KEY_BYTES],
                                    size_t *out_length)
{
  size_t index;
  size_t cursor = 0u;
  if (out_length != NULL) *out_length = 0u;
  if (query == NULL || out_length == NULL ||
      !ftun_cache_name_valid(query->question.name) ||
      query->resolution_mode < 1u || query->resolution_mode > 2u) {
    return FTUN_E_INVALID;
  }
  for (index = 0u; index < query->question.name.length; index++) {
    uint8_t value = query->question.name.data[index];
    if (value >= (uint8_t)'A' && value <= (uint8_t)'Z') {
      value = (uint8_t)(value + ((uint8_t)'a' - (uint8_t)'A'));
    }
    output[cursor++] = value;
  }
  output[cursor++] = (uint8_t)(query->question.type >> 8u);
  output[cursor++] = (uint8_t)query->question.type;
  output[cursor++] = (uint8_t)(query->question.class_code >> 8u);
  output[cursor++] = (uint8_t)query->question.class_code;
  output[cursor++] = (uint8_t)(query->flags >> 8u);
  output[cursor++] = (uint8_t)query->flags;
  ftun_cache_u64(output + cursor, query->policy_fingerprint);
  cursor += 8u;
  ftun_cache_u64(output + cursor, query->server_fingerprint);
  cursor += 8u;
  ftun_cache_put_u32(output + cursor, query->outbound_id);
  cursor += 4u;
  output[cursor++] = query->resolution_mode;
  output[cursor++] = query->dnssec_ok ? 1u : 0u;
  *out_length = cursor;
  return FTUN_OK;
}

static ftun_status_t ftun_cache_skip_name(ftun_bytes_t wire, size_t *cursor)
{
  size_t position;
  if (cursor == NULL || *cursor >= wire.length) return FTUN_E_PROTOCOL;
  position = *cursor;
  for (;;) {
    uint8_t length;
    if (position >= wire.length) return FTUN_E_PROTOCOL;
    length = wire.data[position++];
    if (length == 0u) {
      *cursor = position;
      return FTUN_OK;
    }
    if ((length & 0xc0u) == 0xc0u) {
      if (position >= wire.length) return FTUN_E_PROTOCOL;
      *cursor = position + 1u;
      return FTUN_OK;
    }
    if ((length & 0xc0u) != 0u || length > 63u ||
        (size_t)length > wire.length - position) return FTUN_E_PROTOCOL;
    position += (size_t)length;
  }
}

static ftun_status_t ftun_cache_ttls(ftun_bytes_t wire, size_t *offsets,
                                     uint32_t *ttls, size_t capacity,
                                     size_t *out_count, uint32_t *out_minimum,
                                     int *out_negative)
{
  ftun_dns_message_t *message = NULL;
  size_t cursor = FTUN_DNS_HEADER_BYTES;
  size_t records;
  size_t index;
  size_t count = 0u;
  uint32_t minimum = UINT32_MAX;
  uint32_t negative_minimum = UINT32_MAX;
  ftun_status_t status;
  if (out_count != NULL) *out_count = 0u;
  if (out_minimum != NULL) *out_minimum = 0u;
  if (out_negative != NULL) *out_negative = 0;
  if (out_count == NULL || out_minimum == NULL || out_negative == NULL) {
    return FTUN_E_INVALID;
  }
  status = ftun_dns_message_parse(wire, &message);
  if (status != FTUN_OK) return status;
  *out_negative = message->rcode == 3u ||
                  (message->rcode == 0u && message->answer_count == 0u);
  if (*out_negative) {
    for (index = 0u; index < message->record_count; index++) {
      const ftun_dns_record_t *record = &message->records[index];
      uint32_t value;
      if (record->section != FTUN_DNS_SECTION_AUTHORITY ||
          record->kind != FTUN_DNS_RECORD_ORDINARY || record->type != 6u ||
          record->rdata.length < 4u) continue;
      value = ftun_cache_u32(record->rdata.data + record->rdata.length - 4u);
      if (record->ttl < value) value = record->ttl;
      if (value < negative_minimum) negative_minimum = value;
    }
  }
  records = message->record_count;
  status = ftun_cache_skip_name(wire, &cursor);
  if (status != FTUN_OK || wire.length - cursor < 4u) goto protocol;
  cursor += 4u;
  for (index = 0u; index < records; index++) {
    uint16_t type;
    uint32_t ttl;
    uint16_t rdata_length;
    status = ftun_cache_skip_name(wire, &cursor);
    if (status != FTUN_OK || wire.length - cursor < 10u) goto protocol;
    type = ftun_cache_u16(wire.data + cursor);
    ttl = ftun_cache_u32(wire.data + cursor + 4u);
    rdata_length = ftun_cache_u16(wire.data + cursor + 8u);
    if (type != FTUN_DNS_TYPE_OPT) {
      if (count >= capacity && offsets != NULL) {
        status = FTUN_E_LIMIT;
        goto done;
      }
      if (offsets != NULL) {
        offsets[count] = cursor + 4u;
        ttls[count] = ttl;
      }
      count++;
      if (ttl < minimum) minimum = ttl;
    }
    cursor += 10u;
    if ((size_t)rdata_length > wire.length - cursor) goto protocol;
    cursor += (size_t)rdata_length;
  }
  if (cursor != wire.length) goto protocol;
  *out_count = count;
  if (*out_negative) {
    *out_minimum = negative_minimum == UINT32_MAX ? 0u : negative_minimum;
  } else {
    *out_minimum = minimum == UINT32_MAX ? 0u : minimum;
  }
  status = FTUN_OK;
  goto done;

protocol:
  status = status == FTUN_OK ? FTUN_E_PROTOCOL : status;
done:
  (void)ftun_dns_message_release(&message);
  return status;
}

static void ftun_cache_entry_clear(ftun_dns_cache_t *cache, size_t slot)
{
  ftun_dns_cache_entry_t *entry = &cache->entries[slot];
  ftun_reservation_t *reservation;
  if (!entry->occupied) return;
  (void)ftun_index_remove(cache->index,
    (ftun_bytes_t){entry->key, entry->key_length}, NULL);
  reservation = entry->reservation;
  free(entry->owned_block);
  memset(entry, 0, sizeof(*entry));
  if (cache->entry_count != 0u) cache->entry_count--;
  (void)ftun_reservation_release(&reservation);
}

static size_t ftun_cache_slot(ftun_dns_cache_t *cache, uint64_t now)
{
  size_t index;
  size_t earliest = 0u;
  for (index = 0u; index < cache->capacity; index++) {
    if (!cache->entries[index].occupied) return index;
    if (cache->entries[index].expires_ms <= now) {
      ftun_cache_entry_clear(cache, index);
      return index;
    }
    if (cache->entries[index].expires_ms <
        cache->entries[earliest].expires_ms) earliest = index;
  }
  ftun_cache_entry_clear(cache, earliest);
  return earliest;
}

static ftun_status_t ftun_cache_install(ftun_dns_cache_t *cache,
                                        const uint8_t *key,
                                        size_t key_length,
                                        ftun_bytes_t wire,
                                        const size_t *offsets,
                                        const uint32_t *ttls,
                                        size_t ttl_count,
                                        ftun_dns_cache_kind_t kind,
                                        ftun_status_t failure,
                                        uint64_t lifetime_ms)
{
  uint64_t now = cache->now(cache->now_user);
  uint32_t existing;
  size_t slot;
  size_t bytes;
  size_t data_bytes;
  uint8_t *block;
  ftun_reservation_t *reservation = NULL;
  ftun_dns_cache_entry_t *entry;
  ftun_status_t status;
  if (lifetime_ms == 0u || now > UINT64_MAX - lifetime_ms) return FTUN_E_INVALID;
  status = ftun_hash_lookup(cache->index,
    (ftun_bytes_t){key, key_length}, &existing);
  if (status == FTUN_OK) ftun_cache_entry_clear(cache, existing);
  else if (status != FTUN_E_EOF) return status;
  if (key_length > SIZE_MAX - wire.length) return FTUN_E_LIMIT;
  data_bytes = key_length + wire.length;
  if (data_bytes > SIZE_MAX - (sizeof(size_t) - 1u)) return FTUN_E_LIMIT;
  data_bytes = (data_bytes + sizeof(size_t) - 1u) & ~(sizeof(size_t) - 1u);
  if (ttl_count > SIZE_MAX / (sizeof(size_t) + sizeof(uint32_t)) ||
      data_bytes > SIZE_MAX -
        ttl_count * (sizeof(size_t) + sizeof(uint32_t))) return FTUN_E_LIMIT;
  bytes = data_bytes +
          ttl_count * (sizeof(size_t) + sizeof(uint32_t));
  status = ftun_budget_reserve(cache->budget, bytes, &reservation);
  if (status != FTUN_OK) return status;
  block = (uint8_t *)malloc(bytes == 0u ? 1u : bytes);
  if (block == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  slot = ftun_cache_slot(cache, now);
  entry = &cache->entries[slot];
  entry->key = block;
  memcpy(entry->key, key, key_length);
  entry->key_length = key_length;
  entry->wire = block + key_length;
  if (wire.length != 0u) memcpy(entry->wire, wire.data, wire.length);
  entry->wire_length = wire.length;
  entry->ttl_offsets = (size_t *)(void *)(block + data_bytes);
  entry->ttls = (uint32_t *)(void *)(entry->ttl_offsets + ttl_count);
  if (ttl_count != 0u) {
    memcpy(entry->ttl_offsets, offsets, ttl_count * sizeof(*offsets));
    memcpy(entry->ttls, ttls, ttl_count * sizeof(*ttls));
  }
  entry->ttl_count = ttl_count;
  entry->stored_ms = now;
  entry->expires_ms = now + lifetime_ms;
  entry->kind = kind;
  entry->failure = failure;
  entry->reservation = reservation;
  entry->owned_block = block;
  entry->occupied = 1;
  status = ftun_index_insert(cache->index,
    (ftun_bytes_t){entry->key, entry->key_length}, (uint32_t)slot);
  if (status != FTUN_OK) {
    free(block);
    memset(entry, 0, sizeof(*entry));
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  cache->entry_count++;
  return FTUN_OK;
}

ftun_status_t ftun_dns_cache_create(const ftun_dns_cache_options_t *options,
                                    ftun_dns_cache_t **out)
{
  ftun_dns_cache_t *cache = NULL;
  ftun_reservation_t *reservation = NULL;
  size_t bytes;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (options == NULL || options->budget == NULL ||
      options->max_entries == 0u || options->max_entries > UINT32_MAX ||
      out == NULL || options->max_entries > SIZE_MAX /
        sizeof(ftun_dns_cache_entry_t)) return FTUN_E_INVALID;
  bytes = sizeof(*cache) +
          options->max_entries * sizeof(ftun_dns_cache_entry_t);
  status = ftun_budget_reserve(options->budget, bytes, &reservation);
  if (status != FTUN_OK) return status;
  cache = (ftun_dns_cache_t *)calloc(1u, sizeof(*cache));
  if (cache == NULL) goto limit;
  cache->entries = (ftun_dns_cache_entry_t *)calloc(
    options->max_entries, sizeof(*cache->entries));
  if (cache->entries == NULL) goto limit;
  cache->budget = options->budget;
  cache->capacity = options->max_entries;
  cache->reservation = reservation;
  cache->now = options->now == NULL ? ftun_cache_default_now : options->now;
  cache->now_user = options->now_user;
  status = ftun_index_create(options->budget,
    options->max_entries < 8u ? options->max_entries : 8u,
    options->max_entries, NULL, NULL, &cache->index);
  if (status != FTUN_OK) goto fail;
  *out = cache;
  return FTUN_OK;

limit:
  status = FTUN_E_LIMIT;
fail:
  if (cache != NULL) {
    (void)ftun_index_destroy(&cache->index);
    free(cache->entries);
    free(cache);
  }
  (void)ftun_reservation_release(&reservation);
  return status;
}

ftun_status_t ftun_dns_cache_store(ftun_dns_cache_t *cache,
                                   const ftun_dns_query_t *query,
                                   ftun_bytes_t wire)
{
  uint8_t key[FTUN_DNS_CACHE_KEY_BYTES];
  size_t key_length;
  size_t offsets[FTUN_DNS_MAX_RECORDS];
  uint32_t ttls[FTUN_DNS_MAX_RECORDS];
  size_t ttl_count;
  uint32_t minimum;
  int negative;
  bool matches = false;
  ftun_dns_message_t *message = NULL;
  ftun_status_t status;
  if (cache == NULL) return FTUN_E_INVALID;
  status = ftun_cache_key(query, key, &key_length);
  if (status != FTUN_OK) return status;
  status = ftun_dns_message_parse(wire, &message);
  if (status != FTUN_OK) return status;
  status = ftun_dns_message_matches(message, query, query->transport,
                                    &query->upstream, &matches);
  (void)ftun_dns_message_release(&message);
  if (status != FTUN_OK || !matches) return status == FTUN_OK ?
    FTUN_E_PROTOCOL : status;
  status = ftun_cache_ttls(wire, offsets, ttls, FTUN_DNS_MAX_RECORDS,
                           &ttl_count, &minimum, &negative);
  if (status != FTUN_OK) return status;
  if (minimum == 0u) return FTUN_E_EOF;
  return ftun_cache_install(cache, key, key_length, wire, offsets, ttls,
    ttl_count, negative ? FTUN_DNS_CACHE_NEGATIVE : FTUN_DNS_CACHE_POSITIVE,
    FTUN_OK, (uint64_t)minimum * UINT64_C(1000));
}

ftun_status_t ftun_dns_cache_store_failure(ftun_dns_cache_t *cache,
                                           const ftun_dns_query_t *query,
                                           ftun_status_t failure,
                                           uint64_t suppress_ms)
{
  uint8_t key[FTUN_DNS_CACHE_KEY_BYTES];
  size_t key_length;
  ftun_status_t status;
  if (cache == NULL || failure == FTUN_OK || failure == FTUN_E_RESOLVE ||
      suppress_ms == 0u) return FTUN_E_INVALID;
  status = ftun_cache_key(query, key, &key_length);
  if (status != FTUN_OK) return status;
  return ftun_cache_install(cache, key, key_length,
    (ftun_bytes_t){NULL, 0u}, NULL, NULL, 0u,
    FTUN_DNS_CACHE_FAILURE, failure, suppress_ms);
}

ftun_status_t ftun_dns_cache_lookup(ftun_dns_cache_t *cache,
                                    const ftun_dns_query_t *query,
                                    ftun_dns_answer_t **out)
{
  uint8_t key[FTUN_DNS_CACHE_KEY_BYTES];
  size_t key_length;
  uint32_t slot;
  uint64_t now;
  uint64_t elapsed_seconds;
  size_t bytes;
  uint8_t *block;
  ftun_dns_answer_t *answer;
  ftun_reservation_t *reservation = NULL;
  ftun_dns_cache_entry_t *entry;
  size_t index;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (cache == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_cache_key(query, key, &key_length);
  if (status != FTUN_OK) return status;
  status = ftun_hash_lookup(cache->index,
    (ftun_bytes_t){key, key_length}, &slot);
  if (status != FTUN_OK) return status;
  if ((size_t)slot >= cache->capacity || !cache->entries[slot].occupied) {
    return FTUN_E_STATE_CORRUPT;
  }
  entry = &cache->entries[slot];
  now = cache->now(cache->now_user);
  if (now >= entry->expires_ms) {
    ftun_cache_entry_clear(cache, slot);
    return FTUN_E_EOF;
  }
  if (entry->kind == FTUN_DNS_CACHE_FAILURE) return entry->failure;
  if (sizeof(*answer) > SIZE_MAX - entry->wire_length) return FTUN_E_LIMIT;
  bytes = sizeof(*answer) + entry->wire_length;
  status = ftun_budget_reserve(cache->budget, bytes, &reservation);
  if (status != FTUN_OK) return status;
  block = (uint8_t *)calloc(1u, bytes);
  if (block == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  answer = (ftun_dns_answer_t *)block;
  answer->wire = block + sizeof(*answer);
  answer->wire_length = entry->wire_length;
  answer->kind = entry->kind;
  answer->reservation = reservation;
  answer->owned_block = block;
  memcpy(answer->wire, entry->wire, entry->wire_length);
  answer->wire[0] = (uint8_t)(query->id >> 8u);
  answer->wire[1] = (uint8_t)query->id;
  elapsed_seconds = (now - entry->stored_ms) / UINT64_C(1000);
  for (index = 0u; index < entry->ttl_count; index++) {
    uint32_t ttl = elapsed_seconds >= entry->ttls[index] ? 0u :
      entry->ttls[index] - (uint32_t)elapsed_seconds;
    if (entry->ttl_offsets[index] + 4u > answer->wire_length) {
      (void)ftun_dns_answer_release(&answer);
      return FTUN_E_STATE_CORRUPT;
    }
    ftun_cache_put_u32(answer->wire + entry->ttl_offsets[index], ttl);
  }
  *out = answer;
  return FTUN_OK;
}

ftun_status_t ftun_dns_answer_release(ftun_dns_answer_t **answer)
{
  ftun_dns_answer_t *owned;
  ftun_reservation_t *reservation;
  if (answer == NULL) return FTUN_E_INVALID;
  owned = *answer;
  if (owned == NULL) return FTUN_OK;
  reservation = owned->reservation;
  free(owned->owned_block);
  *answer = NULL;
  return ftun_reservation_release(&reservation);
}

ftun_status_t ftun_dns_cache_get_usage(const ftun_dns_cache_t *cache,
                                       ftun_dns_cache_usage_t *out)
{
  size_t index;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (cache == NULL || out == NULL) return FTUN_E_INVALID;
  out->capacity = cache->capacity;
  out->entries = cache->entry_count;
  for (index = 0u; index < cache->capacity; index++) {
    if (!cache->entries[index].occupied) continue;
    if (cache->entries[index].kind == FTUN_DNS_CACHE_POSITIVE) out->positive++;
    else if (cache->entries[index].kind == FTUN_DNS_CACHE_NEGATIVE) out->negative++;
    else if (cache->entries[index].kind == FTUN_DNS_CACHE_FAILURE) out->failures++;
  }
  return FTUN_OK;
}

ftun_status_t ftun_dns_cache_destroy(ftun_dns_cache_t **cache)
{
  ftun_dns_cache_t *owned;
  ftun_reservation_t *reservation;
  size_t index;
  if (cache == NULL) return FTUN_E_INVALID;
  owned = *cache;
  if (owned == NULL) return FTUN_OK;
  for (index = 0u; index < owned->capacity; index++) {
    ftun_cache_entry_clear(owned, index);
  }
  if (ftun_index_destroy(&owned->index) != FTUN_OK) {
    return FTUN_E_STATE_CORRUPT;
  }
  reservation = owned->reservation;
  free(owned->entries);
  free(owned);
  *cache = NULL;
  return ftun_reservation_release(&reservation);
}
