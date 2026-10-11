#include "router.h"

#include "core/runtime.h"

#include <stdlib.h>
#include <string.h>

/* 需求 REQ-ROUTE-001；任务 TASK-ROUTE-001；目标 0.3.0；验收 TEST-ROUTE-001。 */

struct ftun_route_table {
  ftun_rule_t **rules;
  size_t rule_count;
  uint64_t generation;
};

ftun_status_t ftun_route_table_accounted_bytes(const char *const *rules,
                                               size_t rule_count,
                                               size_t *out)
{
  size_t total = sizeof(ftun_route_table_t);
  size_t index;
  if (out != NULL) *out = 0u;
  if (out == NULL || (rule_count != 0u && rules == NULL) ||
      rule_count > SIZE_MAX / sizeof(ftun_rule_t *)) return FTUN_E_INVALID;
  if (total > SIZE_MAX - rule_count * sizeof(ftun_rule_t *)) {
    return FTUN_E_LIMIT;
  }
  total += rule_count * sizeof(ftun_rule_t *);
  for (index = 0u; index < rule_count; index++) {
    size_t length;
    const char *first;
    const char *second;
    if (rules[index] == NULL) return FTUN_E_INVALID;
    length = strlen(rules[index]);
    first = strchr(rules[index], ',');
    second = first == NULL ? NULL : strchr(first + 1u, ',');
    if (total > SIZE_MAX - sizeof(ftun_rule_t)) return FTUN_E_LIMIT;
    total += sizeof(ftun_rule_t);
    if (second != NULL) {
      size_t operand = (size_t)(second - first - 1u);
      if (total > SIZE_MAX - operand - 1u) return FTUN_E_LIMIT;
      total += operand + 1u;
    }
    if (length == SIZE_MAX) return FTUN_E_LIMIT;
  }
  *out = total;
  return FTUN_OK;
}

ftun_status_t ftun_route_table_create(
  uint64_t generation, const char *const *rules, size_t rule_count,
  ftun_rule_outbound_resolver_fn resolver, void *resolver_user,
  ftun_route_table_t **out)
{
  ftun_route_table_t *table;
  size_t index;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (out == NULL || (rule_count != 0u && rules == NULL) ||
      rule_count > SIZE_MAX / sizeof(ftun_rule_t *)) return FTUN_E_INVALID;
  table = (ftun_route_table_t *)calloc(1u, sizeof(*table));
  if (table == NULL) return FTUN_E_LIMIT;
  if (rule_count != 0u) {
    table->rules = (ftun_rule_t **)calloc(rule_count, sizeof(*table->rules));
    if (table->rules == NULL) {
      free(table);
      return FTUN_E_LIMIT;
    }
  }
  table->rule_count = rule_count;
  table->generation = generation;
  for (index = 0u; index < rule_count; index++) {
    status = ftun_rule_compile(rules[index], resolver, resolver_user,
                               &table->rules[index]);
    if (status != FTUN_OK) {
      (void)ftun_route_table_destroy(&table);
      return status;
    }
  }
  *out = table;
  return FTUN_OK;
}

ftun_status_t ftun_route_table_set_generation(ftun_route_table_t *table,
                                              uint64_t generation)
{
  if (table == NULL || generation == 0u) return FTUN_E_INVALID;
  if (table->generation != 0u) return FTUN_E_STALE;
  table->generation = generation;
  return FTUN_OK;
}

ftun_status_t ftun_route_table_destroy(ftun_route_table_t **table)
{
  ftun_route_table_t *owned;
  size_t index;
  if (table == NULL) return FTUN_E_INVALID;
  owned = *table;
  if (owned == NULL) return FTUN_OK;
  for (index = 0u; index < owned->rule_count; index++) {
    if (ftun_rule_destroy(&owned->rules[index]) != FTUN_OK) {
      return FTUN_E_STATE_CORRUPT;
    }
  }
  free(owned->rules);
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *table = NULL;
  return FTUN_OK;
}

static ftun_status_t ftun_route_copy_all_candidates(
  const ftun_metadata_t *metadata, ftun_route_result_t *out)
{
  size_t index;
  if (metadata->original_target.kind == FTUN_ADDRESS_IPV4 &&
      !metadata->original_is_fake) {
    out->allowed_storage[0] = metadata->original_target;
    out->allowed = out->allowed_storage;
    out->allowed_count = 1u;
    return FTUN_OK;
  }
  if (metadata->resolved_count > FTUN_ROUTE_MAX_CANDIDATES) {
    return FTUN_E_LIMIT;
  }
  for (index = 0u; index < metadata->resolved_count; index++) {
    if (metadata->resolved[index].kind != FTUN_ADDRESS_IPV4 ||
        metadata->resolved[index].domain.length != 0u) return FTUN_E_INVALID;
    out->allowed_storage[index] = metadata->resolved[index];
  }
  if (metadata->resolved_count != 0u) out->allowed = out->allowed_storage;
  out->allowed_count = metadata->resolved_count;
  return FTUN_OK;
}

static ftun_status_t ftun_route_copy_matching_candidates(
  const ftun_rule_t *rule, const ftun_metadata_t *metadata,
  ftun_route_result_t *out)
{
  size_t index;
  bool matched;
  ftun_status_t status;
  if (metadata->original_target.kind == FTUN_ADDRESS_IPV4 &&
      !metadata->original_is_fake) {
    status = ftun_rule_address_match(rule, &metadata->original_target,
                                     &matched);
    if (status != FTUN_OK) return status;
    if (matched) {
      out->allowed_storage[0] = metadata->original_target;
      out->allowed = out->allowed_storage;
      out->allowed_count = 1u;
    }
    return FTUN_OK;
  }
  if (metadata->resolved_count > FTUN_ROUTE_MAX_CANDIDATES) {
    return FTUN_E_LIMIT;
  }
  for (index = 0u; index < metadata->resolved_count; index++) {
    status = ftun_rule_address_match(rule, &metadata->resolved[index],
                                     &matched);
    if (status != FTUN_OK) return status;
    if (matched) {
      out->allowed_storage[out->allowed_count++] = metadata->resolved[index];
    }
  }
  if (out->allowed_count != 0u) out->allowed = out->allowed_storage;
  return FTUN_OK;
}

ftun_status_t ftun_route_table_evaluate(const ftun_route_table_t *table,
                                        const ftun_metadata_t *metadata,
                                        size_t resume_rule,
                                        ftun_route_result_t *out)
{
  size_t index;
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (table == NULL || metadata == NULL || out == NULL ||
      table->generation == 0u || metadata->generation == 0u ||
      resume_rule > table->rule_count) return FTUN_E_INVALID;
  if (metadata->generation != table->generation) return FTUN_E_STALE;
  if (metadata->resolved_count > FTUN_ROUTE_MAX_CANDIDATES) {
    return FTUN_E_LIMIT;
  }
  if (metadata->resolved_count != 0u && metadata->resolved == NULL) {
    return FTUN_E_INVALID;
  }
  for (index = resume_rule; index < table->rule_count; index++) {
    const ftun_rule_t *rule = table->rules[index];
    ftun_match_result_t match;
    status = ftun_rule_match(rule, metadata, &match);
    if (status != FTUN_OK) return status;
    if (match.needs_resolve) {
      out->kind = FTUN_ROUTE_NEED_RESOLVE;
      out->generation = table->generation;
      out->rule_index = index;
      out->resume_rule = index;
      return FTUN_OK;
    }
    if (!match.matched) continue;
    out->generation = table->generation;
    out->rule_index = index;
    out->resume_rule = index;
    out->outbound_id = rule->outbound_id;
    if (rule->outbound_id == FTUN_OUTBOUND_ID_REJECT) {
      out->kind = FTUN_ROUTE_DENY;
      return FTUN_OK;
    }
    out->kind = FTUN_ROUTE_READY;
    if (rule->kind == FTUN_RULE_IP_CIDR ||
        rule->kind == FTUN_RULE_GEOIP) {
      status = ftun_route_copy_matching_candidates(rule, metadata, out);
    } else {
      status = ftun_route_copy_all_candidates(metadata, out);
    }
    if (status != FTUN_OK) {
      memset(out, 0, sizeof(*out));
      return status;
    }
    return FTUN_OK;
  }
  out->kind = FTUN_ROUTE_READY;
  out->generation = table->generation;
  out->rule_index = table->rule_count;
  out->resume_rule = table->rule_count;
  out->outbound_id = FTUN_OUTBOUND_ID_DIRECT;
  status = ftun_route_copy_all_candidates(metadata, out);
  if (status != FTUN_OK) memset(out, 0, sizeof(*out));
  return status;
}

ftun_status_t ftun_route_table_evaluate_known(const ftun_route_table_t *table,
                                              const ftun_metadata_t *metadata,
                                              ftun_route_result_t *out)
{
  size_t index;
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (table == NULL || metadata == NULL || out == NULL ||
      table->generation == 0u || metadata->generation != table->generation ||
      (metadata->resolved_count != 0u && metadata->resolved == NULL)) {
    return FTUN_E_INVALID;
  }
  if (metadata->resolved_count > FTUN_ROUTE_MAX_CANDIDATES) {
    return FTUN_E_LIMIT;
  }
  for (index = 0u; index < table->rule_count; index++) {
    const ftun_rule_t *rule = table->rules[index];
    ftun_match_result_t match;
    status = ftun_rule_match(rule, metadata, &match);
    if (status != FTUN_OK) return status;
    if (match.needs_resolve || !match.matched) continue;
    out->generation = table->generation;
    out->rule_index = index;
    out->resume_rule = index;
    out->outbound_id = rule->outbound_id;
    if (rule->outbound_id == FTUN_OUTBOUND_ID_REJECT) {
      out->kind = FTUN_ROUTE_DENY;
      return FTUN_OK;
    }
    out->kind = FTUN_ROUTE_READY;
    if (rule->kind == FTUN_RULE_IP_CIDR || rule->kind == FTUN_RULE_GEOIP) {
      status = ftun_route_copy_matching_candidates(rule, metadata, out);
    } else {
      status = ftun_route_copy_all_candidates(metadata, out);
    }
    if (status != FTUN_OK) memset(out, 0, sizeof(*out));
    return status;
  }
  out->kind = FTUN_ROUTE_READY;
  out->generation = table->generation;
  out->rule_index = table->rule_count;
  out->resume_rule = table->rule_count;
  out->outbound_id = FTUN_OUTBOUND_ID_DIRECT;
  status = ftun_route_copy_all_candidates(metadata, out);
  if (status != FTUN_OK) memset(out, 0, sizeof(*out));
  return status;
}

ftun_status_t ftun_route_evaluate(const ftun_runtime_t *runtime,
                                  const ftun_metadata_t *metadata,
                                  size_t resume_rule,
                                  ftun_route_result_t *out)
{
  const ftun_route_table_t *table = NULL;
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (runtime == NULL || metadata == NULL || out == NULL) return FTUN_E_INVALID;
  status = ftun_runtime_route_table(runtime, &table);
  if (status != FTUN_OK) return status;
  return ftun_route_table_evaluate(table, metadata, resume_rule, out);
}
