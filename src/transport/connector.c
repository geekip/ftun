#include "transport/connector.h"
#include <string.h>

ftun_status_t ftun_connector_register(ftun_connector_registry_t *registry,
                                      const ftun_connector_ops_t *ops)
{
  if (registry == NULL || ops == NULL || ops->kind == NULL || ops->kind[0] == '\0' ||
      ops->open == NULL ||
      (ops->capabilities & (FTUN_CONNECTOR_TCP | FTUN_CONNECTOR_UDP)) == 0u) {
    return FTUN_E_INVALID;
  }
  if (ftun_connector_lookup(registry, ops->kind) != NULL) return FTUN_E_INVALID;
  if (registry->count >= FTUN_CONNECTOR_MAX) return FTUN_E_LIMIT;
  registry->entries[registry->count++] = *ops;
  return FTUN_OK;
}

const ftun_connector_ops_t *ftun_connector_lookup(
  const ftun_connector_registry_t *registry, const char *kind)
{
  size_t index;
  if (registry == NULL || kind == NULL) return NULL;
  for (index = 0u; index < registry->count; index++) {
    if (strcmp(registry->entries[index].kind, kind) == 0) return &registry->entries[index];
  }
  return NULL;
}
