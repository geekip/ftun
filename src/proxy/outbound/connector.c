#include "proxy/outbound/connector.h"
#include <string.h>

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
