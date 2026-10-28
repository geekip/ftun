#include "reject.h"

#include <string.h>

#define FTUN_DNS_RCODE_REFUSED 5u

/* 纯策略终结映射。 */
ftun_status_t ftun_reject_classify(const ftun_metadata_t *metadata,
                                   bool dns_query,
                                   ftun_reject_result_t *out)
{
  const uint32_t known = FTUN_META_SOURCE | FTUN_META_PORT |
                         FTUN_META_NETWORK | FTUN_META_DOMAIN;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (metadata == NULL || out == NULL ||
      (metadata->known_fields & ~known) != 0u) return FTUN_E_INVALID;
  if (dns_query) {
    if ((metadata->known_fields & FTUN_META_NETWORK) != 0u ||
        metadata->network != 0u) return FTUN_E_INVALID;
    out->action = FTUN_REJECT_DNS_REFUSED;
    out->terminal_status = FTUN_E_REJECTED;
    out->dns_rcode = FTUN_DNS_RCODE_REFUSED;
    return FTUN_OK;
  }
  if ((metadata->known_fields & FTUN_META_NETWORK) == 0u) {
    return FTUN_E_INVALID;
  }
  if (metadata->network == 1u) {
    out->action = FTUN_REJECT_TCP_REFUSE;
  } else if (metadata->network == 2u) {
    out->action = FTUN_REJECT_UDP_DROP;
  } else {
    return FTUN_E_INVALID;
  }
  out->terminal_status = FTUN_E_REJECTED;
  return FTUN_OK;
}

ftun_status_t ftun_reject_request(const ftun_metadata_t *metadata)
{
  ftun_reject_result_t result;
  ftun_status_t status = ftun_reject_classify(metadata, false, &result);
  if (status != FTUN_OK) return status;
  return result.terminal_status;
}
