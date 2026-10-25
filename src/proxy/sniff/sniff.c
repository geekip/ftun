#include "sniff.h"
#include "http_host.h"
#include "tls_sni.h"
#include <string.h>

/* REQ-SNIFF-001 / TASK-SNIFF-001 / TEST-SNIFF-001，目标 0.5.0：
 * ftun_sniff_domain 只补缺失域名且不消费预读字节。 */

ftun_status_t ftun_sniff_domain_with_budget(ftun_budget_t *budget, const ftun_metadata_t *metadata, ftun_bytes_t preread, ftun_sniff_result_t *out)
{
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (metadata == NULL || out == NULL ||
      (preread.length != 0u && preread.data == NULL)) return FTUN_E_INVALID;
  if (metadata->domain.length != 0u ||
      metadata->original_target.kind == FTUN_ADDRESS_DOMAIN) return FTUN_OK;
  if (preread.length == 0u) {
    out->need_more = true;
    return FTUN_OK;
  }
  status = preread.data[0] == 22u
    ? ftun_sniff_tls_sni_with_budget(budget, preread, out)
    : ftun_sniff_http_host(preread, out);
  if (status == FTUN_E_PROTOCOL) {
    memset(out, 0, sizeof(*out));
    return FTUN_OK;
  }
  return status;
}

ftun_status_t ftun_sniff_domain(const ftun_metadata_t *metadata, ftun_bytes_t preread, ftun_sniff_result_t *out)
{
  return ftun_sniff_domain_with_budget(NULL, metadata, preread, out);
}
