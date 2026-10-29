#include "util/time_math.h"
#include "app/config/validate.h"
#include "core/config/syntax.h"
#include "dns/config/validate.h"
#include "proxy/config/validate.h"
#include "libs/tun/config/validate.h"
#include "app/config/compile.h"
#include "app/config/model.h"
#include "app/config/parser.h"
#include "core/limits.h"
#include "util/ip.h"
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int ftun_outbound_index_span(const ftun_config_t *config,
                                    const char *name, size_t length,
                                    size_t *out)
{
  size_t index;
  for (index = 0u; index < config->outbound_count; index++) {
    const char *candidate = config->outbounds[index].name;
    if (candidate != NULL && strlen(candidate) == length &&
        memcmp(candidate, name, length) == 0) {
      if (out != NULL) *out = index;
      return 1;
    }
  }
  return 0;
}

static int ftun_outbound_exists_span(const ftun_config_t *config,
                                     const char *name, size_t length)
{
  return ftun_span_equal(name, length, "DIRECT") ||
         ftun_span_equal(name, length, "REJECT") ||
         ftun_outbound_index_span(config, name, length, NULL);
}

static int ftun_outbound_exists(const ftun_config_t *config, const char *name)
{
  return name != NULL && ftun_outbound_exists_span(config, name, strlen(name));
}

static ftun_status_t ftun_validate_basic(const ftun_config_t *config,
                                         ftun_diagnostic_t *out)
{
  static const char *const levels[] = {
    "silent", "error", "warn", "info", "debug", "trace"
  };
  size_t index;
  int level_valid = 0;
  if (config->base.proxy.ipv6) {
    return ftun_config_diagnostic(out, FTUN_E_UNSUPPORTED, "/base/ipv6",
                                  "IPv6 mode is not supported");
  }
  if (config->base.watchdog_ms != 0u &&
      (config->base.watchdog_ms < FTUN_CONFIG_WATCHDOG_MINIMUM_MS ||
       config->base.watchdog_ms > FTUN_CONFIG_WATCHDOG_MAXIMUM_MS)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/base/watchdog",
                                  "watchdog must be 1s..10m or null");
  }
  {
    ftun_status_t status = ftun_config_validate_proxy_base(&config->base.proxy,
      config->inbounds, config->inbound_count, out);
    if (status != FTUN_OK) return status;
  }
  for (index = 0u; index < sizeof(levels) / sizeof(levels[0]); index++) {
    if (config->log.level != NULL && strcmp(config->log.level, levels[index]) == 0) {
      level_valid = 1;
      break;
    }
  }
  if (!level_valid) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/log/level",
                                  "log level is invalid");
  }
  if (!ftun_path_valid(config->log.file)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/log/file",
                                  "log file path is invalid");
  }
  if (config->log.max_size != 0u &&
      config->log.max_size < FTUN_CONFIG_LOG_MAX_SIZE_MINIMUM) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/log/max-size",
                                  "log max-size must be 0 or at least 65536 bytes");
  }
  if (config->log.max_files == 0u ||
      config->log.max_files > FTUN_CONFIG_LOG_MAX_FILES_MAXIMUM) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/log/max-files",
                                  "log max-files must be 1..32");
  }
  return FTUN_OK;
}

static ftun_status_t ftun_validate_listener_conflicts(const ftun_config_t *config,
  ftun_diagnostic_t *out)
{
  size_t left, right;
  if (!config->dns.enable) return FTUN_OK;
  for (left = 0u; left < config->inbound_count; left++) {
    ftun_config_listener_t inbound;
    if (config->inbounds[left].kind == FTUN_CONFIG_INBOUND_TUN) continue;
    (void)ftun_listen_address(config->inbounds[left].listen, &inbound);
    for (right = 0u; right < config->dns.listener_count; right++) {
      ftun_config_listener_t dns;
      (void)ftun_listen_address(config->dns.listeners[right].listen, &dns);
      if (ftun_listener_conflict(&inbound, &dns)) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/listeners",
          "DNS and inbound listeners conflict");
      }
    }
  }
  return FTUN_OK;
}

static ftun_status_t ftun_validate_dns_links(const ftun_config_t *config,
  ftun_diagnostic_t *out)
{
  size_t index;
  if (!config->dns.enable) return FTUN_OK;
  for (index = 0u; index < config->dns.server_count; index++) {
    if (!ftun_outbound_exists(config, config->dns.servers[index].outbound)) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/servers",
        "DNS server outbound does not exist");
    }
  }
  return FTUN_OK;
}

static ftun_status_t ftun_validate_outbound_links(const ftun_config_t *config,
  const ftun_config_cidr_t *fake_range, ftun_diagnostic_t *out)
{
  size_t index;
  for (index = 0u; index < config->outbound_count; index++) {
    const ftun_config_outbound_t *item = &config->outbounds[index];
    uint32_t address = 0u;
    int is_ipv4 = 0;
    if (config->dns.enable && item->dns_server[0] != '\0' &&
        !ftun_dns_server_exists(&config->dns, item->dns_server)) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/outbounds",
        "outbound DNS server does not exist");
    }
    if (!config->dns.enable || !config->dns.fake_ip.enable) continue;
    if (item->kind == FTUN_CONFIG_OUTBOUND_SOCKS5) {
      (void)ftun_server_address(item->server, 1, &address, &is_ipv4);
      if (is_ipv4 && ftun_config_cidr_has(fake_range, address)) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/outbounds",
          "SOCKS5 server overlaps FakeIP range");
      }
    } else if (item->kind == FTUN_CONFIG_OUTBOUND_URL_TEST) {
      (void)ftun_http_url(item->url, &address, &is_ipv4);
      if (is_ipv4 && ftun_config_cidr_has(fake_range, address)) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/outbounds",
          "health check URL overlaps FakeIP range");
      }
    }
  }
  return FTUN_OK;
}

static ftun_status_t ftun_validate_tun_overlap(const ftun_config_t *config,
  const ftun_config_cidr_t *fake_range, ftun_diagnostic_t *out)
{
  size_t index;
  ftun_config_cidr_t range;
  if (!config->dns.enable || !config->dns.fake_ip.enable) return FTUN_OK;
  if (config->tun.present) {
    (void)ftun_cidr(config->tun.ipv4_address, 0, &range);
    if (ftun_cidr_overlap(fake_range, &range)) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/fake-ip/range",
        "FakeIP range overlaps TUN network");
    }
  }
  for (index = 0u; index < config->inbound_count; index++) {
    if (config->inbounds[index].kind != FTUN_CONFIG_INBOUND_TUN) continue;
    (void)ftun_cidr(config->inbounds[index].ipv4_address, 0, &range);
    if (ftun_cidr_overlap(fake_range, &range)) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/fake-ip/range",
        "FakeIP range overlaps TUN network");
    }
  }
  return FTUN_OK;
}

static ftun_status_t ftun_validate_frs_links(const ftun_config_t *config,
  const ftun_config_cidr_t *fake_range, ftun_diagnostic_t *out)
{
  uint32_t address = 0u;
  int is_ipv4 = 0;
  if (!config->frs.active || !config->frs.auto_update || config->frs.url == NULL ||
      config->frs.url[0] == '\0') return FTUN_OK;
  if (config->dns.enable && config->frs.dns_server[0] != '\0' &&
      !ftun_dns_server_exists(&config->dns, config->frs.dns_server)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/frs/dns-server",
      "FRS DNS server does not exist");
  }
  (void)ftun_http_url(config->frs.url, &address, &is_ipv4);
  if (config->dns.enable && config->dns.fake_ip.enable && is_ipv4 &&
      ftun_config_cidr_has(fake_range, address)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/frs/url",
      "FRS update URL overlaps FakeIP range");
  }
  return FTUN_OK;
}
/* 无副作用语义校验。 */
ftun_status_t ftun_config_validate(const ftun_config_t *config, ftun_diagnostic_t *out)
{
  ftun_config_cidr_t fake_range;
  uint32_t required;
  size_t index;
  ftun_status_t status;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (config == NULL) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "",
                                  "configuration is missing");
  }
  required = ftun_config_required_modules(config);
  status = ftun_build_require_modules(required, out);
  if (status != FTUN_OK) {
    if (out != NULL) {
      const ftun_build_capabilities_t *capabilities = ftun_build_capabilities();
      static const char proxy_path[] = "/";
      static const char dns_path[] = "/dns/enable";
      static const char fakeip_path[] = "/dns/servers";
      static const char tun_path[] = "/inbounds";
      static const char frs_path[] = "/rules";
      if ((required & FTUN_BUILD_MODULE_PROXY) != 0u &&
          (capabilities->builtins & FTUN_BUILD_MODULE_PROXY) == 0u) {
        out->path.data = proxy_path;
        out->path.length = sizeof(proxy_path) - 1u;
      } else if ((required & FTUN_BUILD_MODULE_DNS) != 0u &&
          (capabilities->builtins & FTUN_BUILD_MODULE_DNS) == 0u) {
        out->path.data = dns_path;
        out->path.length = sizeof(dns_path) - 1u;
      } else if ((required & FTUN_BUILD_MODULE_FAKEIP) != 0u &&
                 (capabilities->builtins & FTUN_BUILD_MODULE_FAKEIP) == 0u) {
        out->path.data = fakeip_path;
        out->path.length = sizeof(fakeip_path) - 1u;
      } else if ((required & FTUN_BUILD_MODULE_TUN) != 0u &&
                 (capabilities->builtins & FTUN_BUILD_MODULE_TUN) == 0u) {
        out->path.data = tun_path;
        out->path.length = sizeof(tun_path) - 1u;
      } else {
        out->path.data = frs_path;
        out->path.length = sizeof(frs_path) - 1u;
      }
    }
    return status;
  }
  status = ftun_validate_basic(config, out);
  if (status != FTUN_OK) return status;
  status = ftun_config_validate_dns(&config->dns, out);
  if (status == FTUN_OK) status = ftun_validate_dns_links(config, out);
  if (status != FTUN_OK) return status;
  (void)ftun_cidr(config->dns.fake_ip.range, 0, &fake_range);
  status = ftun_config_validate_outbounds(config->document.budget, config->outbounds, config->outbound_count, out);
  if (status == FTUN_OK) status = ftun_validate_outbound_links(config, &fake_range, out);
  if (status != FTUN_OK) return status;
  status = ftun_config_validate_tun_device(&config->tun, out);
  if (status != FTUN_OK) return status;
  status = ftun_config_validate_inbounds(config->inbounds, config->inbound_count, config->outbounds, config->outbound_count, out);
  if (status == FTUN_OK) status = ftun_validate_tun_overlap(config, &fake_range, out);
  if (status != FTUN_OK) return status;
  status = ftun_validate_listener_conflicts(config, out);
  if (status != FTUN_OK) return status;
  status = ftun_config_validate_frs(&config->frs, config->outbounds, config->outbound_count, out);
  if (status == FTUN_OK) status = ftun_validate_frs_links(config, &fake_range, out);
  if (status != FTUN_OK) return status;
  for (index = 0u; index < config->rules.count; index++) {
    status = ftun_config_validate_rule(config->outbounds, config->outbound_count, config->rules.items[index], out);
    if (status != FTUN_OK) return status;
  }
  if (out != NULL) memset(out, 0, sizeof(*out));
  return FTUN_OK;
}
