#include "dns/config/validate.h"
#include "core/config/syntax.h"
#include <string.h>

int ftun_dns_server_exists(const ftun_config_dns_t *dns, const char *name)
{
  size_t index;
  if (name == NULL) return 0;
  for (index = 0u; index < dns->server_count; index++) {
    if (dns->servers[index].name != NULL &&
        strcmp(dns->servers[index].name, name) == 0) return 1;
  }
  return 0;
}

ftun_status_t ftun_config_validate_dns(const ftun_config_dns_t *dns,
                                       ftun_diagnostic_t *out)
{
  ftun_config_cidr_t fake_range;
  size_t index;
  size_t other;
  if (!ftun_cidr(dns->fake_ip.range, 0, &fake_range)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/fake-ip/range",
                                  "FakeIP range is invalid");
  }
  for (index = 0u; index < dns->bootstrap.count; index++) {
    uint32_t address;
    if (!ftun_bootstrap_address(dns->bootstrap.items[index], &address)) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/bootstrap",
                                    "bootstrap address is invalid");
    }
    if (dns->enable && dns->fake_ip.enable &&
        ftun_config_cidr_has(&fake_range, address)) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/bootstrap",
                                    "bootstrap address overlaps FakeIP range");
    }
  }
  for (index = 0u; index < dns->server_count; index++) {
    const ftun_config_dns_server_t *server = &dns->servers[index];
    if (!ftun_name_valid(server->name)) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/servers",
                                    "DNS server name is invalid");
    }
    for (other = 0u; other < index; other++) {
      if (strcmp(server->name, dns->servers[other].name) == 0) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/servers",
                                      "DNS server name is duplicated");
      }
    }
    if (server->addresses.count == 0u || server->addresses.items == NULL) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/servers",
                                    "DNS server address list is empty");
    }
    if (server->addresses.count > 4u) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/servers",
                                    "DNS server has more than 4 addresses");
    }
    for (other = 0u; other < server->addresses.count; other++) {
      uint32_t address = 0u;
      int is_ipv4 = 0;
      if (!ftun_server_address(server->addresses.items[other], 0, &address, &is_ipv4)) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/servers",
                                      "DNS server address is invalid");
      }
      if (dns->enable && dns->fake_ip.enable && is_ipv4 &&
          ftun_config_cidr_has(&fake_range, address)) {
        return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/servers",
                                      "DNS server address overlaps FakeIP range");
      }
    }

  }
  if (dns->enable && dns->default_server[0] != '\0' &&
      !ftun_dns_server_exists(dns, dns->default_server)) {
    return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/default-server",
                                  "default DNS server does not exist");
  }
  for (index = 0u; index < dns->listener_count; index++) {
    ftun_config_listener_t ignored;
    const ftun_config_dns_listener_t *listener = &dns->listeners[index];
    if (!ftun_listen_address(listener->listen, &ignored)) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/listeners",
                                    "DNS listen address is invalid");
    }
    if (dns->enable && listener->server[0] != '\0' &&
        !ftun_dns_server_exists(dns, listener->server)) {
      return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/listeners",
                                    "DNS listener server does not exist");
    }
  }
  if (dns->enable) {
    for (index = 0u; index < dns->listener_count; index++) {
      ftun_config_listener_t left;
      (void)ftun_listen_address(dns->listeners[index].listen, &left);
      for (other = index + 1u; other < dns->listener_count; other++) {
        ftun_config_listener_t right;
        (void)ftun_listen_address(dns->listeners[other].listen, &right);
        if (ftun_listener_conflict(&left, &right)) {
          return ftun_config_diagnostic(out, FTUN_E_INVALID, "/dns/listeners",
            "DNS listeners conflict");
        }
      }
    }
  }
  return FTUN_OK;
}
