#define _POSIX_C_SOURCE 200809L
#include "platform/sysresolve.h"
#include "util/endpoint.h"
#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>

static ftun_status_t ftun_system_resolver_errno(int error_code)
{
  if (error_code == ENOMEM || error_code == ENOBUFS || error_code == EMFILE ||
      error_code == ENFILE) return FTUN_E_LIMIT;
  if (error_code == EACCES || error_code == EPERM) return FTUN_E_REJECTED;
  if (error_code == ETIMEDOUT) return FTUN_E_TIMEOUT;
  if (error_code == EAFNOSUPPORT || error_code == ENOSYS) {
    return FTUN_E_UNSUPPORTED;
  }
  return FTUN_E_IO;
}

static ftun_status_t ftun_system_resolver_gai_status(int code)
{
  if (code == 0) return FTUN_OK;
  if (code == EAI_AGAIN) return FTUN_E_AGAIN;
  if (code == EAI_MEMORY) return FTUN_E_LIMIT;
  if (code == EAI_FAMILY || code == EAI_SOCKTYPE || code == EAI_SERVICE ||
      code == EAI_BADFLAGS) return FTUN_E_UNSUPPORTED;
#ifdef EAI_SYSTEM
  if (code == EAI_SYSTEM) return ftun_system_resolver_errno(errno);
#endif
  return FTUN_E_RESOLVE;
}

ftun_status_t ftun_sysresolve(const char *domain, uint8_t family, ftun_ip_t *result,
  size_t maximum, size_t *out_count)
{
  struct addrinfo hints = {0}, *addresses = NULL, *item;
  size_t count = 0u;
  int code;
  *out_count = 0u;
  hints.ai_family = family == FTUN_IP_V4 ? AF_INET : family == FTUN_IP_V6 ? AF_INET6 : AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  code = getaddrinfo(domain, NULL, &hints, &addresses);
  if (code != 0) return ftun_system_resolver_gai_status(code);
  for (item = addresses; item != NULL; item = item->ai_next) {
    ftun_ip_t ip = {0};
    size_t previous;
    if (item->ai_family == AF_INET && item->ai_addrlen >= sizeof(struct sockaddr_in)) {
      ip.family = FTUN_IP_V4;
      memcpy(ip.bytes, &((struct sockaddr_in *)item->ai_addr)->sin_addr, 4u);
    } else if (item->ai_family == AF_INET6 && item->ai_addrlen >= sizeof(struct sockaddr_in6)) {
      ip.family = FTUN_IP_V6;
      memcpy(ip.bytes, &((struct sockaddr_in6 *)item->ai_addr)->sin6_addr, 16u);
    } else continue;
    for (previous = 0u; previous < count && !ftun_ip_equal(&result[previous], &ip); previous++) {}
    if (previous < count) continue;
    if (count == maximum) { freeaddrinfo(addresses); return FTUN_E_LIMIT; }
    result[count++] = ip;
  }
  freeaddrinfo(addresses);
  if (count == 0u) return FTUN_E_RESOLVE;
  *out_count = count;
  return FTUN_OK;
}
ftun_status_t ftun_sysresolve_first(const char *host, uint8_t family, uint16_t port, ftun_endpoint_t *out)
{
  ftun_ip_t addresses[16];
  size_t count;
  ftun_status_t status = ftun_sysresolve(host, family, addresses, 16u, &count);
  if (status == FTUN_OK) ftun_endpoint_set_ip(out, &addresses[0], port);
  return status;
}

/* 读取本机解析器的首个nameserver；不回退到其他服务。 */
ftun_status_t ftun_system_nameserver(ftun_endpoint_t *out)
{
  FILE *file = fopen("/etc/resolv.conf", "r");
  char line[512];
  ftun_status_t status = FTUN_E_RESOLVE;
  if (file == NULL) return FTUN_E_IO;
  while (fgets(line, sizeof(line), file) != NULL) {
    char address[FTUN_IP_TEXT_BYTES];
    ftun_ip_t ip;
    char extra;
    if (sscanf(line, " nameserver %45s %c", address, &extra) >= 1 &&
        ftun_ip_parse(address, strlen(address), &ip)) {
      ftun_endpoint_set_ip(out, &ip, 53u);
      status = FTUN_OK;
      break;
    }
  }
  if (fclose(file) != 0 && status == FTUN_OK) status = FTUN_E_IO;
  return status;
}
