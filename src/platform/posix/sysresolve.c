#define _POSIX_C_SOURCE 200809L
#include "platform/sysresolve.h"
#include "util/ip.h"
#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>

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

static int ftun_system_resolver_contains(const uint8_t *addresses,
                                          size_t count,
                                          const uint8_t address[4])
{
  size_t index;
  for (index = 0u; index < count; index++) {
    if (memcmp(addresses + index * 4u, address, 4u) == 0) return 1;
  }
  return 0;
}

ftun_status_t ftun_sysresolve_ipv4(const char *domain, uint8_t *result,
  size_t maximum, size_t *out_count)
{
  struct addrinfo hints;
  struct addrinfo *addresses = NULL, *item;
  size_t count = 0u;
  int code;
  *out_count = 0u;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  code = getaddrinfo(domain, NULL, &hints, &addresses);
  if (code != 0) return ftun_system_resolver_gai_status(code);
  for (item = addresses; item != NULL; item = item->ai_next) {
    const struct sockaddr_in *address;
    const uint8_t *bytes;
    if (item->ai_family != AF_INET || item->ai_addr == NULL ||
        item->ai_addrlen < (socklen_t)sizeof(*address)) continue;
    address = (const struct sockaddr_in *)item->ai_addr;
    bytes = (const uint8_t *)&address->sin_addr.s_addr;
    if (ftun_system_resolver_contains(result, count, bytes)) continue;
    if (count >= maximum) {
      freeaddrinfo(addresses);
      return FTUN_E_LIMIT;
    }
    memcpy(result + count * 4u, bytes, 4u);
    count++;
  }
  freeaddrinfo(addresses);
  if (count == 0u) return FTUN_E_RESOLVE;
  *out_count = count;
  return FTUN_OK;
}

ftun_status_t ftun_sysresolve_first_ipv4(const char *host, uint16_t port, ftun_endpoint_t *out)
{
  char service[6];
  struct addrinfo hints;
  struct addrinfo *results = NULL;
  struct addrinfo *cursor;
  (void)snprintf(service, sizeof(service), "%u", (unsigned int)port);
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(host, service, &hints, &results) != 0) {
    return FTUN_E_RESOLVE;
  }
  for (cursor = results; cursor != NULL; cursor = cursor->ai_next) {
    if (cursor->ai_family == AF_INET && cursor->ai_addr != NULL &&
        cursor->ai_addrlen >= (socklen_t)sizeof(struct sockaddr_in)) {
      const struct sockaddr_in *address =
        (const struct sockaddr_in *)cursor->ai_addr;
      memset(out, 0, sizeof(*out));
      out->kind = FTUN_ADDRESS_IPV4;
      out->port = port;
      memcpy(out->address, &address->sin_addr.s_addr, 4u);
      freeaddrinfo(results);
      return FTUN_OK;
    }
  }
  freeaddrinfo(results);
  return FTUN_E_RESOLVE;
}

/* 读取本机解析器的首个 IPv4 nameserver；不回退到其他服务。 */
ftun_status_t ftun_system_nameserver(ftun_endpoint_t *out)
{
  FILE *file = fopen("/etc/resolv.conf", "r");
  char line[512];
  ftun_status_t status = FTUN_E_RESOLVE;
  if (file == NULL) return FTUN_E_IO;
  while (fgets(line, sizeof(line), file) != NULL) {
    char address[16];
    char extra;
    if (sscanf(line, " nameserver %15s %c", address, &extra) >= 1 &&
        ftun_ipv4_parse(address, strlen(address), out->address)) {
      out->kind = FTUN_ADDRESS_IPV4;
      out->port = 53u;
      status = FTUN_OK;
      break;
    }
  }
  if (fclose(file) != 0 && status == FTUN_OK) status = FTUN_E_IO;
  return status;
}
