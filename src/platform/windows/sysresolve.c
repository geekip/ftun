#include "platform/sysresolve.h"
#include "util/endpoint.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <string.h>

ftun_status_t ftun_windows_sockets_initialize(void);
ftun_status_t ftun_sysresolve(const char *domain, uint8_t family, ftun_ip_t *result,
  size_t maximum, size_t *out_count)
{
  struct addrinfo hints = {0}, *addresses = NULL;
  size_t count = 0u;
  *out_count = 0u;
  ftun_status_t status = ftun_windows_sockets_initialize();
  if (status != FTUN_OK) return status;
  hints.ai_family = family == FTUN_IP_V4 ? AF_INET : family == FTUN_IP_V6 ? AF_INET6 : AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  int code = getaddrinfo(domain, NULL, &hints, &addresses);
  if (code != 0) return code == EAI_MEMORY ? FTUN_E_LIMIT : code == EAI_AGAIN ? FTUN_E_AGAIN : FTUN_E_RESOLVE;
  for (struct addrinfo *item = addresses; item != NULL; item = item->ai_next) {
    ftun_ip_t ip = {0};
    if (item->ai_family == AF_INET) {
      ip.family = FTUN_IP_V4;
      memcpy(ip.bytes, &((struct sockaddr_in *)item->ai_addr)->sin_addr, 4u);
    } else if (item->ai_family == AF_INET6) {
      ip.family = FTUN_IP_V6;
      memcpy(ip.bytes, &((struct sockaddr_in6 *)item->ai_addr)->sin6_addr, 16u);
    } else continue;
    size_t index;
    for (index = 0u; index < count && !ftun_ip_equal(&ip, &result[index]); index++) {}
    if (index < count) continue;
    if (count == maximum) { freeaddrinfo(addresses); return FTUN_E_LIMIT; }
    result[count++] = ip;
  }
  freeaddrinfo(addresses);
  *out_count = count;
  return count != 0u ? FTUN_OK : FTUN_E_RESOLVE;
}
ftun_status_t ftun_sysresolve_first(const char *domain, uint8_t family, uint16_t port, ftun_endpoint_t *out)
{
  ftun_ip_t addresses[16];
  size_t count;
  ftun_status_t status = ftun_sysresolve(domain, family, addresses, 16u, &count);
  if (status == FTUN_OK) ftun_endpoint_set_ip(out, &addresses[0], port);
  return status;
}
ftun_status_t ftun_system_nameserver(ftun_endpoint_t *out)
{
  union { IP_ADAPTER_ADDRESSES align; unsigned char bytes[16384]; } storage;
  ULONG bytes = sizeof(storage);
  IP_ADAPTER_ADDRESSES *adapters = (void *)&storage;
  DWORD code = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST |
    GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_FRIENDLY_NAME, NULL, adapters, &bytes);
  if (code != ERROR_SUCCESS) return code == ERROR_BUFFER_OVERFLOW ? FTUN_E_LIMIT : FTUN_E_IO;
  for (IP_ADAPTER_ADDRESSES *adapter = adapters; adapter != NULL; adapter = adapter->Next) {
    if (adapter->OperStatus != IfOperStatusUp) continue;
    for (IP_ADAPTER_DNS_SERVER_ADDRESS *entry = adapter->FirstDnsServerAddress; entry != NULL; entry = entry->Next) {
      ftun_ip_t ip = {0};
      if (entry->Address.lpSockaddr->sa_family == AF_INET) {
        ip.family = FTUN_IP_V4;
        memcpy(ip.bytes, &((struct sockaddr_in *)entry->Address.lpSockaddr)->sin_addr, 4u);
      } else if (entry->Address.lpSockaddr->sa_family == AF_INET6) {
        ip.family = FTUN_IP_V6;
        memcpy(ip.bytes, &((struct sockaddr_in6 *)entry->Address.lpSockaddr)->sin6_addr, 16u);
      } else continue;
      ftun_endpoint_set_ip(out, &ip, 53u);
      return FTUN_OK;
    }
  }
  return FTUN_E_RESOLVE;
}
