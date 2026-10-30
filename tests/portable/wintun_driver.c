#include "platform/tun.h"
#include "platform/tun_config.h"
#include "platform/clock.h"
#include "libs/tun/port.h"
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 显式执行的原生驱动验收：只创建隔离网卡和两条地址自带的直连路由。
 * 将内核发出的 UDP 包原样交换端点再注回；地址/端口交换不改变校验和。 */
static int echo_packet(ftun_packet_port_t *port, ftun_cidr_t address, const ftun_ip_t *peer)
{
  SOCKET channel = INVALID_SOCKET;
  struct sockaddr_storage local = {0}, remote = {0};
  char payload[] = "ftun-wintun-driver";
  BYTE packet[65535], temporary[16];
  char answer[64];
  int family = address.address.family == FTUN_IP_V4 ? AF_INET : AF_INET6;
  int socklen = family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
  size_t length, source = family == AF_INET ? 12u : 8u;
  size_t destination = family == AF_INET ? 16u : 24u, bytes = family == AF_INET ? 4u : 16u;
  uint64_t now, deadline;
  bool reflected = false;
  int result = 1;
  ftun_status_t status;
  local.ss_family = remote.ss_family = (ADDRESS_FAMILY)family;
  if (family == AF_INET) {
    memcpy(&((struct sockaddr_in *)&local)->sin_addr, address.address.bytes, 4u);
    memcpy(&((struct sockaddr_in *)&remote)->sin_addr, peer->bytes, 4u);
    ((struct sockaddr_in *)&remote)->sin_port = htons(54321u);
  } else {
    memcpy(&((struct sockaddr_in6 *)&local)->sin6_addr, address.address.bytes, 16u);
    memcpy(&((struct sockaddr_in6 *)&remote)->sin6_addr, peer->bytes, 16u);
    ((struct sockaddr_in6 *)&remote)->sin6_port = htons(54321u);
  }
  channel = socket(family, SOCK_DGRAM, IPPROTO_UDP);
  if (channel == INVALID_SOCKET || bind(channel, (struct sockaddr *)&local, socklen) != 0) goto done;
  u_long nonblocking = 1u;
  if (ioctlsocket(channel, FIONBIO, &nonblocking) != 0) goto done;
  if (sendto(channel, payload, sizeof(payload), 0, (struct sockaddr *)&remote, socklen) != sizeof(payload)) goto done;
  if (ftun_monotonic_now(&now) != FTUN_OK) goto done;
  deadline = now + 10000u;
  while (now < deadline) {
    status = ftun_tun_port_read(port, packet, sizeof(packet), &length);
    if (status == FTUN_OK && length >= destination + bytes &&
        packet[0] >> 4u == address.address.family &&
        memcmp(packet + source, address.address.bytes, bytes) == 0 &&
        memcmp(packet + destination, peer->bytes, bytes) == 0) {
      size_t udp = family == AF_INET ? (packet[0] & 15u) * 4u : 40u;
      bool protocol = family == AF_INET ? packet[9] == IPPROTO_UDP : packet[6] == IPPROTO_UDP;
      if (protocol && length == udp + 8u + sizeof(payload) &&
          memcmp(packet + udp + 8u, payload, sizeof(payload)) == 0) {
        memcpy(temporary, packet + source, bytes);
        memcpy(packet + source, packet + destination, bytes);
        memcpy(packet + destination, temporary, bytes);
        memcpy(temporary, packet + udp, 2u);
        memcpy(packet + udp, packet + udp + 2u, 2u);
        memcpy(packet + udp + 2u, temporary, 2u);
        if (ftun_tun_port_write(port, packet, length) != FTUN_OK) goto done;
        reflected = true;
      }
    } else if (status != FTUN_OK && status != FTUN_E_AGAIN) goto done;
    int received = recv(channel, answer, sizeof(answer), 0);
    if (received >= 0) {
      if (reflected && received == sizeof(payload) && memcmp(answer, payload, sizeof(payload)) == 0) result = 0;
      break;
    }
    if (WSAGetLastError() != WSAEWOULDBLOCK) goto done;
    Sleep(1u);
    if (ftun_monotonic_now(&now) != FTUN_OK) goto done;
  }
done:
  if (channel != INVALID_SOCKET) closesocket(channel);
  if (result) fprintf(stderr, "Wintun driver IPv%d UDP roundtrip failed (Winsock %d)\n", address.address.family, WSAGetLastError());
  return result;
}
int main(int argc, char **argv)
{
  ftun_packet_port_t *port = NULL;
  ftun_tun_spec_t device = {{"ftun-probe", 10u}, 1500u};
  ftun_cidr_t addresses[2];
  ftun_ip_t peers[2];
  WSADATA winsock;
  void *network = NULL;
  ftun_status_t status;
  int result = 1;
  if (argc != 2 || strcmp(argv[1], "--driver") != 0) {
    fputs("Run as administrator with --driver to create an isolated Wintun adapter.\n", stderr);
    return 2;
  }
  if (GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "wine_get_version") != NULL) {
    fputs("SKIP: Wine cannot exercise the Windows kernel driver.\n", stderr);
    return 77;
  }
  if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) return 1;
  ftun_cidr_parse("198.18.254.1/30", sizeof("198.18.254.1/30") - 1u, false, &addresses[0]);
  ftun_cidr_parse("fdfe:ff01::1/126", sizeof("fdfe:ff01::1/126") - 1u, false, &addresses[1]);
  ftun_ip_parse("198.18.254.2", sizeof("198.18.254.2") - 1u, &peers[0]);
  ftun_ip_parse("fdfe:ff01::2", sizeof("fdfe:ff01::2") - 1u, &peers[1]);
  status = ftun_tun_port_open(&device, &port);
  if (status != FTUN_OK) { fprintf(stderr, "Wintun adapter open failed: %d\n", status); goto done; }
  network = calloc(1u, ftun_platform_tun_config_size());
  if (network == NULL) goto done;
  status = ftun_platform_tun_configure(network, NULL, device.name, device.mtu, addresses, 2u);
  if (status != FTUN_OK) { fprintf(stderr, "Wintun address/MTU setup failed: %d\n", status); goto done; }
  if (echo_packet(port, addresses[0], &peers[0]) || echo_packet(port, addresses[1], &peers[1])) goto done;
  result = 0;
done:
  if (network != NULL) {
    if (ftun_platform_tun_unconfigure(network, NULL) != FTUN_OK) { fputs("Wintun address cleanup failed\n", stderr); result = 1; }
    free(network);
  }
  if (ftun_tun_port_close(&port) != FTUN_OK) result = 1;
  WSACleanup();
  if (!result) puts("Wintun native driver: IPv4/IPv6 kernel UDP roundtrips, address/MTU setup and removal passed");
  return result;
}
