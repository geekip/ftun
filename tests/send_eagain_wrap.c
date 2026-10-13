#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

ssize_t __real_send(int descriptor, const void *buffer, size_t length,
                    int flags);

ssize_t __wrap_send(int descriptor, const void *buffer, size_t length,
                    int flags)
{
  static int injected;
  const char *port_text = getenv("FTUN_TEST_SEND_EAGAIN_PORT");
  if (port_text != NULL && !__atomic_load_n(&injected, __ATOMIC_RELAXED)) {
    struct sockaddr_in peer;
    socklen_t peer_length = (socklen_t)sizeof(peer);
    int type = 0;
    socklen_t type_length = (socklen_t)sizeof(type);
    char *tail = NULL;
    unsigned long port;
    int target_match = 0;
    errno = 0;
    port = strtoul(port_text, &tail, 10);
    if (errno == 0 && tail != port_text && *tail == '\0' &&
        port != 0u && port <= UINT16_MAX &&
        getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &type, &type_length) == 0 &&
        type == SOCK_DGRAM) {
      const uint8_t *bytes = (const uint8_t *)buffer;
      if (getpeername(descriptor, (struct sockaddr *)&peer, &peer_length) == 0 &&
          peer.sin_family == AF_INET && ntohs(peer.sin_port) == (uint16_t)port) {
        target_match = 1;
      } else if (length >= 10u && bytes[0] == 0u && bytes[1] == 0u &&
                 bytes[2] == 0u && bytes[3] == 1u &&
                 (((unsigned int)bytes[8] << 8u) | bytes[9]) == port) {
        target_match = 1;
      }
    }
    if (target_match &&
        __atomic_exchange_n(&injected, 1, __ATOMIC_RELAXED) == 0) {
      static const char marker[] = "ftun-test-send-eagain\n";
      (void)write(STDERR_FILENO, marker, sizeof(marker) - 1u);
      errno = EAGAIN;
      return -1;
    }
  }
  return __real_send(descriptor, buffer, length, flags);
}
