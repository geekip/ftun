#ifndef FTUN_PLATFORM_POSIX_ERROR_H
#define FTUN_PLATFORM_POSIX_ERROR_H
#include "platform/socket.h"
ftun_socket_accept_disposition_t ftun_socket_accept_classify(int error_code);
#endif
