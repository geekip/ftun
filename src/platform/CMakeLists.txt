# 原生后端按目标OS选择，公共层编译档仍保留以验证分层。
set(FTUN_POLLER_BACKEND "" CACHE STRING "Platform poller override")
mark_as_advanced(FTUN_POLLER_BACKEND)
if(NOT FTUN_POLLER_BACKEND STREQUAL "" AND
   NOT (CMAKE_SYSTEM_NAME STREQUAL "Linux" AND FTUN_POLLER_BACKEND STREQUAL "epoll") AND
   NOT (APPLE AND FTUN_POLLER_BACKEND STREQUAL "kqueue") AND
   NOT (WIN32 AND FTUN_POLLER_BACKEND STREQUAL "wepoll"))
  message(FATAL_ERROR "Poller ${FTUN_POLLER_BACKEND} is unavailable on ${CMAKE_SYSTEM_NAME}")
endif()
if(WIN32)
  set(ftun_sources_platform windows/clock.c windows/file.c windows/thread.c
    windows/socket.c windows/poller.c windows/process.c windows/random.c
    windows/sysresolve.c unsupported_network.c)
  if(FTUN_MODULE_TUN STREQUAL "BUILTIN")
    list(APPEND ftun_sources_platform windows/tun.c windows/tun_config.c)
  endif()
else()
  set(ftun_sources_platform posix/clock.c posix/error.c posix/file.c posix/process.c
    posix/socket_io.c posix/socket.c posix/sysresolve.c posix/sockopt.c posix/thread.c)
  if(APPLE)
    list(APPEND ftun_sources_platform bsd/poller_kqueue.c darwin/random.c
      darwin/process.c unsupported_network.c)
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND ftun_sources_platform linux/poller_epoll.c linux/route.c
      linux/route_transaction.c linux/route_transaction_async.c linux/route_async.c
      linux/tun.c linux/iface.c linux/random.c linux/process.c linux/socket_protect.c)
  else()
    message(FATAL_ERROR "Native platform services are not implemented for ${CMAKE_SYSTEM_NAME}")
  endif()
endif()
ftun_add_layer(platform ftun_util Threads::Threads)
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  target_compile_definitions(ftun_platform PRIVATE _DARWIN_C_SOURCE=1)
endif()
if(NOT FTUN_HAVE_COMPILER_ATOMICS)
  target_link_libraries(ftun_platform PUBLIC atomic)
endif()

if(WIN32)
  if(NOT EXISTS "${PROJECT_SOURCE_DIR}/third_party/wepoll/wepoll.c")
    message(FATAL_ERROR "wepoll submodule is missing; run: git submodule update --init third_party/wepoll")
  endif()
  target_include_directories(ftun_platform SYSTEM PRIVATE "${PROJECT_SOURCE_DIR}/third_party/wepoll")
  if(FTUN_MODULE_TUN STREQUAL "BUILTIN")
    if(NOT EXISTS "${PROJECT_SOURCE_DIR}/third_party/wintun/api/wintun.h")
      message(FATAL_ERROR "Wintun submodule is missing; run: git submodule update --init third_party/wintun")
    endif()
    target_include_directories(ftun_platform SYSTEM PRIVATE "${PROJECT_SOURCE_DIR}/third_party/wintun/api")
  endif()
  target_link_libraries(ftun_platform PUBLIC ws2_32 bcrypt iphlpapi ntdll advapi32)
endif()
