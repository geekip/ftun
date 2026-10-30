# 当前原生服务只实现 Linux；平台移植只替换本层源文件。
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" AND
   NOT (CMAKE_SYSTEM_NAME STREQUAL "Darwin" AND FTUN_PLATFORM_COMPILE_CHECK))
  message(FATAL_ERROR "Native platform services are not implemented for ${CMAKE_SYSTEM_NAME}")
endif()
# 高级变量用于编译替换检查，kqueue 尚不提供运行能力。
set(FTUN_POLLER_BACKEND "epoll" CACHE STRING "Platform poller backend")
mark_as_advanced(FTUN_POLLER_BACKEND)
if(FTUN_POLLER_BACKEND STREQUAL "epoll")
  set(ftun_poller_source linux/poller_epoll.c)
elseif(FTUN_POLLER_BACKEND STREQUAL "kqueue")
  set(ftun_poller_source bsd/poller_kqueue.c)
else()
  message(FATAL_ERROR "Unknown platform poller: ${FTUN_POLLER_BACKEND}")
endif()
set(ftun_sources_platform
  posix/clock.c
  posix/error.c
  posix/file.c
  posix/process.c
  posix/socket_io.c
  posix/socket.c
  posix/sysresolve.c
  posix/sockopt.c
  posix/thread.c
)
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  list(APPEND ftun_sources_platform bsd/poller_kqueue.c)
else()
  list(APPEND ftun_sources_platform ${ftun_poller_source}
  linux/route.c
  linux/route_transaction.c
  linux/route_transaction_async.c
  linux/route_async.c
  linux/tun.c
  linux/iface.c
  linux/random.c
  linux/process.c
  linux/socket_protect.c
)
endif()
ftun_add_layer(platform ftun_util Threads::Threads)
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  target_compile_definitions(ftun_platform PRIVATE _DARWIN_C_SOURCE=1)
endif()
if(NOT FTUN_HAVE_COMPILER_ATOMICS)
  target_link_libraries(ftun_platform PUBLIC atomic)
endif()
