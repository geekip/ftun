set(ftun_sources_platform
  linux/route.c
  linux/route_async.c
  linux/tun.c
  linux/iface.c
  linux/poller_epoll.c
  linux/random.c
  linux/process.c
  linux/socket_protect.c
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
ftun_add_layer(platform ftun_util Threads::Threads)
if(NOT FTUN_HAVE_COMPILER_ATOMICS)
  target_link_libraries(ftun_platform PUBLIC atomic)
endif()
