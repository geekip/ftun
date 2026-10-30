set(ftun_sources_lib_tun
  device.c
  dispatch.c
  port.c
  owner.c
  path.c
  route.c
  service.c
)
if(WIN32)
  list(APPEND ftun_sources_lib_tun interface_windows.c)
else()
  list(APPEND ftun_sources_lib_tun interface.c routes.c routes_async.c)
endif()
ftun_add_layer(lib_tun ftun_lib_buffer ftun_lib_transport ftun_core)
