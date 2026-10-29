set(ftun_sources_lib_tun
  device.c
  dispatch.c
  port.c
  interface.c
  routes.c
  routes_async.c
  owner.c
  path.c
  route.c
  service.c
)
ftun_add_layer(lib_tun ftun_lib_buffer ftun_lib_transport ftun_core)
