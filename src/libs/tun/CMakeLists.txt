set(ftun_sources_lib_tun
  device.c
  dispatch.c
  linux/device.c
  linux/interface.c
  linux/routes.c
  linux/routes_async.c
  owner.c
  path.c
  route.c
  service.c
)
ftun_add_layer(lib_tun ftun_lib_buffer ftun_lib_transport ftun_core)
