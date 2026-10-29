set(ftun_sources_lib_resolver
  basic.c
  control.c
  socks5_transport.c
  control_channel.c
  control_transport.c
  dnswire.c
  resolver.c
  system.c
)
ftun_add_layer(lib_resolver ftun_lib_transport ftun_core)
