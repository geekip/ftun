set(ftun_sources_lib_transport
  channel.c
  datagram.c
  dialer.c
  netmon.c
  path.c
  relay.c
  socket_path.c
  stream.c
  view.c
)
ftun_add_layer(lib_transport ftun_lib_buffer ftun_core ftun_platform)
