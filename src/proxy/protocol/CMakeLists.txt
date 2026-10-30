set(ftun_sources_proxy_protocol
  socks5_client.c
  socks5_codec.c
)
ftun_add_layer(proxy_protocol ftun_lib_resolver ftun_lib_transport)
