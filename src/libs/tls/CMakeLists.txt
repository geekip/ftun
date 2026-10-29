set(ftun_sources_lib_tls
  tls.c
  wolfssl_adapter.c
)
ftun_add_layer(lib_tls ftun_core wolfssl::wolfssl)
