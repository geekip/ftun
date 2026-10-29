set(ftun_sources_dns
  cache.c
  dispatcher.c
  listener.c
  listener_runtime.c
  module.c
  plan.c
  server.c
  service.c
  upstream.c
  upstream_set.c
)
ftun_add_layer(dns ftun_lib_resolver ftun_lib_transport ftun_lib_buffer ftun_core)
