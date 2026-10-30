set(ftun_sources_proxy
  egress.c
  egress_path.c
  bindings.c
  control_resolver.c
  deadline.c
  dns/hooks.c
  dns/resolver_adapter.c
  http_route.c
  inbound/adapter.c
  inbound/http_codec.c
  inbound/mixed.c
  inbound/socks5.c
  listener.c
  maintenance.c
  module.c
  outbound/connector.c
  outbound/direct.c
  outbound/group/health.c
  outbound/group/url_test.c
  outbound/outbound.c
  outbound/reject.c
  outbound/socks5.c
  route/group.c
  route/router.c
  route/rule.c
  route/target.c
  runtime.c
  runtime_state.c
  session.c
  slot_pool.c
  snapshot.c
  sniff/http_host.c
  sniff/sniff.c
  sniff/tls_sni.c
  state/group_cache.c
  state/restore.c
  tcp_flow.c
  tun_bridge.c
  udp/session.c
  udp_assoc.c
)
if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
  list(APPEND ftun_sources_proxy
    frs/domain.c
    frs/format.c
    frs/frs.c
    frs/ip.c
)
endif()
if(FTUN_MODULE_FAKEIP STREQUAL "BUILTIN")
  list(APPEND ftun_sources_proxy
    fakeip/pool.c
    fakeip/snapshot.c
    fakeip/store.c
)
endif()
if(FTUN_MODULE_TUN STREQUAL "BUILTIN")
  list(APPEND ftun_sources_proxy
    netstack/ingress.c
    netstack/lwip_adapter.c
)
endif()
ftun_add_layer(proxy ftun_proxy_protocol ftun_lib_resolver ftun_lib_transport ftun_lib_http ftun_lib_tls ftun_lib_buffer ftun_core)
if(TARGET ftun_lib_tun)
  target_link_libraries(ftun_proxy PUBLIC ftun_lib_tun)
endif()
if(TARGET ftun_lwip)
  target_link_libraries(ftun_proxy PRIVATE ftun_lwip)
endif()
