set(ftun_sources_dns_config parse.c validate.c)
ftun_add_layer(dns_config ftun_lib_resolver ftun_core)
