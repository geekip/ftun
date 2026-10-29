set(ftun_sources_app_config compile.c config.c parser.c validate.c)
ftun_add_layer(app_config ftun_dns_config ftun_proxy_config ftun_lib_tun_config ftun_core)
