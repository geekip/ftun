add_subdirectory(config)
set(ftun_sources_app
  capi/ftun.c
  capi/version.c
  cli/cmd_check.c
  cli/cmd_control.c
  cli/cmd_status.c
  cli/cmd_run.c
  cli/background.c
  cli/cmd_version.c
  cli/args.c
  cli/dispatch.c
  cli/render.c
  cli/result.c
  composition/egress.c
  composition/default.c
  composition/reload.c
  control/cleanup.c
  control/request.c
  control/server.c
  control/status.c
  control/status_json.c
  control/watchdog.c
)
if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
  list(APPEND ftun_sources_app
    composition/bridges.c
    composition/dns_dispatch.c
    composition/proxy_runtime.c
)
endif()
ftun_add_layer(app ftun_app_config ftun_core ftun_lib_resolver ftun_lib_transport ftun_lib_buffer)
foreach(dependency ftun_lib_tls ftun_dns ftun_proxy ftun_proxy_protocol ftun_lib_tun)
  if(TARGET ${dependency} AND (NOT dependency STREQUAL "ftun_lib_tls" OR FTUN_MODULE_PROXY STREQUAL "BUILTIN"))
    target_link_libraries(ftun_app PUBLIC ${dependency})
  endif()
endforeach()
target_include_directories(ftun_app SYSTEM PRIVATE "${PROJECT_SOURCE_DIR}/third_party/optparse")
target_compile_definitions(ftun_app PRIVATE FTUN_SOURCE_REVISION="${ftun_source_revision}"
  FTUN_BUILD_TARGET="${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
add_executable(ftun main.c)
target_include_directories(ftun PRIVATE "${PROJECT_SOURCE_DIR}/src")
target_link_libraries(ftun PRIVATE ftun_app)

target_include_directories(ftun_app PRIVATE "${PROJECT_SOURCE_DIR}/src")
