cmake_minimum_required(VERSION 3.21)
project(FTUN VERSION 0.1.0 LANGUAGES C)
include(GNUInstallDirs)
include(CTest)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
option(FTUN_SANITIZERS "Enable address and undefined behavior checks" OFF)
option(FTUN_LTO "Require supported interprocedural optimization" OFF)
option(FTUN_SECTION_GC "Remove unused code and data on supported toolchains" ON)
option(FTUN_STATIC "Build fully static Linux executables" OFF)
option(FTUN_BUILD_GEO_TOOL "Build the standalone C converter skeleton" ON)
set(FTUN_OPTIMIZATION "balanced" CACHE STRING "balanced, speed or size")
set_property(CACHE FTUN_OPTIMIZATION PROPERTY STRINGS balanced speed size)
set(FTUN_EXTRA_COMPILE_OPTIONS "" CACHE STRING "Additional target options as a CMake list")
set(FTUN_EXTRA_LINK_OPTIONS "" CACHE STRING "Additional target link options as a CMake list")
if(NOT FTUN_OPTIMIZATION MATCHES "^(balanced|speed|size)$")
  message(FATAL_ERROR "Unsupported FTUN_OPTIMIZATION")
endif()
if(FTUN_STATIC AND NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "FTUN_STATIC requires a Linux target toolchain")
endif()
if(FTUN_STATIC AND FTUN_SANITIZERS)
  message(FATAL_ERROR "Full-static and sanitizer builds are separate supported profiles")
endif()
add_library(ftun_options INTERFACE)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(ftun_options INTERFACE -Wall -Wextra -Wvla -fno-strict-aliasing)
  if(FTUN_OPTIMIZATION STREQUAL "speed")
    set(ftun_opt -O3)
  elseif(FTUN_OPTIMIZATION STREQUAL "size")
    set(ftun_opt -Os)
  else()
    set(ftun_opt -O2)
  endif()
  target_compile_options(ftun_options INTERFACE
    "$<$<CONFIG:Debug>:-O0;-g>" "$<$<NOT:$<CONFIG:Debug>>:${ftun_opt}>")
  target_link_options(ftun_options INTERFACE "$<$<NOT:$<CONFIG:Debug>>:${ftun_opt}>")
  target_compile_definitions(ftun_options INTERFACE "$<$<NOT:$<CONFIG:Debug>>:NDEBUG>")
  if(FTUN_SECTION_GC)
    target_compile_options(ftun_options INTERFACE -ffunction-sections -fdata-sections)
    if(APPLE)
      target_link_options(ftun_options INTERFACE "LINKER:-dead_strip")
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      target_link_options(ftun_options INTERFACE "LINKER:--gc-sections")
    else()
      message(FATAL_ERROR "Section GC has not been defined for this target")
    endif()
  endif()
  if(FTUN_SANITIZERS)
    target_compile_options(ftun_options INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer -Wconversion -Wsign-conversion)
    target_link_options(ftun_options INTERFACE -fsanitize=address,undefined)
  endif()
else()
  if(FTUN_SANITIZERS OR FTUN_SECTION_GC)
    message(FATAL_ERROR "Requested compiler options have not been defined for this compiler")
  endif()
endif()
target_compile_options(ftun_options INTERFACE ${FTUN_EXTRA_COMPILE_OPTIONS})
target_link_options(ftun_options INTERFACE ${FTUN_EXTRA_LINK_OPTIONS})
if(FTUN_LTO)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT ftun_ipo_ok OUTPUT ftun_ipo_error LANGUAGES C)
  if(NOT ftun_ipo_ok)
    message(FATAL_ERROR "Requested LTO is unavailable: ${ftun_ipo_error}")
  endif()
endif()
# 0.1 骨架不发现/下载第三方库。未来逐模块接入须验证锁文件与目标 ABI。
# DEC-025 / TASK-BUILD-MODULES-002：真实模块接入时按 OFF/BUILTIN 分组源码、
# 注册项与依赖；不提供动态功能插件。下列骨架清单不代表已实现的能力。
add_library(ftun_core STATIC
  src/core/core.c
  src/util/error.c
  src/core/runtime.c
  src/core/session.c
  src/core/state.c
  src/core/budget.c
  src/core/operation.c
  src/core/worker.c
  src/config/config.c
  src/config/parser.c
  src/config/validate.c
  src/config/compile.c
  src/inbound/inbound.c
  src/inbound/mixed.c
  src/inbound/socks5.c
  src/inbound/anytls.c
  src/inbound/tun.c
  src/outbound/outbound.c
  src/outbound/direct.c
  src/outbound/reject.c
  src/outbound/socks5.c
  src/outbound/anytls.c
  src/route/router.c
  src/route/rule.c
  src/route/target.c
  src/route/group.c
  src/dns/dns.c
  src/dns/server.c
  src/dns/listener.c
  src/dns/bootstrap.c
  src/dns/resolver.c
  src/dns/cache.c
  src/dns/fakeip.c
  src/dns/wire.c
  src/group/select.c
  src/group/url_test.c
  src/group/health.c
  src/geo/geo.c
  src/geo/geoip.c
  src/geo/geosite.c
  src/geo/update.c
  src/tun/tun.c
  src/tun/lwip_adapter.c
  src/tun/udp_session.c
  src/platform/linux/tun.c
  src/platform/linux/route.c
  src/platform/linux/socket_protect.c
  src/platform/system_resolver.c
  src/platform/file.c
  src/api/api.c
  src/util/logger.c
  src/util/buffer.c
  src/util/hash.c
  src/util/time.c
  src/event/event.c
  src/event/libev_adapter.c
  src/transport/dialer.c
  src/transport/stream.c
  src/transport/datagram.c
  src/transport/relay.c
  src/protocol/socks5.c
  src/protocol/http.c
  src/protocol/anytls.c
  src/protocol/uot.c
  src/tls/tls.c
  src/tls/wolfssl_adapter.c
  src/sniff/sniff.c
  src/sniff/tls_sni.c
  src/sniff/http_host.c
  src/state/fakeip_store.c
  src/state/snapshot.c
  src/state/group_cache.c
  src/geo/format.c
)
target_include_directories(ftun_core PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(ftun_core PRIVATE ftun_options)
add_executable(ftun src/main.c src/cli/cli.c)
target_include_directories(ftun PRIVATE src)
target_link_libraries(ftun PRIVATE ftun_core ftun_options)
set(ftun_targets ftun_core ftun)
if(FTUN_BUILD_GEO_TOOL)
  add_executable(ftun-geo tools/geo/main.c)
  target_link_libraries(ftun-geo PRIVATE ftun_options)
  list(APPEND ftun_targets ftun-geo)
  install(TARGETS ftun-geo RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
if(FTUN_STATIC)
  target_link_options(ftun PRIVATE -static)
  if(TARGET ftun-geo)
    target_link_options(ftun-geo PRIVATE -static)
  endif()
endif()
if(FTUN_LTO)
  set_property(TARGET ${ftun_targets} PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()
install(TARGETS ftun ftun_core RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/ftun DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
configure_file(cmake/uninstall.cmake.in uninstall.cmake @ONLY)
add_custom_target(uninstall COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/uninstall.cmake)
if(BUILD_TESTING)
  add_executable(ftun-contract-test tests/skeleton_contract.c)
  target_include_directories(ftun-contract-test PRIVATE src)
  target_link_libraries(ftun-contract-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-contract-test PRIVATE -static)
  endif()
  add_test(NAME skeleton-contract COMMAND ftun-contract-test)
  if(UNIX)
    add_executable(ftun-time-test tests/monotonic_time.c)
    target_include_directories(ftun-time-test PRIVATE src)
    target_link_libraries(ftun-time-test PRIVATE ftun_core ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-time-test PRIVATE -static)
    endif()
    add_test(NAME monotonic-time COMMAND ftun-time-test)
  endif()
  add_test(NAME cli-version COMMAND ftun version)
  set_tests_properties(cli-version PROPERTIES PASS_REGULAR_EXPRESSION "skeleton; proxy features: none")
  add_test(NAME cli-refuses-run COMMAND ftun run)
  set_tests_properties(cli-refuses-run PROPERTIES WILL_FAIL TRUE)
  if(TARGET ftun-geo)
    add_test(NAME geo-refuses-convert COMMAND ftun-geo compile)
    set_tests_properties(geo-refuses-convert PROPERTIES WILL_FAIL TRUE)
  endif()
  find_package(Python3 QUIET COMPONENTS Interpreter)
  if(Python3_Interpreter_FOUND)
    add_test(NAME config-schema COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/config_schema.py)
    # Optional development dependency: skip explicitly if jsonschema is absent.
    set_tests_properties(config-schema PROPERTIES SKIP_RETURN_CODE 77)
  endif()
  # 工程检查不能因运行环境或工具故障无限阻塞。
  get_property(ftun_tests DIRECTORY PROPERTY TESTS)
  set_tests_properties(${ftun_tests} PROPERTIES TIMEOUT 30)
endif()
