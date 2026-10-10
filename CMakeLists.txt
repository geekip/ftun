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
set(FTUN_MODULE_DNS "OFF" CACHE STRING "Build the DNS module: OFF or BUILTIN")
set(FTUN_MODULE_TUN "OFF" CACHE STRING "Build the TUN module: OFF or BUILTIN")
set_property(CACHE FTUN_MODULE_DNS PROPERTY STRINGS OFF BUILTIN)
set_property(CACHE FTUN_MODULE_TUN PROPERTY STRINGS OFF BUILTIN)
set(FTUN_OPTIMIZATION "balanced" CACHE STRING "balanced, speed or size")
set_property(CACHE FTUN_OPTIMIZATION PROPERTY STRINGS balanced speed size)
set(FTUN_EXTRA_COMPILE_OPTIONS "" CACHE STRING "Additional target options as a CMake list")
set(FTUN_EXTRA_LINK_OPTIONS "" CACHE STRING "Additional target link options as a CMake list")
if(NOT FTUN_OPTIMIZATION MATCHES "^(balanced|speed|size)$")
  message(FATAL_ERROR "Unsupported FTUN_OPTIMIZATION")
endif()
foreach(ftun_module DNS TUN)
  if(NOT FTUN_MODULE_${ftun_module} MATCHES "^(OFF|BUILTIN)$")
    message(FATAL_ERROR
      "FTUN_MODULE_${ftun_module} must be OFF or BUILTIN; dynamic modules are not supported")
  endif()
endforeach()
if(FTUN_MODULE_TUN STREQUAL "BUILTIN" AND NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "FTUN_MODULE_TUN=BUILTIN requires a Linux target")
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
# 当前库不发现或下载第三方库。后续引入依赖时必须和所属模块同时裁剪。
# 核心保留 SystemResolver、通用 Datagram 和 SOCKS5，不反向依赖 TUN。
set(ftun_core_sources
  src/core/core.c
  src/util/error.c
  src/core/runtime.c
  src/core/session.c
  src/core/budget.c
  src/core/operation.c
  src/core/worker.c
  src/config/config.c
  src/config/parser.c
  src/config/validate.c
  src/config/compile.c
  src/inbound/inbound.c
  src/inbound/socks5.c
  src/outbound/outbound.c
  src/outbound/direct.c
  src/outbound/reject.c
  src/outbound/socks5.c
  src/route/router.c
  src/route/rule.c
  src/route/target.c
  src/dns/resolver.c
  src/platform/linux/socket_protect.c
  src/platform/system_resolver.c
  src/platform/file.c
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
)

# 这些源码属于后续版本的可选模块，当前不加入任何 target。
# 各模块交付时再与其注册项、独占依赖和 OFF/BUILTIN 测试一起接入。
set(ftun_deferred_module_sources
  src/core/state.c
  src/inbound/mixed.c
  src/inbound/anytls.c
  src/outbound/anytls.c
  src/route/group.c
  src/dns/fakeip.c
  src/group/select.c
  src/group/url_test.c
  src/group/health.c
  src/geo/geo.c
  src/geo/geoip.c
  src/geo/geosite.c
  src/geo/update.c
  src/geo/format.c
  src/api/api.c
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
)

set(ftun_module_definitions)
if(FTUN_MODULE_DNS STREQUAL "BUILTIN")
  list(APPEND ftun_core_sources
    src/dns/dns.c
    src/dns/server.c
    src/dns/listener.c
    src/dns/bootstrap.c
    src/dns/cache.c
    src/dns/wire.c
  )
  list(APPEND ftun_module_definitions FTUN_HAVE_MODULE_DNS=1)
endif()
if(FTUN_MODULE_TUN STREQUAL "BUILTIN")
  list(APPEND ftun_core_sources
    src/inbound/tun.c
    src/tun/tun.c
    src/tun/lwip_adapter.c
    src/tun/udp_session.c
    src/platform/linux/tun.c
    src/platform/linux/route.c
  )
  list(APPEND ftun_module_definitions FTUN_HAVE_MODULE_TUN=1)
endif()

add_library(ftun_core STATIC ${ftun_core_sources})
target_include_directories(ftun_core PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_definitions(ftun_core PRIVATE ${ftun_module_definitions})
target_link_libraries(ftun_core PRIVATE ftun_options)
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/ftun-build-modules.txt" CONTENT
  "core=BUILTIN\ndns=${FTUN_MODULE_DNS}\ntun=${FTUN_MODULE_TUN}\n")
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
  add_executable(ftun-build-modules-test tests/build_modules.c)
  target_include_directories(ftun-build-modules-test PRIVATE src)
  target_link_libraries(ftun-build-modules-test PRIVATE ftun_core ftun_options)
  if(FTUN_MODULE_DNS STREQUAL "BUILTIN")
    target_compile_definitions(ftun-build-modules-test PRIVATE FTUN_EXPECT_DNS=1)
  endif()
  if(FTUN_MODULE_TUN STREQUAL "BUILTIN")
    target_compile_definitions(ftun-build-modules-test PRIVATE FTUN_EXPECT_TUN=1)
  endif()
  if(FTUN_STATIC)
    target_link_options(ftun-build-modules-test PRIVATE -static)
  endif()
  add_test(NAME build-modules-capabilities COMMAND ftun-build-modules-test)
  add_executable(ftun-budget-test tests/budget.c)
  target_include_directories(ftun-budget-test PRIVATE src)
  target_link_libraries(ftun-budget-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-budget-test PRIVATE -static)
  endif()
  add_test(NAME budget-contract COMMAND ftun-budget-test)
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
  add_test(NAME build-modules-matrix
    COMMAND ${CMAKE_COMMAND}
      -DFTUN_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
      -DFTUN_MATRIX_DIR=${CMAKE_CURRENT_BINARY_DIR}/module-matrix
      -DFTUN_MATRIX_GENERATOR=${CMAKE_GENERATOR}
      -DFTUN_MATRIX_COMPILER=${CMAKE_C_COMPILER}
      -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/build_modules.cmake)
  # 工程检查不能因运行环境或工具故障无限阻塞。
  get_property(ftun_tests DIRECTORY PROPERTY TESTS)
  set_tests_properties(${ftun_tests} PROPERTIES TIMEOUT 30)
endif()
