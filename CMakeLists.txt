cmake_minimum_required(VERSION 3.21)
project(FTUN VERSION 1.0.1 LANGUAGES C)
include(GNUInstallDirs)
include(CTest)
find_package(Threads REQUIRED)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
option(FTUN_SANITIZERS "Enable address and undefined behavior checks" OFF)
option(FTUN_LTO "Require supported interprocedural optimization" OFF)
option(FTUN_SECTION_GC "Remove unused code and data on supported toolchains" ON)
option(FTUN_STATIC "Build fully static Linux executables" OFF)
set(FTUN_MODULE_DNS "OFF" CACHE STRING "Build the DNS module: OFF or BUILTIN")
set(FTUN_MODULE_FAKEIP "OFF" CACHE STRING "Build the FakeIP module: OFF or BUILTIN")
set(FTUN_MODULE_TUN "OFF" CACHE STRING "Build the TUN module: OFF or BUILTIN")
set(FTUN_MODULE_FRS "OFF" CACHE STRING "Build the FRS module: OFF or BUILTIN")
set_property(CACHE FTUN_MODULE_DNS PROPERTY STRINGS OFF BUILTIN)
set_property(CACHE FTUN_MODULE_FAKEIP PROPERTY STRINGS OFF BUILTIN)
set_property(CACHE FTUN_MODULE_TUN PROPERTY STRINGS OFF BUILTIN)
set_property(CACHE FTUN_MODULE_FRS PROPERTY STRINGS OFF BUILTIN)
set(FTUN_OPTIMIZATION "balanced" CACHE STRING "balanced, speed or size")
set_property(CACHE FTUN_OPTIMIZATION PROPERTY STRINGS balanced speed size)
set(FTUN_EXTRA_COMPILE_OPTIONS "" CACHE STRING "Additional target options as a CMake list")
set(FTUN_EXTRA_LINK_OPTIONS "" CACHE STRING "Additional target link options as a CMake list")
set(FTUN_SOURCE_REVISION_OVERRIDE "" CACHE STRING
  "Override the source revision embedded in ftun version output")
set(ftun_source_revision "unknown")
if(NOT FTUN_SOURCE_REVISION_OVERRIDE STREQUAL "")
  set(ftun_source_revision "${FTUN_SOURCE_REVISION_OVERRIDE}")
else()
  find_package(Git QUIET)
  if(GIT_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git")
    execute_process(
      COMMAND ${GIT_EXECUTABLE} rev-parse --short=12 HEAD
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      RESULT_VARIABLE ftun_revision_result
      OUTPUT_VARIABLE ftun_revision_output
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET)
    execute_process(
      COMMAND ${GIT_EXECUTABLE} status --porcelain --untracked-files=normal
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      RESULT_VARIABLE ftun_status_result
      OUTPUT_VARIABLE ftun_status_output
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET)
    if(ftun_revision_result EQUAL 0 AND NOT ftun_revision_output STREQUAL "")
      set(ftun_source_revision "${ftun_revision_output}")
      if(ftun_status_result EQUAL 0 AND NOT ftun_status_output STREQUAL "")
        string(APPEND ftun_source_revision "-dirty")
      endif()
    endif()
  endif()
endif()
if(NOT FTUN_OPTIMIZATION MATCHES "^(balanced|speed|size)$")
  message(FATAL_ERROR "Unsupported FTUN_OPTIMIZATION")
endif()
foreach(ftun_module DNS FAKEIP TUN FRS)
  if(NOT FTUN_MODULE_${ftun_module} MATCHES "^(OFF|BUILTIN)$")
    message(FATAL_ERROR
      "FTUN_MODULE_${ftun_module} must be OFF or BUILTIN; dynamic modules are not supported")
  endif()
endforeach()
if(FTUN_MODULE_FAKEIP STREQUAL "BUILTIN" AND
   NOT FTUN_MODULE_DNS STREQUAL "BUILTIN")
  message(FATAL_ERROR "FTUN_MODULE_FAKEIP=BUILTIN requires FTUN_MODULE_DNS=BUILTIN")
endif()
if(FTUN_MODULE_TUN STREQUAL "BUILTIN" AND NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "FTUN_MODULE_TUN=BUILTIN requires a Linux target")
endif()
if(FTUN_MODULE_FRS STREQUAL "BUILTIN" AND NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "FTUN_MODULE_FRS=BUILTIN requires a Linux target")
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
if(FTUN_STATIC)
  # Every first-party executable in the full-static profile, including its
  # verification binaries, must close over the same musl ABI.
  target_link_options(ftun_options INTERFACE -static)
endif()
if(FTUN_LTO)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT ftun_ipo_ok OUTPUT ftun_ipo_error LANGUAGES C)
  if(NOT ftun_ipo_ok)
    message(FATAL_ERROR "Requested LTO is unavailable: ${ftun_ipo_error}")
  endif()
endif()

# libev 保留完整上游源码；0.2 Linux 构建只编译 epoll 后端。
set(ftun_internal_dependencies)
add_library(ftun_cjson STATIC third_party/cjson/cJSON.c)
target_include_directories(ftun_cjson PUBLIC
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/third_party/cjson>")
target_compile_definitions(ftun_cjson PRIVATE CJSON_NESTING_LIMIT=32)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(ftun_cjson PRIVATE -Wall -Wextra -fno-strict-aliasing
    "$<$<CONFIG:Debug>:-O0;-g>" "$<$<NOT:$<CONFIG:Debug>>:${ftun_opt}>")
  if(FTUN_SECTION_GC)
    target_compile_options(ftun_cjson PRIVATE -ffunction-sections -fdata-sections)
  endif()
  if(FTUN_SANITIZERS)
    target_compile_options(ftun_cjson PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
  endif()
endif()
target_compile_options(ftun_cjson PRIVATE ${FTUN_EXTRA_COMPILE_OPTIONS})
list(APPEND ftun_internal_dependencies ftun_cjson)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_library(ftun_libev STATIC third_party/libev/ev.c)
  target_include_directories(ftun_libev PUBLIC third_party/libev)
  target_compile_definitions(ftun_libev PRIVATE
    _GNU_SOURCE=1
    EV_STANDALONE=1
    EV_NO_THREADS=0
    "EV_ATOMIC_T=_Atomic sig_atomic_t"
    EV_USE_EPOLL=1
    EV_USE_SELECT=0
    EV_USE_POLL=0
    EV_USE_KQUEUE=0
    EV_USE_PORT=0
    EV_USE_LINUXAIO=0
    EV_USE_IOURING=0
    EV_USE_EVENTFD=1
    EV_USE_SIGNALFD=0
    EV_USE_TIMERFD=0
    EV_USE_INOTIFY=0)
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(ftun_libev PRIVATE -Wall -Wextra -fno-strict-aliasing
      "$<$<CONFIG:Debug>:-O0;-g>" "$<$<NOT:$<CONFIG:Debug>>:${ftun_opt}>")
    if(FTUN_SECTION_GC)
      target_compile_options(ftun_libev PRIVATE -ffunction-sections -fdata-sections)
    endif()
    if(FTUN_SANITIZERS)
      target_compile_options(ftun_libev PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    endif()
  endif()
  target_compile_options(ftun_libev PRIVATE ${FTUN_EXTRA_COMPILE_OPTIONS})
  set_property(TARGET ftun_libev PROPERTY C_EXTENSIONS ON)
  list(APPEND ftun_internal_dependencies ftun_libev)
endif()

# wolfSSL 5.8.4-stable 以精确 gitlink 固定；仅构建静态库，不构建上游示例、
# benchmark、测试或安装规则。FTUN 适配层强制 TLS 1.2+ 与 peer verification。
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/wolfssl/CMakeLists.txt")
  message(FATAL_ERROR
    "wolfSSL submodule is missing; run: git submodule update --init third_party/wolfssl")
endif()
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build static dependencies" FORCE)
set(WOLFSSL_EXAMPLES no CACHE STRING "Disable wolfSSL examples" FORCE)
set(WOLFSSL_CRYPT_TESTS no CACHE STRING "Disable wolfSSL crypt tests" FORCE)
set(WOLFSSL_INSTALL no CACHE STRING "Disable wolfSSL install rules" FORCE)
set(WOLFSSL_TLS13 yes CACHE STRING "Enable wolfSSL TLS 1.3" FORCE)
set(WOLFSSL_DTLS no CACHE STRING "Disable unused wolfSSL DTLS" FORCE)
set(WOLFSSL_OLD_TLS no CACHE STRING "Disable obsolete TLS versions" FORCE)
add_subdirectory(third_party/wolfssl EXCLUDE_FROM_ALL)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_compile_definitions(wolfssl PRIVATE _POSIX_C_SOURCE=200809L)
endif()
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  if(FTUN_SECTION_GC)
    target_compile_options(wolfssl PRIVATE
      -ffunction-sections -fdata-sections)
  endif()
  if(FTUN_SANITIZERS)
    target_compile_options(wolfssl PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
  endif()
endif()
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND
   CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 14)
  # wolfSSL 5.8.4's constant-time HMAC loop triggers GCC 14's conservative
  # object-size diagnostic at -O3. Keep all other upstream -Werror checks.
  target_compile_options(wolfssl PRIVATE -Wno-error=stringop-overflow)
endif()
target_compile_options(wolfssl PRIVATE ${FTUN_EXTRA_COMPILE_OPTIONS})
list(APPEND ftun_internal_dependencies wolfssl::wolfssl)
# 当前库不在配置期发现或下载第三方库；依赖均由本地锁定源构建。
# 核心保留 SystemResolver、通用 Datagram 和 SOCKS5，不反向依赖 TUN。
set(ftun_core_sources
    src/core/core.c
    src/core/http_fetch.c
    src/core/control_resolver.c
  src/core/engine.c
  src/core/engine_dns.c
  src/core/state.c
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
  src/inbound/mixed.c
  src/outbound/outbound.c
  src/outbound/direct.c
  src/outbound/reject.c
  src/outbound/socks5.c
  src/route/router.c
  src/route/rule.c
  src/route/target.c
  src/route/group.c
  src/group/select.c
  src/group/url_test.c
  src/group/health.c
  src/tls/tls.c
  src/tls/wolfssl_adapter.c
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
    src/tun/udp_session.c
  src/protocol/socks5.c
  src/protocol/http.c
  src/sniff/sniff.c
  src/sniff/tls_sni.c
  src/sniff/http_host.c
  src/state/group_cache.c
)

# 这些源码属于后续版本的可选模块，当前不加入任何 target。
# 各模块交付时再与其注册项、独占依赖和 OFF/BUILTIN 测试一起接入。
set(ftun_deferred_module_sources
  src/inbound/anytls.c
  src/outbound/anytls.c
  src/api/api.c
  src/protocol/anytls.c
  src/protocol/uot.c
)

set(ftun_module_definitions)
if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
  list(APPEND ftun_core_sources
    src/frs/format.c
    src/frs/frs.c
    src/frs/ip.c
    src/frs/domain.c
    src/frs/update.c
  )
  list(APPEND ftun_module_definitions FTUN_HAVE_MODULE_FRS=1)
endif()
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
if(FTUN_MODULE_FAKEIP STREQUAL "BUILTIN")
  list(APPEND ftun_core_sources
    src/dns/fakeip.c
    src/state/fakeip_store.c
    src/state/snapshot.c
  )
  list(APPEND ftun_module_definitions FTUN_HAVE_MODULE_FAKEIP=1)
endif()
if(FTUN_MODULE_TUN STREQUAL "BUILTIN")
  add_library(ftun_lwip STATIC
    third_party/lwip/src/core/def.c
    third_party/lwip/src/core/inet_chksum.c
    third_party/lwip/src/core/init.c
    third_party/lwip/src/core/ip.c
    third_party/lwip/src/core/mem.c
    third_party/lwip/src/core/memp.c
    third_party/lwip/src/core/netif.c
    third_party/lwip/src/core/pbuf.c
    third_party/lwip/src/core/stats.c
    third_party/lwip/src/core/sys.c
    third_party/lwip/src/core/tcp.c
    third_party/lwip/src/core/tcp_in.c
    third_party/lwip/src/core/tcp_out.c
    third_party/lwip/src/core/timeouts.c
    third_party/lwip/src/core/udp.c
    third_party/lwip/src/core/ipv4/ip4.c
    third_party/lwip/src/core/ipv4/ip4_addr.c
    third_party/lwip/src/core/ipv4/ip4_frag.c)
  target_include_directories(ftun_lwip PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/third_party/lwip/src/include>"
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/tun/lwip_port>")
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(ftun_lwip PRIVATE -Wall -Wextra -fno-strict-aliasing
      "$<$<CONFIG:Debug>:-O0;-g>" "$<$<NOT:$<CONFIG:Debug>>:${ftun_opt}>")
    if(FTUN_SECTION_GC)
      target_compile_options(ftun_lwip PRIVATE -ffunction-sections -fdata-sections)
    endif()
    if(FTUN_SANITIZERS)
      target_compile_options(ftun_lwip PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    endif()
  endif()
  target_compile_options(ftun_lwip PRIVATE ${FTUN_EXTRA_COMPILE_OPTIONS})
  list(APPEND ftun_internal_dependencies ftun_lwip)
  list(APPEND ftun_core_sources
    src/inbound/tun.c
    src/tun/tun.c
    src/tun/lwip_adapter.c
    src/platform/linux/tun.c
    src/platform/linux/route.c
  )
  list(APPEND ftun_module_definitions FTUN_HAVE_MODULE_TUN=1)
endif()

add_library(ftun_core STATIC ${ftun_core_sources})
target_include_directories(ftun_core PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_definitions(ftun_core PRIVATE ${ftun_module_definitions}
  "$<$<TARGET_EXISTS:ftun_libev>:FTUN_HAVE_LIBEV=1>")
target_link_libraries(ftun_core PRIVATE ftun_options Threads::Threads
  ${ftun_internal_dependencies})
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/ftun-build-modules.txt" CONTENT
  "core=BUILTIN\ndns=${FTUN_MODULE_DNS}\nfakeip=${FTUN_MODULE_FAKEIP}\ntun=${FTUN_MODULE_TUN}\nfrs=${FTUN_MODULE_FRS}\n")
add_executable(ftun src/main.c src/cli/cli.c)
target_include_directories(ftun PRIVATE src)
target_compile_definitions(ftun PRIVATE ${ftun_module_definitions}
  FTUN_SOURCE_REVISION="${ftun_source_revision}")
target_link_libraries(ftun PRIVATE ftun_core ftun_options)
set(ftun_targets ftun_core ftun)
list(APPEND ftun_targets ftun_cjson wolfssl)
if(TARGET ftun_lwip)
  list(APPEND ftun_targets ftun_lwip)
endif()
if(TARGET ftun_libev)
  list(APPEND ftun_targets ftun_libev)
endif()
if(FTUN_STATIC)
  target_link_options(ftun PRIVATE -static)
endif()
if(FTUN_LTO)
  set_property(TARGET ${ftun_targets} PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()
install(TARGETS ftun ftun_core RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS ftun_cjson ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS wolfssl ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
if(TARGET ftun_lwip)
  install(TARGETS ftun_lwip ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
  install(FILES third_party/lwip/LICENSE
    DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/ftun RENAME LICENSE-lwIP)
endif()
if(TARGET ftun_libev)
  install(TARGETS ftun_libev ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()
install(FILES third_party/cjson/LICENSE
  DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/ftun RENAME LICENSE-cJSON)
install(FILES third_party/wolfssl/COPYING
  DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/ftun RENAME LICENSE-wolfSSL)
install(DIRECTORY include/ftun DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES LICENSE README.md document/control.md document/build-release.md
  document/release-v1.0.md document/release-v1.0.1.md
  THIRD_PARTY_NOTICES.md third_party/LOCK.json
  DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/ftun)
if(TARGET ftun_libev)
  install(FILES third_party/libev/LICENSE
    DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/ftun RENAME LICENSE-libev)
endif()
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
  if(FTUN_MODULE_FAKEIP STREQUAL "BUILTIN")
    target_compile_definitions(ftun-build-modules-test PRIVATE FTUN_EXPECT_FAKEIP=1)
  endif()
  if(FTUN_MODULE_TUN STREQUAL "BUILTIN")
    target_compile_definitions(ftun-build-modules-test PRIVATE FTUN_EXPECT_TUN=1)
  endif()
  if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
    target_compile_definitions(ftun-build-modules-test PRIVATE FTUN_EXPECT_FRS=1)
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
  add_executable(ftun-runtime-test tests/runtime.c)
  target_include_directories(ftun-runtime-test PRIVATE src)
  target_link_libraries(ftun-runtime-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-runtime-test PRIVATE -static)
  endif()
  add_test(NAME runtime-contract COMMAND ftun-runtime-test)
  add_executable(ftun-session-test tests/session.c)
  target_include_directories(ftun-session-test PRIVATE src)
  target_link_libraries(ftun-session-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-session-test PRIVATE -static)
  endif()
  add_test(NAME session-contract COMMAND ftun-session-test)
  add_executable(ftun-buffer-test tests/buffer.c)
  target_include_directories(ftun-buffer-test PRIVATE src)
  target_link_libraries(ftun-buffer-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-buffer-test PRIVATE -static)
  endif()
  add_test(NAME buffer-contract COMMAND ftun-buffer-test)
  add_executable(ftun-hash-test tests/hash.c)
  target_include_directories(ftun-hash-test PRIVATE src)
  target_link_libraries(ftun-hash-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-hash-test PRIVATE -static)
  endif()
  add_test(NAME hash-contract COMMAND ftun-hash-test)
  add_executable(ftun-operation-test tests/operation.c)
  target_include_directories(ftun-operation-test PRIVATE src)
  target_link_libraries(ftun-operation-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-operation-test PRIVATE -static)
  endif()
  add_test(NAME operation-contract COMMAND ftun-operation-test)
  add_executable(ftun-worker-test tests/worker.c)
  target_include_directories(ftun-worker-test PRIVATE src)
  target_link_libraries(ftun-worker-test PRIVATE ftun_core ftun_options Threads::Threads)
  if(FTUN_STATIC)
    target_link_options(ftun-worker-test PRIVATE -static)
  endif()
  add_test(NAME worker-contract COMMAND ftun-worker-test)
  add_executable(ftun-event-test tests/event.c)
  target_include_directories(ftun-event-test PRIVATE src)
  target_link_libraries(ftun-event-test PRIVATE ftun_core ftun_options Threads::Threads)
  if(FTUN_STATIC)
    target_link_options(ftun-event-test PRIVATE -static)
  endif()
  add_test(NAME event-contract COMMAND ftun-event-test)
  add_executable(ftun-dialer-test tests/dialer.c)
  target_include_directories(ftun-dialer-test PRIVATE src)
  target_link_libraries(ftun-dialer-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-dialer-test PRIVATE -static)
  endif()
  add_test(NAME dialer-contract COMMAND ftun-dialer-test)
  add_executable(ftun-stream-test tests/stream.c)
  target_include_directories(ftun-stream-test PRIVATE src)
  target_link_libraries(ftun-stream-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-stream-test PRIVATE -static)
  endif()
  add_test(NAME stream-contract COMMAND ftun-stream-test)
  add_executable(ftun-datagram-test tests/datagram.c)
  target_include_directories(ftun-datagram-test PRIVATE src)
  target_link_libraries(ftun-datagram-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-datagram-test PRIVATE -static)
  endif()
  add_test(NAME datagram-contract COMMAND ftun-datagram-test)
  add_executable(ftun-relay-test tests/relay.c)
  target_include_directories(ftun-relay-test PRIVATE src)
  target_link_libraries(ftun-relay-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-relay-test PRIVATE -static)
  endif()
  add_test(NAME relay-contract COMMAND ftun-relay-test)
  add_executable(ftun-protocol-socks5-test tests/protocol_socks5.c)
  target_include_directories(ftun-protocol-socks5-test PRIVATE src)
  target_link_libraries(ftun-protocol-socks5-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-protocol-socks5-test PRIVATE -static)
  endif()
  add_test(NAME protocol-socks5-contract COMMAND ftun-protocol-socks5-test)
  add_executable(ftun-protocol-http-test tests/protocol_http.c)
  target_include_directories(ftun-protocol-http-test PRIVATE src)
  target_link_libraries(ftun-protocol-http-test PRIVATE ftun_core ftun_options)
  add_test(NAME protocol-http-contract COMMAND ftun-protocol-http-test)
  add_executable(ftun-inbound-socks5-test tests/inbound_socks5.c)
  target_include_directories(ftun-inbound-socks5-test PRIVATE src)
  target_link_libraries(ftun-inbound-socks5-test PRIVATE ftun_core ftun_options)
  add_test(NAME inbound-socks5-contract COMMAND ftun-inbound-socks5-test)
  add_executable(ftun-inbound-mixed-test tests/inbound_mixed.c)
  target_include_directories(ftun-inbound-mixed-test PRIVATE src)
  target_link_libraries(ftun-inbound-mixed-test PRIVATE
    ftun_core ftun_options)
  add_test(NAME inbound-mixed-contract COMMAND ftun-inbound-mixed-test)
  add_executable(ftun-v04-group-test tests/group.c)
  target_include_directories(ftun-v04-group-test PRIVATE src)
  target_link_libraries(ftun-v04-group-test PRIVATE ftun_core ftun_options)
  add_test(NAME group-contract COMMAND ftun-v04-group-test)
  add_executable(ftun-sniff-tls-test tests/sniff_tls.c)
  target_include_directories(ftun-sniff-tls-test PRIVATE src)
  target_link_libraries(ftun-sniff-tls-test PRIVATE ftun_core ftun_options)
  add_test(NAME sniff-tls-contract COMMAND ftun-sniff-tls-test)
  add_executable(ftun-sniff-http-test tests/sniff_http.c)
  target_include_directories(ftun-sniff-http-test PRIVATE src)
  target_link_libraries(ftun-sniff-http-test PRIVATE ftun_core ftun_options)
  add_test(NAME sniff-http-contract COMMAND ftun-sniff-http-test)
  add_executable(ftun-sniff-test tests/sniff.c)
  target_include_directories(ftun-sniff-test PRIVATE src)
  target_link_libraries(ftun-sniff-test PRIVATE ftun_core ftun_options)
  add_test(NAME sniff-contract COMMAND ftun-sniff-test)
  set(ftun_untrusted_parser_sources tests/untrusted_parsers.c)
  if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
    list(APPEND ftun_untrusted_parser_sources tests/frs_fixture.c)
  endif()
  add_executable(ftun-untrusted-parsers-test
    ${ftun_untrusted_parser_sources})
  target_include_directories(ftun-untrusted-parsers-test PRIVATE src tests)
  target_link_libraries(ftun-untrusted-parsers-test PRIVATE
    ftun_core ftun_options)
  if(FTUN_MODULE_DNS STREQUAL "BUILTIN")
    target_compile_definitions(ftun-untrusted-parsers-test PRIVATE
      FTUN_TEST_DNS=1)
  endif()
  if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
    target_compile_definitions(ftun-untrusted-parsers-test PRIVATE
      FTUN_TEST_FRS=1)
  endif()
  if(FTUN_STATIC)
    target_link_options(ftun-untrusted-parsers-test PRIVATE -static)
  endif()
  add_test(NAME untrusted-parsers-regression
    COMMAND ftun-untrusted-parsers-test)
  add_executable(ftun-group-cache-test tests/group_cache.c)
  target_include_directories(ftun-group-cache-test PRIVATE src)
  target_link_libraries(ftun-group-cache-test PRIVATE ftun_core ftun_options)
  add_test(NAME group-cache-contract COMMAND ftun-group-cache-test)
  add_executable(ftun-core-state-test tests/core_state.c)
  target_include_directories(ftun-core-state-test PRIVATE src)
  target_link_libraries(ftun-core-state-test PRIVATE ftun_core ftun_options)
  add_test(NAME core-state-contract COMMAND ftun-core-state-test)
  add_executable(ftun-logger-test tests/logger.c)
  target_include_directories(ftun-logger-test PRIVATE src)
  target_link_libraries(ftun-logger-test PRIVATE
    ftun_core ftun_options Threads::Threads)
  add_test(NAME logger-contract COMMAND ftun-logger-test)
  add_executable(ftun-v05-integration-test tests/integration_v05.c)
  target_include_directories(ftun-v05-integration-test PRIVATE src)
  target_link_libraries(ftun-v05-integration-test PRIVATE
    ftun_core ftun_options Threads::Threads)
  add_test(NAME integration-v05-contract COMMAND ftun-v05-integration-test)
  add_executable(ftun-control-resolver-test tests/control_resolver.c)
  target_include_directories(ftun-control-resolver-test PRIVATE src)
  target_link_libraries(ftun-control-resolver-test PRIVATE
    ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-control-resolver-test PRIVATE -static)
  endif()
  add_test(NAME control-resolver-contract COMMAND ftun-control-resolver-test)
  if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
    add_executable(ftun-v04-frs-test tests/frs.c tests/frs_fixture.c)
    target_include_directories(ftun-v04-frs-test PRIVATE src tests)
    target_link_libraries(ftun-v04-frs-test PRIVATE ftun_core ftun_options)
    add_test(NAME frs-contract COMMAND ftun-v04-frs-test)
    add_executable(ftun-v04-frs-update-test
      tests/frs_update.c tests/frs_fixture.c)
    target_include_directories(ftun-v04-frs-update-test PRIVATE src tests)
    target_link_libraries(ftun-v04-frs-update-test PRIVATE
      ftun_core ftun_options)
    add_test(NAME frs-update-contract COMMAND ftun-v04-frs-update-test)
  endif()
  add_executable(ftun-v04-tls-test tests/tls.c)
  target_include_directories(ftun-v04-tls-test PRIVATE src)
  target_compile_definitions(ftun-v04-tls-test PRIVATE
    "FTUN_TEST_CERT_DIR=${CMAKE_CURRENT_SOURCE_DIR}/third_party/wolfssl/certs")
  target_link_libraries(ftun-v04-tls-test PRIVATE
    ftun_core ftun_options wolfssl::wolfssl)
  add_test(NAME tls-wolfssl-contract COMMAND ftun-v04-tls-test)
  if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
    add_executable(ftun-v04-integration-test
      tests/integration_v04.c tests/frs_fixture.c)
    target_include_directories(ftun-v04-integration-test PRIVATE src tests)
    target_link_libraries(ftun-v04-integration-test PRIVATE
      ftun_core ftun_options)
    add_test(NAME integration-v04-contract COMMAND ftun-v04-integration-test)
  endif()
  add_executable(ftun-route-target-test tests/route_target.c)
  target_include_directories(ftun-route-target-test PRIVATE src)
  target_link_libraries(ftun-route-target-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-route-target-test PRIVATE -static)
  endif()
  add_test(NAME route-target-contract COMMAND ftun-route-target-test)
  add_executable(ftun-route-rule-test tests/route_rule.c)
  target_include_directories(ftun-route-rule-test PRIVATE src)
  target_link_libraries(ftun-route-rule-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-route-rule-test PRIVATE -static)
  endif()
  add_test(NAME route-rule-contract COMMAND ftun-route-rule-test)
  add_executable(ftun-route-router-test tests/route_router.c)
  target_include_directories(ftun-route-router-test PRIVATE src)
  target_link_libraries(ftun-route-router-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-route-router-test PRIVATE -static)
  endif()
  add_test(NAME route-router-contract COMMAND ftun-route-router-test)
  add_executable(ftun-outbound-reject-test tests/outbound_reject.c)
  target_include_directories(ftun-outbound-reject-test PRIVATE src)
  target_link_libraries(ftun-outbound-reject-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-outbound-reject-test PRIVATE -static)
  endif()
  add_test(NAME outbound-reject-contract COMMAND ftun-outbound-reject-test)
  add_executable(ftun-outbound-direct-test tests/outbound_direct.c)
  target_include_directories(ftun-outbound-direct-test PRIVATE src)
  target_link_libraries(ftun-outbound-direct-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-outbound-direct-test PRIVATE -static)
  endif()
  add_test(NAME outbound-direct-contract COMMAND ftun-outbound-direct-test)
  add_executable(ftun-outbound-socks5-test tests/outbound_socks5.c)
  target_include_directories(ftun-outbound-socks5-test PRIVATE src)
  target_link_libraries(ftun-outbound-socks5-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-outbound-socks5-test PRIVATE -static)
  endif()
  add_test(NAME outbound-socks5-contract COMMAND ftun-outbound-socks5-test)
  add_executable(ftun-outbound-test tests/outbound.c)
  target_include_directories(ftun-outbound-test PRIVATE src)
  target_link_libraries(ftun-outbound-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-outbound-test PRIVATE -static)
  endif()
  add_test(NAME outbound-contract COMMAND ftun-outbound-test)
  if(TARGET ftun_libev)
    add_executable(ftun-libev-test tests/libev_adapter.c)
    target_include_directories(ftun-libev-test PRIVATE src)
    target_link_libraries(ftun-libev-test PRIVATE ftun_core ftun_options Threads::Threads)
    if(FTUN_STATIC)
      target_link_options(ftun-libev-test PRIVATE -static)
    endif()
    add_test(NAME libev-adapter COMMAND ftun-libev-test)
    add_executable(ftun-libev-runtime-test tests/libev_runtime.c)
    target_compile_definitions(ftun-libev-runtime-test PRIVATE
      "EV_ATOMIC_T=_Atomic sig_atomic_t")
    target_link_libraries(ftun-libev-runtime-test PRIVATE ftun_libev ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-libev-runtime-test PRIVATE -static)
    endif()
    add_test(NAME libev-signal-exit COMMAND ftun-libev-runtime-test)
  endif()
  add_executable(ftun-config-parser-test tests/config_parser.c)
  target_include_directories(ftun-config-parser-test PRIVATE src)
  target_link_libraries(ftun-config-parser-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-config-parser-test PRIVATE -static)
  endif()
  add_test(NAME config-parser COMMAND ftun-config-parser-test
    ${CMAKE_CURRENT_SOURCE_DIR}/examples/full.json)
  add_executable(ftun-config-validate-test tests/config_validate.c)
  target_include_directories(ftun-config-validate-test PRIVATE src)
  target_link_libraries(ftun-config-validate-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-config-validate-test PRIVATE -static)
  endif()
  add_test(NAME config-validate COMMAND ftun-config-validate-test
    ${CMAKE_CURRENT_SOURCE_DIR}/examples/full.json)
  add_executable(ftun-config-compile-test tests/config_compile.c)
  target_include_directories(ftun-config-compile-test PRIVATE src)
  target_link_libraries(ftun-config-compile-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-config-compile-test PRIVATE -static)
  endif()
  add_test(NAME config-compile COMMAND ftun-config-compile-test
    ${CMAKE_CURRENT_SOURCE_DIR}/examples/full.json)
  add_executable(ftun-config-load-test tests/config_load.c)
  target_include_directories(ftun-config-load-test PRIVATE src)
  target_link_libraries(ftun-config-load-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-config-load-test PRIVATE -static)
  endif()
  add_test(NAME config-load COMMAND ftun-config-load-test)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(ftun-platform-file-test tests/platform_file.c)
    target_include_directories(ftun-platform-file-test PRIVATE src)
    target_link_libraries(ftun-platform-file-test PRIVATE ftun_core ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-platform-file-test PRIVATE -static)
    endif()
    add_test(NAME platform-file-contract COMMAND ftun-platform-file-test)
    add_executable(ftun-platform-linux-socket-protect-test
      tests/platform_linux_socket_protect.c)
    target_include_directories(ftun-platform-linux-socket-protect-test PRIVATE src)
    target_link_libraries(ftun-platform-linux-socket-protect-test PRIVATE
      ftun_core ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-platform-linux-socket-protect-test PRIVATE -static)
    endif()
    add_test(NAME platform-linux-socket-protect
      COMMAND ftun-platform-linux-socket-protect-test)
    add_executable(ftun-platform-system-resolver-test
      tests/platform_system_resolver.c)
    target_include_directories(ftun-platform-system-resolver-test PRIVATE src)
    target_link_libraries(ftun-platform-system-resolver-test PRIVATE
      ftun_core ftun_options Threads::Threads)
    if(FTUN_STATIC)
      target_link_options(ftun-platform-system-resolver-test PRIVATE -static)
    endif()
    add_test(NAME platform-system-resolver
      COMMAND ftun-platform-system-resolver-test)
  endif()
  if(FTUN_MODULE_FAKEIP STREQUAL "BUILTIN")
    add_executable(ftun-fakeip-store-test tests/fakeip_store.c)
    target_include_directories(ftun-fakeip-store-test PRIVATE src)
    target_link_libraries(ftun-fakeip-store-test PRIVATE
      ftun_core ftun_options Threads::Threads)
    if(FTUN_STATIC)
      target_link_options(ftun-fakeip-store-test PRIVATE -static)
    endif()
    add_test(NAME fakeip-store-contract COMMAND ftun-fakeip-store-test)
    add_executable(ftun-fakeip-snapshot-test tests/fakeip_snapshot.c)
    target_include_directories(ftun-fakeip-snapshot-test PRIVATE src)
    target_link_libraries(ftun-fakeip-snapshot-test PRIVATE
      ftun_core ftun_options Threads::Threads)
    if(FTUN_STATIC)
      target_link_options(ftun-fakeip-snapshot-test PRIVATE -static)
    endif()
    add_test(NAME fakeip-snapshot-contract COMMAND ftun-fakeip-snapshot-test)
    add_executable(ftun-fakeip-test tests/fakeip.c)
    target_include_directories(ftun-fakeip-test PRIVATE src)
    target_link_libraries(ftun-fakeip-test PRIVATE
      ftun_core ftun_options Threads::Threads)
    if(FTUN_STATIC)
      target_link_options(ftun-fakeip-test PRIVATE -static)
    endif()
    add_test(NAME fakeip-contract COMMAND ftun-fakeip-test)
  endif()
  if(FTUN_MODULE_DNS STREQUAL "BUILTIN")
    add_executable(ftun-dns-cache-test tests/dns_cache.c)
    target_include_directories(ftun-dns-cache-test PRIVATE src)
    target_link_libraries(ftun-dns-cache-test PRIVATE ftun_core ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-dns-cache-test PRIVATE -static)
    endif()
    add_test(NAME dns-cache-contract COMMAND ftun-dns-cache-test)
    add_executable(ftun-dns-server-test tests/dns_server.c)
    target_include_directories(ftun-dns-server-test PRIVATE src)
    target_link_libraries(ftun-dns-server-test PRIVATE ftun_core ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-dns-server-test PRIVATE -static)
    endif()
    add_test(NAME dns-server-contract COMMAND ftun-dns-server-test)
    add_executable(ftun-dns-dispatch-test tests/dns_dispatch.c)
    target_include_directories(ftun-dns-dispatch-test PRIVATE src)
    target_link_libraries(ftun-dns-dispatch-test PRIVATE ftun_core ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-dns-dispatch-test PRIVATE -static)
    endif()
    add_test(NAME dns-dispatch-contract COMMAND ftun-dns-dispatch-test)
    add_executable(ftun-dns-listener-test tests/dns_listener.c)
    target_include_directories(ftun-dns-listener-test PRIVATE src)
    target_link_libraries(ftun-dns-listener-test PRIVATE ftun_core ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-dns-listener-test PRIVATE -static)
    endif()
    add_test(NAME dns-listener-contract COMMAND ftun-dns-listener-test)
    add_executable(ftun-v03-integration-test tests/integration_v03.c)
    target_include_directories(ftun-v03-integration-test PRIVATE src)
    target_link_libraries(ftun-v03-integration-test PRIVATE
      ftun_core ftun_options Threads::Threads)
    if(FTUN_STATIC)
      target_link_options(ftun-v03-integration-test PRIVATE -static)
    endif()
    add_test(NAME integration-v03-contract COMMAND ftun-v03-integration-test)
    add_executable(ftun-dns-wire-test tests/dns_wire.c)
    target_include_directories(ftun-dns-wire-test PRIVATE src)
    target_link_libraries(ftun-dns-wire-test PRIVATE ftun_core ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-dns-wire-test PRIVATE -static)
    endif()
    add_test(NAME dns-wire-contract COMMAND ftun-dns-wire-test)
    add_executable(ftun-dns-bootstrap-test tests/dns_bootstrap.c)
    target_include_directories(ftun-dns-bootstrap-test PRIVATE src)
    target_link_libraries(ftun-dns-bootstrap-test PRIVATE
      ftun_core ftun_options Threads::Threads)
    if(FTUN_STATIC)
      target_link_options(ftun-dns-bootstrap-test PRIVATE -static)
    endif()
    add_test(NAME dns-bootstrap-contract COMMAND ftun-dns-bootstrap-test)
    add_executable(ftun-dns-resolver-test tests/dns_resolver.c)
    target_include_directories(ftun-dns-resolver-test PRIVATE src)
    target_link_libraries(ftun-dns-resolver-test PRIVATE ftun_core ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-dns-resolver-test PRIVATE -static)
    endif()
    add_test(NAME dns-resolver-contract COMMAND ftun-dns-resolver-test)
  endif()
  if(FTUN_MODULE_TUN STREQUAL "BUILTIN")
    add_executable(ftun-inbound-test tests/inbound.c)
    target_include_directories(ftun-inbound-test PRIVATE src)
    target_link_libraries(ftun-inbound-test PRIVATE ftun_core ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-inbound-test PRIVATE -static)
    endif()
    add_test(NAME inbound-contract COMMAND ftun-inbound-test)
    add_executable(ftun-platform-linux-tun-test tests/platform_linux_tun.c)
    target_include_directories(ftun-platform-linux-tun-test PRIVATE src)
    target_link_libraries(ftun-platform-linux-tun-test PRIVATE ftun_core ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-platform-linux-tun-test PRIVATE -static)
    endif()
    add_test(NAME platform-linux-tun COMMAND ftun-platform-linux-tun-test)
    add_executable(ftun-platform-linux-route-test tests/platform_linux_route.c)
    target_include_directories(ftun-platform-linux-route-test PRIVATE src)
    target_link_libraries(ftun-platform-linux-route-test PRIVATE ftun_core ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-platform-linux-route-test PRIVATE -static)
    endif()
    add_test(NAME platform-linux-route COMMAND ftun-platform-linux-route-test)
    add_executable(ftun-tun-port-test tests/tun_port.c)
    target_include_directories(ftun-tun-port-test PRIVATE src)
    target_link_libraries(ftun-tun-port-test PRIVATE ftun_core ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-tun-port-test PRIVATE -static)
    endif()
    add_test(NAME tun-packet-port COMMAND ftun-tun-port-test)
    add_executable(ftun-lwip-adapter-test tests/lwip_adapter.c)
    target_include_directories(ftun-lwip-adapter-test PRIVATE src)
    target_link_libraries(ftun-lwip-adapter-test PRIVATE ftun_core ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-lwip-adapter-test PRIVATE -static)
    endif()
    add_test(NAME tun-lwip-adapter COMMAND ftun-lwip-adapter-test)
    add_executable(ftun-inbound-tun-test tests/inbound_tun.c)
    target_include_directories(ftun-inbound-tun-test PRIVATE src)
    target_link_libraries(ftun-inbound-tun-test PRIVATE ftun_core ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-inbound-tun-test PRIVATE -static)
    endif()
    add_test(NAME inbound-tun-contract COMMAND ftun-inbound-tun-test)
    add_executable(ftun-udp-session-test tests/udp_session.c)
    target_include_directories(ftun-udp-session-test PRIVATE src)
    target_link_libraries(ftun-udp-session-test PRIVATE ftun_core ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-udp-session-test PRIVATE -static)
    endif()
    add_test(NAME tun-udp-flow-contract COMMAND ftun-udp-session-test)
    if(UNIX)
      add_executable(ftun-linux-integration-test tests/integration_linux.c)
      target_include_directories(ftun-linux-integration-test PRIVATE src)
      target_link_libraries(ftun-linux-integration-test PRIVATE
        ftun_core ftun_options Threads::Threads)
      if(FTUN_STATIC)
        target_link_options(ftun-linux-integration-test PRIVATE -static)
      endif()
      add_test(NAME linux-isolated-integration
        COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration_linux.sh
                   $<TARGET_FILE:ftun-linux-integration-test>)
      set_tests_properties(linux-isolated-integration PROPERTIES
        SKIP_RETURN_CODE 77 TIMEOUT 30 RESOURCE_LOCK ftun_linux_namespace)
      if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
        add_test(NAME release-linux-production
          COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/release_linux.sh
                     $<TARGET_FILE:ftun>
                     $<TARGET_FILE:ftun-linux-integration-test>
                     $<TARGET_FILE:ftun-v04-frs-test>)
        set_tests_properties(release-linux-production PROPERTIES
          SKIP_RETURN_CODE 77 RESOURCE_LOCK ftun_linux_namespace)
        if(FTUN_SANITIZERS)
          # ASan reserves and commits shadow/quarantine pages which are not part
          # of the production memory budget. Keep the same 32-flow functional
          # pressure while applying the 64 MiB gate only to release binaries.
          set_tests_properties(release-linux-production PROPERTIES
            ENVIRONMENT "FTUN_RELEASE_RESOURCE_LIMIT_KIB=262144")
        endif()
      endif()
      add_test(NAME socket-inbounds-production
        COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/socket_inbounds.sh
                   $<TARGET_FILE:ftun>
                   $<TARGET_FILE:ftun-linux-integration-test>)
      set_tests_properties(socket-inbounds-production PROPERTIES
        TIMEOUT 20 RESOURCE_LOCK ftun_host_socket)
      if(CMAKE_BUILD_TYPE MATCHES "^(Release|MinSizeRel)$")
        add_test(NAME idle-tcp-resource-profile
          COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/idle_tcp.sh
                     $<TARGET_FILE:ftun>
                     $<TARGET_FILE:ftun-linux-integration-test>)
        set_tests_properties(idle-tcp-resource-profile PROPERTIES
          TIMEOUT 75 RESOURCE_LOCK ftun_host_socket)
      endif()
    endif()
  endif()
  if(UNIX)
    add_executable(ftun-time-test tests/monotonic_time.c)
    target_include_directories(ftun-time-test PRIVATE src)
    target_link_libraries(ftun-time-test PRIVATE ftun_core ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-time-test PRIVATE -static)
    endif()
    add_test(NAME monotonic-time COMMAND ftun-time-test)
  endif()
  add_executable(ftun-performance-test tests/performance.c)
  target_include_directories(ftun-performance-test PRIVATE src)
  target_link_libraries(ftun-performance-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-performance-test PRIVATE -static)
  endif()
  if(CMAKE_BUILD_TYPE MATCHES "^(Release|MinSizeRel)$")
    add_test(NAME performance-baseline COMMAND ftun-performance-test)
  endif()
  set(ftun_cli_capabilities "core")
  foreach(ftun_module DNS FAKEIP TUN FRS)
    if(FTUN_MODULE_${ftun_module} STREQUAL "BUILTIN")
      string(TOLOWER "${ftun_module}" ftun_capability)
      string(APPEND ftun_cli_capabilities ",${ftun_capability}")
    endif()
  endforeach()
  add_test(NAME cli-version COMMAND ${CMAKE_COMMAND}
    -DFTUN_BINARY=$<TARGET_FILE:ftun>
    -DFTUN_EXPECTED_REVISION=${ftun_source_revision}
    -DFTUN_EXPECTED_CAPABILITIES=${ftun_cli_capabilities}
    -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_version.cmake)
  add_test(NAME cli-help COMMAND ftun help)
  set_tests_properties(cli-help PROPERTIES PASS_REGULAR_EXPRESSION "ftun check -c CONFIG")
  add_test(NAME cli-refuses-run COMMAND ftun run)
  set_tests_properties(cli-refuses-run PROPERTIES WILL_FAIL TRUE)
  if(UNIX)
    if(FTUN_MODULE_FAKEIP STREQUAL "BUILTIN")
      set(ftun_cli_dns_enabled 1)
    else()
      set(ftun_cli_dns_enabled 0)
    endif()
    add_test(NAME cli-v05-contract
      COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_v05.sh
        $<TARGET_FILE:ftun> ${ftun_cli_dns_enabled}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/cli-run.json.in
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/cli-fakeip.json.in)
    set_tests_properties(cli-v05-contract PROPERTIES TIMEOUT 10)
  endif()
  find_package(Python3 QUIET COMPONENTS Interpreter)
  if(Python3_Interpreter_FOUND)
    add_test(NAME dependency-lock
      COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/dependency_lock.py
        ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME config-schema COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/config_schema.py)
    if(TARGET ftun_libev)
      add_test(NAME libev-vendor
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/libev_vendor.py
          ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json)
    endif()
    add_test(NAME cjson-vendor
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/cjson_vendor.py
        ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json)
    add_test(NAME wolfssl-vendor
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/wolfssl_vendor.py
        ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json)
    if(TARGET ftun_lwip)
      add_test(NAME lwip-vendor
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/lwip_vendor.py
          ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json)
    endif()
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      if(FTUN_STATIC)
        set(ftun_expect_static 1)
      else()
        set(ftun_expect_static 0)
      endif()
      add_test(NAME release-elf-contract
        COMMAND ${Python3_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/release_contract.py
          $<TARGET_FILE:ftun>
          ${CMAKE_CURRENT_BINARY_DIR}/ftun-build-modules.txt
          ${ftun_expect_static})
      if(CMAKE_BUILD_TYPE MATCHES "^(Release|MinSizeRel)$")
        add_test(NAME release-resource-profile
          COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/resource_profile.py
            $<TARGET_FILE:ftun> ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/cli-run.json.in)
      endif()
    endif()
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
  set_tests_properties(build-modules-matrix PROPERTIES TIMEOUT 180)
  if(TEST release-linux-production)
    set_tests_properties(release-linux-production PROPERTIES TIMEOUT 90)
  endif()
  if(TEST idle-tcp-resource-profile)
    set_tests_properties(idle-tcp-resource-profile PROPERTIES TIMEOUT 75)
  endif()
endif()
