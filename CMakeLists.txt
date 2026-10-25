cmake_minimum_required(VERSION 3.21)
project(FTUN VERSION 1.0.3 LANGUAGES C)
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
set(FTUN_MODULE_PROXY "BUILTIN" CACHE STRING "Build the Proxy module: OFF or BUILTIN")
set(FTUN_MODULE_DNS "OFF" CACHE STRING "Build the DNS module: OFF or BUILTIN")
set(FTUN_MODULE_FAKEIP "OFF" CACHE STRING "Build the FakeIP module: OFF or BUILTIN")
set(FTUN_MODULE_TUN "OFF" CACHE STRING "Build the TUN module: OFF or BUILTIN")
set(FTUN_MODULE_FRS "OFF" CACHE STRING "Build the FRS module: OFF or BUILTIN")
set_property(CACHE FTUN_MODULE_PROXY PROPERTY STRINGS OFF BUILTIN)
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
foreach(ftun_module PROXY DNS FAKEIP TUN FRS)
  if(NOT FTUN_MODULE_${ftun_module} MATCHES "^(OFF|BUILTIN)$")
    message(FATAL_ERROR
      "FTUN_MODULE_${ftun_module} must be OFF or BUILTIN; dynamic modules are not supported")
  endif()
endforeach()
if(FTUN_MODULE_FAKEIP STREQUAL "BUILTIN" AND
   (NOT FTUN_MODULE_DNS STREQUAL "BUILTIN" OR
    NOT FTUN_MODULE_PROXY STREQUAL "BUILTIN"))
  message(FATAL_ERROR
    "FTUN_MODULE_FAKEIP=BUILTIN requires FTUN_MODULE_PROXY=BUILTIN and FTUN_MODULE_DNS=BUILTIN")
endif()
if(FTUN_MODULE_FRS STREQUAL "BUILTIN" AND
   NOT FTUN_MODULE_PROXY STREQUAL "BUILTIN")
  message(FATAL_ERROR "FTUN_MODULE_FRS=BUILTIN requires FTUN_MODULE_PROXY=BUILTIN")
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
    FTUN_LIBEV_EPOLL_HOOK=1
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
  target_compile_options(ftun_libev PRIVATE
    -include "${CMAKE_CURRENT_SOURCE_DIR}/src/event/libev_epoll.h")
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(ftun_libev PRIVATE -Wall -Wextra -fno-strict-aliasing
      "$<$<CONFIG:Debug>:-O0;-g>" "$<$<NOT:$<CONFIG:Debug>>:${ftun_opt}>")
    if(FTUN_SECTION_GC)
      target_compile_options(ftun_libev PRIVATE -ffunction-sections -fdata-sections)
    endif()
    if(FTUN_SANITIZERS)
      target_compile_options(ftun_libev PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
      # libev intentionally stores typed watcher callbacks behind its common
      # ev_watcher callback slot.  Clang's function sanitizer diagnoses that
      # established C layout at the generic dispatch site, including libev's
      # own pipecb.  Keep ASan and all other UBSan checks on the vendor target.
      if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        target_compile_options(ftun_libev PRIVATE -fno-sanitize=function)
      endif()
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
# C10-011 使用对象目标固定源码归属，再由 ftun_runtime 聚合成兼容的
# libftun_core.a。对象目标避免在 C10-012 收窄兼容接口前引入静态库循环。
set(ftun_core_sources
  src/core/core.c
  src/core/context.c
  src/core/service.c
  src/core/module_plan.c
  src/core/budget.c
  src/core/operation.c
  src/core/worker.c
)

set(ftun_app_sources
  src/app/runtime.c
  src/app/composition/default.c
  src/app/cli/dispatch.c
  src/app/cli/run.c
  src/app/cli/result.c
  src/app/cli/check.c
  src/app/cli/control.c
  src/app/cli/fakeip.c
  src/app/cli/version.c
)
if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
  list(APPEND ftun_app_sources src/app/composition/proxy_runtime.c)
endif()

set(ftun_proxy_sources)
if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
  list(APPEND ftun_proxy_sources
  src/proxy/service.c
  src/proxy/bindings.c
  src/proxy/runtime.c
  src/proxy/slot_pool.c
  src/proxy/dns/dispatch_adapter.c
  src/proxy/dns/runtime_adapter.c
  src/proxy/dns/control_path_adapter.c
  src/proxy/snapshot.c
  src/proxy/runtime_state.c
  src/proxy/session.c
  src/proxy/http_fetch.c
  src/proxy/control_resolver.c
  src/proxy/state/restore.c
  src/proxy/state/group_cache.c
  src/proxy/udp/session.c
  src/proxy/inbound/inbound.c
  src/proxy/inbound/socks5.c
  src/proxy/inbound/mixed.c
  src/proxy/inbound/adapter.c
  src/proxy/outbound/outbound.c
  src/proxy/outbound/direct.c
  src/proxy/outbound/reject.c
  src/proxy/outbound/socks5.c
  src/proxy/route/router.c
  src/proxy/route/rule.c
  src/proxy/route/target.c
  src/proxy/route/group.c
  src/proxy/group/select.c
  src/proxy/group/url_test.c
  src/proxy/group/health.c
  src/proxy/sniff/sniff.c
  src/proxy/sniff/tls_sni.c
  src/proxy/sniff/http_host.c
  src/proxy/dns/resolver_adapter.c
  )
endif()

set(ftun_shared_sources
  src/util/error.c
  src/config/config.c
  src/config/parser.c
  src/config/validate.c
  src/config/compile.c
  src/tls/tls.c
  src/tls/wolfssl_adapter.c
  src/dns/control_transport.c
  src/platform/linux/socket_protect.c
  src/platform/system_resolver.c
  src/platform/file.c
  src/util/logger.c
  src/util/event_log.c
  src/util/buffer.c
  src/util/hash.c
  src/util/time.c
  src/event/event.c
  src/event/libev_adapter.c
  src/network/view.c
  src/network/resolver.c
  src/transport/dialer.c
  src/transport/path.c
  src/transport/socket_path.c
  src/transport/control_channel.c
  src/transport/blocking.c
  src/transport/carrier.c
  src/transport/stream.c
  src/transport/datagram.c
  src/transport/relay.c
  src/protocol/socks5.c
  src/protocol/http.c
)

set(ftun_tun_sources)
set(ftun_dns_sources)
set(ftun_fakeip_sources)
set(ftun_frs_sources)

# 这些源码属于后续版本的可选模块，当前不加入任何 target。
# 各模块交付时再与其注册项、独占依赖和 OFF/BUILTIN 测试一起接入。
set(ftun_deferred_module_sources
  src/proxy/inbound/anytls.c
  src/proxy/outbound/anytls.c
  src/app/api/api.c
  src/protocol/anytls.c
  src/protocol/uot.c
)

set(ftun_module_definitions)
if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
  list(APPEND ftun_module_definitions FTUN_HAVE_MODULE_PROXY=1)
endif()
if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
  list(APPEND ftun_frs_sources
    src/proxy/frs/format.c
    src/proxy/frs/frs.c
    src/proxy/frs/ip.c
    src/proxy/frs/domain.c
    src/proxy/frs/update.c
  )
  list(APPEND ftun_module_definitions FTUN_HAVE_MODULE_FRS=1)
endif()
if(FTUN_MODULE_DNS STREQUAL "BUILTIN")
  list(APPEND ftun_dns_sources
    src/dns/dispatcher.c
    src/dns/service.c
    src/dns/core_service.c
    src/dns/server.c
    src/dns/listener.c
    src/dns/bootstrap.c
    src/dns/cache.c
    src/dns/wire.c
  )
  list(APPEND ftun_module_definitions FTUN_HAVE_MODULE_DNS=1)
endif()
if(FTUN_MODULE_FAKEIP STREQUAL "BUILTIN")
  list(APPEND ftun_fakeip_sources
    src/proxy/dns/fakeip.c
    src/proxy/state/fakeip_store.c
    src/proxy/state/fakeip_snapshot.c
  )
  list(APPEND ftun_module_definitions FTUN_HAVE_MODULE_FAKEIP=1)
endif()
if(FTUN_MODULE_TUN STREQUAL "BUILTIN")
  if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
    list(APPEND ftun_proxy_sources
      src/proxy/tun/ingress.c
      src/proxy/tun/lwip_adapter.c
    )
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
      "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/proxy/tun/lwip_port>")
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
  endif()
  list(APPEND ftun_tun_sources
    src/tun/device.c
    src/tun/service.c
    src/tun/dispatch.c
    src/tun/route.c
    src/tun/path.c
    src/tun/owner.c
    src/platform/linux/tun.c
    src/platform/linux/interface.c
    src/platform/linux/route.c
    src/platform/linux/route_async.c
  )
  list(APPEND ftun_module_definitions FTUN_HAVE_MODULE_TUN=1)
endif()

function(ftun_configure_object_target target)
  target_include_directories(${target}
    PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
  target_compile_definitions(${target} PRIVATE ${ARGN}
    "$<$<TARGET_EXISTS:ftun_libev>:FTUN_HAVE_LIBEV=1>")
  target_link_libraries(${target} PRIVATE ftun_options Threads::Threads)
endfunction()

add_library(ftun_core OBJECT ${ftun_core_sources})
ftun_configure_object_target(ftun_core)
add_library(ftun_shared_services OBJECT ${ftun_shared_sources})
ftun_configure_object_target(ftun_shared_services
  ${ftun_module_definitions})
target_link_libraries(ftun_shared_services PRIVATE ftun_cjson wolfssl::wolfssl)
if(TARGET ftun_libev)
  target_link_libraries(ftun_shared_services PRIVATE ftun_libev)
endif()
if(ftun_proxy_sources)
  add_library(ftun_proxy OBJECT ${ftun_proxy_sources})
  ftun_configure_object_target(ftun_proxy ${ftun_module_definitions})
  if(TARGET ftun_lwip)
    target_link_libraries(ftun_proxy PRIVATE ftun_lwip)
  endif()
endif()
add_library(ftun_app OBJECT ${ftun_app_sources})
ftun_configure_object_target(ftun_app
  ${ftun_module_definitions})
target_compile_definitions(ftun_app PRIVATE
  FTUN_SOURCE_REVISION="${ftun_source_revision}")

set(ftun_runtime_objects
  $<TARGET_OBJECTS:ftun_core>
  $<TARGET_OBJECTS:ftun_shared_services>
  $<TARGET_OBJECTS:ftun_app>)
set(ftun_layer_targets
  ftun_core ftun_shared_services ftun_app)
if(TARGET ftun_proxy)
  list(APPEND ftun_runtime_objects $<TARGET_OBJECTS:ftun_proxy>)
  list(APPEND ftun_layer_targets ftun_proxy)
endif()

if(ftun_dns_sources)
  add_library(ftun_module_dns OBJECT ${ftun_dns_sources})
  ftun_configure_object_target(ftun_module_dns FTUN_HAVE_MODULE_DNS=1)
  list(APPEND ftun_runtime_objects $<TARGET_OBJECTS:ftun_module_dns>)
  list(APPEND ftun_layer_targets ftun_module_dns)
endif()
if(ftun_fakeip_sources)
  add_library(ftun_module_fakeip OBJECT ${ftun_fakeip_sources})
  ftun_configure_object_target(ftun_module_fakeip
    FTUN_HAVE_MODULE_DNS=1 FTUN_HAVE_MODULE_FAKEIP=1)
  list(APPEND ftun_runtime_objects $<TARGET_OBJECTS:ftun_module_fakeip>)
  list(APPEND ftun_layer_targets ftun_module_fakeip)
endif()
if(ftun_frs_sources)
  add_library(ftun_module_frs OBJECT ${ftun_frs_sources})
  ftun_configure_object_target(ftun_module_frs FTUN_HAVE_MODULE_FRS=1)
  list(APPEND ftun_runtime_objects $<TARGET_OBJECTS:ftun_module_frs>)
  list(APPEND ftun_layer_targets ftun_module_frs)
endif()
if(ftun_tun_sources)
  add_library(ftun_tun OBJECT ${ftun_tun_sources})
  ftun_configure_object_target(ftun_tun FTUN_HAVE_MODULE_TUN=1)
  list(APPEND ftun_runtime_objects $<TARGET_OBJECTS:ftun_tun>)
  list(APPEND ftun_layer_targets ftun_tun)
endif()

add_library(ftun_runtime STATIC ${ftun_runtime_objects})
set_target_properties(ftun_runtime PROPERTIES OUTPUT_NAME ftun_core)
target_include_directories(ftun_runtime
  PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_definitions(ftun_runtime PRIVATE ${ftun_module_definitions}
  "$<$<TARGET_EXISTS:ftun_libev>:FTUN_HAVE_LIBEV=1>")
target_link_libraries(ftun_runtime PRIVATE ftun_options Threads::Threads
  ${ftun_internal_dependencies})

# 目标边只允许工具链/线程和各层明确需要的第三方编译接口；第一方层通过对象聚合，
# 不能偷偷以 target_link_libraries 反向引入另一业务层。
function(ftun_assert_target_dependencies target)
  set(allowed ${ARGN})
  get_target_property(actual ${target} LINK_LIBRARIES)
  if(NOT actual)
    return()
  endif()
  foreach(dependency IN LISTS actual)
    if(TARGET "${dependency}")
      list(FIND allowed "${dependency}" found)
      if(found EQUAL -1)
        message(FATAL_ERROR
          "${target} has undeclared target dependency: ${dependency}")
      endif()
    endif()
  endforeach()
endfunction()
ftun_assert_target_dependencies(ftun_core ftun_options Threads::Threads)
if(TARGET ftun_proxy)
  ftun_assert_target_dependencies(ftun_proxy
    ftun_options Threads::Threads ftun_lwip)
endif()
ftun_assert_target_dependencies(ftun_app
  ftun_options Threads::Threads)
ftun_assert_target_dependencies(ftun_shared_services
  ftun_options Threads::Threads ftun_cjson wolfssl::wolfssl ftun_libev)
if(TARGET ftun_tun)
  ftun_assert_target_dependencies(ftun_tun
    ftun_options Threads::Threads)
endif()
foreach(target ftun_module_dns ftun_module_fakeip ftun_module_frs)
  if(TARGET ${target})
    ftun_assert_target_dependencies(${target} ftun_options Threads::Threads)
  endif()
endforeach()
ftun_assert_target_dependencies(ftun_runtime
  ftun_options Threads::Threads ftun_cjson wolfssl::wolfssl
  ftun_libev ftun_lwip)
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/ftun-build-modules.txt" CONTENT
  "core=BUILTIN\nproxy=${FTUN_MODULE_PROXY}\ndns=${FTUN_MODULE_DNS}\nfakeip=${FTUN_MODULE_FAKEIP}\ntun=${FTUN_MODULE_TUN}\nfrs=${FTUN_MODULE_FRS}\nmesh=OFF\n")
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/ftun-build-targets.txt" CONTENT
  "core=ftun_core\nshared=ftun_shared_services\nproxy=$<IF:$<TARGET_EXISTS:ftun_proxy>,ftun_proxy,OFF>\napp=ftun_app\ntun=$<IF:$<TARGET_EXISTS:ftun_tun>,ftun_tun,OFF>\nlwip=$<IF:$<TARGET_EXISTS:ftun_lwip>,ftun_lwip,OFF>\ndns=$<IF:$<TARGET_EXISTS:ftun_module_dns>,ftun_module_dns,OFF>\nfakeip=$<IF:$<TARGET_EXISTS:ftun_module_fakeip>,ftun_module_fakeip,OFF>\nfrs=$<IF:$<TARGET_EXISTS:ftun_module_frs>,ftun_module_frs,OFF>\nmesh=OFF\n")
set(ftun_layer_policy "${CMAKE_CURRENT_SOURCE_DIR}/cmake/ftun-layer-policy.json")
if(NOT EXISTS "${ftun_layer_policy}")
  message(FATAL_ERROR "missing frozen source-layer policy: ${ftun_layer_policy}")
endif()
file(READ "${ftun_layer_policy}" ftun_layer_policy_json)
string(JSON ftun_layer_policy_schema ERROR_VARIABLE ftun_layer_policy_error
  GET "${ftun_layer_policy_json}" schema)
if(ftun_layer_policy_error OR
   NOT ftun_layer_policy_schema STREQUAL "ftun-layer-policy-v1")
  message(FATAL_ERROR "invalid frozen source-layer policy schema")
endif()
add_executable(ftun src/app/main.c)
target_include_directories(ftun PRIVATE src)
target_compile_definitions(ftun PRIVATE ${ftun_module_definitions}
  FTUN_SOURCE_REVISION="${ftun_source_revision}")
target_link_libraries(ftun PRIVATE ftun_runtime ftun_options)
set(ftun_targets ftun_runtime ftun ${ftun_layer_targets})
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
install(TARGETS ftun ftun_runtime RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
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
install(FILES LICENSE README.md THIRD_PARTY_NOTICES.md third_party/LOCK.json
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
  target_link_libraries(ftun-contract-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
    target_compile_definitions(ftun-contract-test PRIVATE FTUN_EXPECT_PROXY=1)
  endif()
  if(FTUN_STATIC)
    target_link_options(ftun-contract-test PRIVATE -static)
  endif()
  add_test(NAME skeleton-contract COMMAND ftun-contract-test)
  # v1.0.2 发行头固定为独立编译输入，调用方 object 不继承当前 public include。
  set(ftun_abi_v102_include
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/abi-v1.0.2/include")
  file(SHA256 "${ftun_abi_v102_include}/ftun/ftun.h" ftun_abi_header_hash)
  file(SHA256 "${ftun_abi_v102_include}/ftun/error.h" ftun_abi_error_hash)
  if(NOT ftun_abi_header_hash STREQUAL
      "15ecf2ed55648dc85978f11ad049c2feed93b1715a4d7fc5cef73b148eb8a68d" OR
     NOT ftun_abi_error_hash STREQUAL
      "8c63278b9052da9676259dfde70a3b5a1e401cfe2cf863c69ba89fac55a01891")
    message(FATAL_ERROR "The v1.0.2 public ABI fixture must remain unchanged")
  endif()
  foreach(ftun_abi_caller v102 current)
    add_library(ftun-abi-${ftun_abi_caller}-caller OBJECT tests/c_api_abi.c)
    if(ftun_abi_caller STREQUAL "v102")
      target_include_directories(ftun-abi-${ftun_abi_caller}-caller PRIVATE
        "${ftun_abi_v102_include}")
    else()
      target_include_directories(ftun-abi-${ftun_abi_caller}-caller PRIVATE include)
    endif()
    target_link_libraries(ftun-abi-${ftun_abi_caller}-caller PRIVATE
      ftun_options Threads::Threads)
    if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
      target_compile_definitions(ftun-abi-${ftun_abi_caller}-caller PRIVATE
        FTUN_TEST_PROXY=1)
    endif()
    add_executable(ftun-abi-${ftun_abi_caller}-test tests/c_api_abi_host.c
      $<TARGET_OBJECTS:ftun-abi-${ftun_abi_caller}-caller>)
    target_include_directories(ftun-abi-${ftun_abi_caller}-test PRIVATE src)
    target_link_libraries(ftun-abi-${ftun_abi_caller}-test PRIVATE
      ftun_runtime ftun_options Threads::Threads)
    target_link_options(ftun-abi-${ftun_abi_caller}-test PRIVATE
      -Wl,--wrap=ftun_operation_queue_get_usage)
    if(FTUN_STATIC)
      target_link_options(ftun-abi-${ftun_abi_caller}-test PRIVATE -static)
    endif()
    add_test(NAME c-api-abi-${ftun_abi_caller}
      COMMAND ftun-abi-${ftun_abi_caller}-test)
  endforeach()
  add_executable(ftun-core-service-test tests/core_service.c)
  add_executable(ftun-app-cleanup-test tests/app_cleanup.c)
  target_include_directories(ftun-app-cleanup-test PRIVATE src)
  target_link_libraries(ftun-app-cleanup-test PRIVATE ftun_runtime ftun_options Threads::Threads)
  if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
    target_compile_definitions(ftun-app-cleanup-test PRIVATE FTUN_TEST_PROXY=1)
  endif()
  if(FTUN_STATIC)
    target_link_options(ftun-app-cleanup-test PRIVATE -static)
  endif()
  add_test(NAME app-cleanup-contract COMMAND ftun-app-cleanup-test)
  add_executable(ftun-app-control-test tests/app_control.c)
  target_include_directories(ftun-app-control-test PRIVATE src)
  target_link_libraries(ftun-app-control-test PRIVATE ftun_runtime ftun_options Threads::Threads)
  if(FTUN_STATIC)
    target_link_options(ftun-app-control-test PRIVATE -static)
  endif()
  add_test(NAME app-control-contract COMMAND ftun-app-control-test)
  set_tests_properties(app-control-contract PROPERTIES TIMEOUT 15)
  add_executable(ftun-app-host-test tests/app_host.c)
  target_include_directories(ftun-app-host-test PRIVATE src)
  target_link_libraries(ftun-app-host-test PRIVATE ftun_runtime ftun_options Threads::Threads)
  if(FTUN_STATIC)
    target_link_options(ftun-app-host-test PRIVATE -static)
  endif()
  add_test(NAME app-host-contract COMMAND ftun-app-host-test)
  set_tests_properties(app-host-contract PROPERTIES TIMEOUT 15)
  add_executable(ftun-app-composition-test tests/app_composition.c)
  add_executable(ftun-app-event-cleanup-test tests/app_composition.c tests/app_event_cleanup.c)
  target_compile_definitions(ftun-app-event-cleanup-test PRIVATE FTUN_TEST_EVENT_CLEANUP=1)
  foreach(operation ftun_libev_attach ftun_core_module_runtime_prepare ftun_core_module_runtime_drain_until)
    target_link_options(ftun-app-event-cleanup-test PRIVATE "-Wl,--wrap=${operation}")
  endforeach()
  set(ftun_composition_test_targets ftun-app-composition-test ftun-app-event-cleanup-test)
  if(FTUN_MODULE_PROXY STREQUAL "BUILTIN" AND FTUN_MODULE_TUN STREQUAL "BUILTIN"
      AND FTUN_MODULE_DNS STREQUAL "BUILTIN")
    add_executable(ftun-runtime-tun-admission-test tests/app_composition.c tests/runtime_tun_admission.c)
    target_compile_definitions(ftun-runtime-tun-admission-test PRIVATE FTUN_TEST_TUN_ADMISSION=1)
    foreach(operation ftun_proxy_runtime_prepare ftun_tun_ingress_bind ftun_socket_path_open
        ftun_proxy_dns_has_hijack ftun_proxy_dns_hijack_tcp ftun_stream_create
        ftun_session_transition ftun_relay_start_with_pool_options socketpair close)
      target_link_options(ftun-runtime-tun-admission-test PRIVATE "-Wl,--wrap=${operation}")
    endforeach()
    list(APPEND ftun_composition_test_targets ftun-runtime-tun-admission-test)
    add_test(NAME runtime-tun-admission-contract COMMAND ftun-runtime-tun-admission-test)
    set_tests_properties(runtime-tun-admission-contract PROPERTIES TIMEOUT 30)
    add_executable(ftun-runtime-tun-recovery-test tests/app_composition.c tests/runtime_tun_admission.c)
    target_compile_definitions(ftun-runtime-tun-recovery-test PRIVATE FTUN_TEST_TUN_ADMISSION=1 FTUN_TEST_TUN_RECOVERY=1)
    foreach(operation ftun_proxy_runtime_prepare ftun_tun_ingress_bind ftun_socket_path_open
        ftun_proxy_dns_has_hijack ftun_proxy_dns_hijack_tcp ftun_stream_create
        ftun_session_transition ftun_relay_start_with_pool_options socketpair close ftun_l3_provider_acquire)
      target_link_options(ftun-runtime-tun-recovery-test PRIVATE "-Wl,--wrap=${operation}")
    endforeach()
    target_link_options(ftun-runtime-tun-recovery-test PRIVATE -Wl,--wrap=ftun_proxy_runtime_reload_commit)
    list(APPEND ftun_composition_test_targets ftun-runtime-tun-recovery-test)
    add_test(NAME runtime-tun-recovery-contract COMMAND ftun-runtime-tun-recovery-test)
    set_tests_properties(runtime-tun-recovery-contract PROPERTIES TIMEOUT 30)
    add_executable(ftun-runtime-tun-async-test tests/app_composition.c tests/runtime_tun_async.c)
    target_compile_definitions(ftun-runtime-tun-async-test PRIVATE FTUN_TEST_TUN_ADMISSION=1 FTUN_TEST_TUN_ASYNC=1)
    foreach(operation ftun_tun_ingress_bind ftun_l3_provider_acquire
        ftun_linux_route_prepare ftun_linux_route_prepare_with_budget ftun_linux_route_async_start ftun_linux_route_async_adopt)
      target_link_options(ftun-runtime-tun-async-test PRIVATE "-Wl,--wrap=${operation}")
    endforeach()
    list(APPEND ftun_composition_test_targets ftun-runtime-tun-async-test)
    add_test(NAME runtime-tun-async-contract COMMAND ftun-runtime-tun-async-test)
    set_tests_properties(runtime-tun-async-contract PROPERTIES TIMEOUT 30)
    add_executable(ftun-runtime-udp-retention-test tests/app_composition.c tests/runtime_udp_retention.c)
    target_compile_definitions(ftun-runtime-udp-retention-test PRIVATE FTUN_TEST_TUN_ADMISSION=1)
    foreach(operation ftun_tun_ingress_bind ftun_proxy_dns_resolve_with_provider ftun_socket_path_open)
      target_link_options(ftun-runtime-udp-retention-test PRIVATE "-Wl,--wrap=${operation}")
    endforeach()
    list(APPEND ftun_composition_test_targets ftun-runtime-udp-retention-test)
    add_test(NAME runtime-udp-retention-contract COMMAND ftun-runtime-udp-retention-test)
    set_tests_properties(runtime-udp-retention-contract PROPERTIES TIMEOUT 30)
    add_executable(ftun-runtime-tun-udp-recovery-test tests/app_composition.c tests/runtime_udp_retention.c)
    target_compile_definitions(ftun-runtime-tun-udp-recovery-test PRIVATE FTUN_TEST_TUN_ADMISSION=1 FTUN_TEST_TUN_UDP_RECOVERY=1)
    foreach(operation ftun_tun_ingress_bind ftun_proxy_dns_resolve_with_provider ftun_socket_path_open ftun_l3_provider_acquire)
      target_link_options(ftun-runtime-tun-udp-recovery-test PRIVATE "-Wl,--wrap=${operation}")
    endforeach()
    list(APPEND ftun_composition_test_targets ftun-runtime-tun-udp-recovery-test)
    add_test(NAME runtime-tun-udp-recovery-contract COMMAND ftun-runtime-tun-udp-recovery-test)
    set_tests_properties(runtime-tun-udp-recovery-contract PROPERTIES TIMEOUT 30)
    add_executable(ftun-app-control-policy-test tests/app_composition.c tests/app_control_policy.c)
    target_compile_definitions(ftun-app-control-policy-test PRIVATE FTUN_TEST_CONTROL_POLICY=1)
    target_link_options(ftun-app-control-policy-test PRIVATE
      -Wl,--wrap=ftun_app_runtime_support -Wl,--wrap=ftun_linux_route_prepare
      -Wl,--wrap=ftun_linux_route_prepare_with_budget
      -Wl,--wrap=ftun_linux_route_async_adopt)
    list(APPEND ftun_composition_test_targets ftun-app-control-policy-test)
    foreach(route true false)
      add_test(NAME app-control-policy-${route} COMMAND ftun-app-control-policy-test)
      set_tests_properties(app-control-policy-${route} PROPERTIES TIMEOUT 15
        ENVIRONMENT "FTUN_TEST_CONTROL_AUTO_ROUTE=${route}")
    endforeach()
  endif()
  foreach(target IN LISTS ftun_composition_test_targets)
    target_include_directories(${target} PRIVATE src)
    target_link_libraries(${target} PRIVATE ftun_runtime ftun_options Threads::Threads)
    if(FTUN_MODULE_TUN STREQUAL "BUILTIN")
      target_compile_definitions(${target} PRIVATE FTUN_TEST_TUN=1)
      foreach(operation open open_with_budget get_info read write close)
        target_link_options(${target} PRIVATE "-Wl,--wrap=ftun_packet_port_${operation}")
      endforeach()
    endif()
    if(FTUN_STATIC)
      target_link_options(${target} PRIVATE -static)
    endif()
  endforeach()
  add_test(NAME app-composition-contract COMMAND ftun-app-composition-test)
  add_test(NAME app-event-cleanup-contract COMMAND ftun-app-event-cleanup-test)
  set_tests_properties(app-event-cleanup-contract PROPERTIES TIMEOUT 15)
  target_include_directories(ftun-core-service-test PRIVATE src)
  target_link_libraries(ftun-core-service-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-core-service-test PRIVATE -static)
  endif()
  add_test(NAME core-service-contract COMMAND ftun-core-service-test)
  if(FTUN_MODULE_PROXY STREQUAL "OFF" AND
     FTUN_MODULE_DNS STREQUAL "BUILTIN")
    add_executable(ftun-service-runtime-test tests/service_runtime.c)
    target_include_directories(ftun-service-runtime-test PRIVATE src)
    target_link_libraries(ftun-service-runtime-test PRIVATE
      ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-service-runtime-test PRIVATE -static)
    endif()
    add_test(NAME service-runtime-stop-contract
      COMMAND ftun-service-runtime-test)
  endif()
  add_executable(ftun-core-module-plan-test tests/core_module_plan.c)
  target_include_directories(ftun-core-module-plan-test PRIVATE src)
  target_link_libraries(ftun-core-module-plan-test PRIVATE
    ftun_runtime ftun_options)
  target_link_options(ftun-core-module-plan-test PRIVATE -Wl,--wrap=calloc)
  if(FTUN_STATIC)
    target_link_options(ftun-core-module-plan-test PRIVATE -static)
  endif()
  add_test(NAME core-module-plan-contract COMMAND ftun-core-module-plan-test)
  if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
    add_executable(ftun-proxy-resources-test tests/proxy_resources.c)
    target_include_directories(ftun-proxy-resources-test PRIVATE src)
    target_link_libraries(ftun-proxy-resources-test PRIVATE ftun_runtime ftun_options)
    target_link_options(ftun-proxy-resources-test PRIVATE
      -Wl,--wrap=socket -Wl,--wrap=ftun_event_source_backend_data)
    if(FTUN_STATIC)
      target_link_options(ftun-proxy-resources-test PRIVATE -static)
    endif()
    add_test(NAME proxy-resources-contract COMMAND ftun-proxy-resources-test)
    set_tests_properties(proxy-resources-contract PROPERTIES TIMEOUT 30)
    add_executable(ftun-proxy-owned-memory-test tests/proxy_owned_memory.c)
    target_include_directories(ftun-proxy-owned-memory-test PRIVATE src)
    target_link_libraries(ftun-proxy-owned-memory-test PRIVATE ftun_runtime ftun_options)
    foreach(module DNS FAKEIP TUN FRS)
      if(FTUN_MODULE_${module} STREQUAL "BUILTIN")
        target_compile_definitions(ftun-proxy-owned-memory-test PRIVATE FTUN_HAVE_MODULE_${module}=1)
      endif()
    endforeach()
    target_link_options(ftun-proxy-owned-memory-test PRIVATE
      -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=ftun_worker_submit)
    if(FTUN_STATIC)
      target_link_options(ftun-proxy-owned-memory-test PRIVATE -static)
    endif()
    add_test(NAME proxy-owned-memory-contract COMMAND ftun-proxy-owned-memory-test)
    set_tests_properties(proxy-owned-memory-contract PROPERTIES TIMEOUT 30)
    add_executable(ftun-proxy-slot-pool-test tests/proxy_slot_pool.c)
    target_include_directories(ftun-proxy-slot-pool-test PRIVATE src)
    target_link_libraries(ftun-proxy-slot-pool-test PRIVATE
      ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-proxy-slot-pool-test PRIVATE -static)
    endif()
    add_test(NAME proxy-slot-pool-contract COMMAND ftun-proxy-slot-pool-test)
  endif()
  add_executable(ftun-build-modules-test tests/build_modules.c)
  target_include_directories(ftun-build-modules-test PRIVATE src)
  target_link_libraries(ftun-build-modules-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
    target_compile_definitions(ftun-build-modules-test PRIVATE FTUN_EXPECT_PROXY=1)
  endif()
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
  target_link_libraries(ftun-budget-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-budget-test PRIVATE -static)
  endif()
  add_test(NAME budget-contract COMMAND ftun-budget-test)
  add_executable(ftun-core-resources-test tests/core_resources.c)
  target_include_directories(ftun-core-resources-test PRIVATE src)
  target_link_libraries(ftun-core-resources-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-core-resources-test PRIVATE -static)
  endif()
  add_test(NAME core-resources-contract COMMAND ftun-core-resources-test)
  add_executable(ftun-app-owned-memory-test tests/app_owned_memory.c)
  target_include_directories(ftun-app-owned-memory-test PRIVATE src)
  target_link_libraries(ftun-app-owned-memory-test PRIVATE ftun_runtime ftun_options Threads::Threads)
  # 故障注入依赖分配函数调用，不能让内建优化绕过链接器wrap。
  target_compile_options(ftun-app-owned-memory-test PRIVATE
    -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-free)
  target_link_options(ftun-app-owned-memory-test PRIVATE
    -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=ftun_core_service_plan_destroy
    -Wl,--wrap=ftun_core_service_reload_commit -Wl,--wrap=ftun_worker_submit)
  if(FTUN_STATIC)
    target_link_options(ftun-app-owned-memory-test PRIVATE -static)
  endif()
  add_test(NAME app-owned-memory-contract COMMAND ftun-app-owned-memory-test)
  set_tests_properties(app-owned-memory-contract PROPERTIES TIMEOUT 15)
  add_executable(ftun-budget-faults-test tests/budget_faults.c)
  target_include_directories(ftun-budget-faults-test PRIVATE include src)
  target_link_libraries(ftun-budget-faults-test PRIVATE ftun_options Threads::Threads)
  if(FTUN_STATIC)
    target_link_options(ftun-budget-faults-test PRIVATE -static)
  endif()
  add_test(NAME budget-faults-contract COMMAND ftun-budget-faults-test)
  add_executable(ftun-budget-consumers-test tests/budget_consumers.c)
  target_include_directories(ftun-budget-consumers-test PRIVATE src)
  target_link_libraries(ftun-budget-consumers-test PRIVATE
    ftun_runtime ftun_options Threads::Threads)
  if(FTUN_STATIC)
    target_link_options(ftun-budget-consumers-test PRIVATE -static)
  endif()
  add_test(NAME budget-consumers-contract COMMAND ftun-budget-consumers-test)
  if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
    add_executable(ftun-app-proxy-memory-test tests/app_proxy_memory.c)
    target_include_directories(ftun-app-proxy-memory-test PRIVATE src tests)
    target_link_libraries(ftun-app-proxy-memory-test PRIVATE ftun_runtime ftun_options)
    target_compile_options(ftun-app-proxy-memory-test PRIVATE
      -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-free)
    target_link_options(ftun-app-proxy-memory-test PRIVATE
      -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=free -Wl,--wrap=open
      -Wl,--wrap=ftun_route_table_destroy -Wl,--wrap=read
      -Wl,--wrap=close -Wl,--wrap=mkstemp)
    if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
      target_sources(ftun-app-proxy-memory-test PRIVATE tests/frs_fixture.c)
      target_compile_definitions(ftun-app-proxy-memory-test PRIVATE FTUN_HAVE_MODULE_FRS=1)
      target_link_options(ftun-app-proxy-memory-test PRIVATE -Wl,--wrap=ftun_http_fetch)
    endif()
    if(FTUN_STATIC)
      target_link_options(ftun-app-proxy-memory-test PRIVATE -static)
    endif()
    add_test(NAME app-proxy-memory-contract COMMAND ftun-app-proxy-memory-test)
    set_tests_properties(app-proxy-memory-contract PROPERTIES TIMEOUT 15)
    add_executable(ftun-runtime-test tests/runtime.c)
    target_include_directories(ftun-runtime-test PRIVATE src)
    target_link_libraries(ftun-runtime-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-runtime-test PRIVATE -static)
    endif()
    add_test(NAME runtime-contract COMMAND ftun-runtime-test)
    add_executable(ftun-runtime-cleanup-test tests/runtime_cleanup.c)
    target_include_directories(ftun-runtime-cleanup-test PRIVATE src)
    target_link_libraries(ftun-runtime-cleanup-test PRIVATE ftun_runtime ftun_options)
    target_link_options(ftun-runtime-cleanup-test PRIVATE -Wl,--wrap=ftun_route_table_destroy)
    if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
      target_sources(ftun-runtime-cleanup-test PRIVATE tests/frs_fixture.c)
      target_compile_definitions(ftun-runtime-cleanup-test PRIVATE FTUN_HAVE_MODULE_FRS=1)
      target_link_options(ftun-runtime-cleanup-test PRIVATE -Wl,--wrap=munmap -Wl,--wrap=calloc)
    endif()
    if(FTUN_STATIC)
      target_link_options(ftun-runtime-cleanup-test PRIVATE -static)
    endif()
    add_test(NAME runtime-cleanup-contract COMMAND ftun-runtime-cleanup-test)
    set_tests_properties(runtime-cleanup-contract PROPERTIES TIMEOUT 15)
    if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
      add_executable(ftun-runtime-detached-test tests/runtime_detached.c tests/frs_fixture.c)
      target_include_directories(ftun-runtime-detached-test PRIVATE src)
      target_compile_definitions(ftun-runtime-detached-test PRIVATE FTUN_HAVE_MODULE_FRS=1)
      target_link_libraries(ftun-runtime-detached-test PRIVATE ftun_runtime ftun_options)
      target_link_options(ftun-runtime-detached-test PRIVATE
        -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=free
        -Wl,--wrap=ftun_route_table_destroy)
      if(FTUN_STATIC)
        target_link_options(ftun-runtime-detached-test PRIVATE -static)
      endif()
      add_test(NAME runtime-detached-contract COMMAND ftun-runtime-detached-test)
      set_tests_properties(runtime-detached-contract PROPERTIES TIMEOUT 15)
    endif()
    add_executable(ftun-session-test tests/session.c)
    target_include_directories(ftun-session-test PRIVATE src)
    target_link_libraries(ftun-session-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-session-test PRIVATE -static)
    endif()
    add_test(NAME session-contract COMMAND ftun-session-test)
  endif()
  add_executable(ftun-buffer-test tests/buffer.c)
  target_include_directories(ftun-buffer-test PRIVATE src)
  target_link_libraries(ftun-buffer-test PRIVATE ftun_runtime ftun_options)
  target_link_options(ftun-buffer-test PRIVATE -Wl,--wrap=calloc)
  if(FTUN_STATIC)
    target_link_options(ftun-buffer-test PRIVATE -static)
  endif()
  add_test(NAME buffer-contract COMMAND ftun-buffer-test)
  add_executable(ftun-hash-test tests/hash.c)
  target_include_directories(ftun-hash-test PRIVATE src)
  target_link_libraries(ftun-hash-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-hash-test PRIVATE -static)
  endif()
  add_test(NAME hash-contract COMMAND ftun-hash-test)
  add_executable(ftun-logger-test tests/logger.c)
  target_include_directories(ftun-logger-test PRIVATE src)
  target_link_libraries(ftun-logger-test PRIVATE
    ftun_runtime ftun_options Threads::Threads)
  if(FTUN_STATIC)
    target_link_options(ftun-logger-test PRIVATE -static)
  endif()
  add_test(NAME logger-contract COMMAND ftun-logger-test)
  add_executable(ftun-log-ledger-test tests/log_ledger.c)
  target_include_directories(ftun-log-ledger-test PRIVATE src)
  target_link_libraries(ftun-log-ledger-test PRIVATE
    ftun_runtime ftun_options Threads::Threads)
  target_link_options(ftun-log-ledger-test PRIVATE -Wl,--wrap=close)
  if(FTUN_STATIC)
    target_link_options(ftun-log-ledger-test PRIVATE -static)
  endif()
  add_test(NAME log-ledger-contract COMMAND ftun-log-ledger-test)
  set_tests_properties(log-ledger-contract PROPERTIES TIMEOUT 30)
  add_executable(ftun-app-logging-test tests/app_logging.c)
  target_include_directories(ftun-app-logging-test PRIVATE src)
  target_link_libraries(ftun-app-logging-test PRIVATE
    ftun_runtime ftun_options Threads::Threads)
  target_link_options(ftun-app-logging-test PRIVATE
    -Wl,--wrap=ftun_logger_create -Wl,--wrap=ftun_worker_poll)
  if(FTUN_STATIC)
    target_link_options(ftun-app-logging-test PRIVATE -static)
  endif()
  add_test(NAME app-logging-contract COMMAND ftun-app-logging-test)
  set_tests_properties(app-logging-contract PROPERTIES TIMEOUT 30)
  add_executable(ftun-event-log-test tests/event_log.c)
  target_include_directories(ftun-event-log-test PRIVATE src)
  target_link_libraries(ftun-event-log-test PRIVATE
    ftun_runtime ftun_options Threads::Threads)
  if(FTUN_STATIC)
    target_link_options(ftun-event-log-test PRIVATE -static)
  endif()
  add_test(NAME event-log-contract COMMAND ftun-event-log-test)
  add_executable(ftun-cli-result-test tests/cli_result.c)
  target_include_directories(ftun-cli-result-test PRIVATE src)
  target_link_libraries(ftun-cli-result-test PRIVATE
    ftun_runtime ftun_options Threads::Threads)
  target_link_options(ftun-cli-result-test PRIVATE -Wl,--wrap=write
    -Wl,--wrap=ftun_budget_reserve_resources -Wl,--wrap=ftun_budget_destroy)
  if(FTUN_STATIC)
    target_link_options(ftun-cli-result-test PRIVATE -static)
  endif()
  add_test(NAME cli-result-contract COMMAND ftun-cli-result-test)
  set_tests_properties(cli-result-contract PROPERTIES TIMEOUT 30)
  add_executable(ftun-cli-preflight-test tests/cli_preflight.c)
  target_include_directories(ftun-cli-preflight-test PRIVATE src)
  target_link_libraries(ftun-cli-preflight-test PRIVATE
    ftun_runtime ftun_options Threads::Threads)
  target_link_options(ftun-cli-preflight-test PRIVATE
    -Wl,--wrap=ftun_config_load_budget_traced
    -Wl,--wrap=ftun_config_destroy -Wl,--wrap=ftun_core_destroy)
  if(FTUN_MODULE_FAKEIP STREQUAL "BUILTIN")
    target_compile_definitions(ftun-cli-preflight-test PRIVATE FTUN_HAVE_MODULE_FAKEIP=1)
    target_link_options(ftun-cli-preflight-test PRIVATE
      -Wl,--wrap=getrandom -Wl,--wrap=open -Wl,--wrap=close)
  endif()
  if(FTUN_STATIC)
    target_link_options(ftun-cli-preflight-test PRIVATE -static)
  endif()
  add_test(NAME cli-preflight-contract COMMAND ftun-cli-preflight-test)
  set_tests_properties(cli-preflight-contract PROPERTIES TIMEOUT 30)
  add_executable(ftun-operation-test tests/operation.c)
  target_include_directories(ftun-operation-test PRIVATE src)
  target_link_libraries(ftun-operation-test PRIVATE
    ftun_runtime ftun_options Threads::Threads)
  if(FTUN_STATIC)
    target_link_options(ftun-operation-test PRIVATE -static)
  endif()
  add_test(NAME operation-contract COMMAND ftun-operation-test)
  add_executable(ftun-worker-test tests/worker.c)
  target_include_directories(ftun-worker-test PRIVATE src)
  target_link_libraries(ftun-worker-test PRIVATE ftun_runtime ftun_options Threads::Threads)
  if(FTUN_STATIC)
    target_link_options(ftun-worker-test PRIVATE -static)
  endif()
  add_test(NAME worker-contract COMMAND ftun-worker-test)
  add_executable(ftun-event-test tests/event.c)
  target_include_directories(ftun-event-test PRIVATE src)
  target_link_libraries(ftun-event-test PRIVATE ftun_runtime ftun_options Threads::Threads)
  if(FTUN_STATIC)
    target_link_options(ftun-event-test PRIVATE -static)
  endif()
  add_test(NAME event-contract COMMAND ftun-event-test)
  add_executable(ftun-dialer-test tests/dialer.c)
  target_include_directories(ftun-dialer-test PRIVATE src)
  target_link_libraries(ftun-dialer-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-dialer-test PRIVATE -static)
  endif()
  add_test(NAME dialer-contract COMMAND ftun-dialer-test)
  add_executable(ftun-network-view-test tests/network_view.c)
  target_include_directories(ftun-network-view-test PRIVATE src)
  target_link_libraries(ftun-network-view-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-network-view-test PRIVATE -static)
  endif()
  add_test(NAME network-view-contract COMMAND ftun-network-view-test)
  add_executable(ftun-provider-bindings-test tests/provider_bindings.c)
  target_include_directories(ftun-provider-bindings-test PRIVATE src)
  target_link_libraries(ftun-provider-bindings-test PRIVATE
    ftun_runtime ftun_options)
  if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
    target_compile_definitions(ftun-provider-bindings-test PRIVATE
      FTUN_EXPECT_PROXY=1)
  endif()
  if(FTUN_MODULE_DNS STREQUAL "BUILTIN")
    target_compile_definitions(ftun-provider-bindings-test PRIVATE
      FTUN_EXPECT_DNS=1)
  endif()
  if(FTUN_STATIC)
    target_link_options(ftun-provider-bindings-test PRIVATE -static)
  endif()
  add_test(NAME provider-bindings-contract COMMAND ftun-provider-bindings-test)
  add_executable(ftun-resolver-provider-test tests/resolver_provider.c)
  target_include_directories(ftun-resolver-provider-test PRIVATE src)
  target_link_libraries(ftun-resolver-provider-test PRIVATE ftun_runtime ftun_options)
  add_test(NAME resolver-provider-contract COMMAND ftun-resolver-provider-test)
  add_executable(ftun-path-test tests/path.c)
  target_include_directories(ftun-path-test PRIVATE src)
  target_link_libraries(ftun-path-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-path-test PRIVATE -static)
  endif()
  add_test(NAME path-contract COMMAND ftun-path-test)
  add_executable(ftun-path-result-test tests/path_result.c)
  target_include_directories(ftun-path-result-test PRIVATE src)
  target_link_libraries(ftun-path-result-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-path-result-test PRIVATE -static)
  endif()
  add_test(NAME path-result-contract COMMAND ftun-path-result-test)
  add_executable(ftun-path-provider-test tests/path_provider.c)
  target_include_directories(ftun-path-provider-test PRIVATE src)
  target_link_libraries(ftun-path-provider-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-path-provider-test PRIVATE -static)
  endif()
  add_test(NAME path-provider-contract COMMAND ftun-path-provider-test)

  add_executable(ftun-socket-path-test tests/socket_path.c)
  target_include_directories(ftun-socket-path-test PRIVATE src)
  target_link_libraries(ftun-socket-path-test PRIVATE ftun_runtime ftun_options)
  target_link_options(ftun-socket-path-test PRIVATE -Wl,--wrap=send)
  if(FTUN_STATIC)
    target_link_options(ftun-socket-path-test PRIVATE -static)
  endif()
  add_test(NAME socket-path-contract COMMAND ftun-socket-path-test)
  add_executable(ftun-stream-test tests/stream.c)
  target_include_directories(ftun-stream-test PRIVATE src)
  target_link_libraries(ftun-stream-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-stream-test PRIVATE -static)
  endif()
  add_test(NAME stream-contract COMMAND ftun-stream-test)
  add_executable(ftun-stream-abort-test tests/stream_abort.c)
  target_include_directories(ftun-stream-abort-test PRIVATE src)
  target_link_libraries(ftun-stream-abort-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-stream-abort-test PRIVATE -static)
  endif()
  add_test(NAME stream-abort-contract COMMAND ftun-stream-abort-test)
  add_executable(ftun-datagram-test tests/datagram.c)
  target_include_directories(ftun-datagram-test PRIVATE src)
  target_link_libraries(ftun-datagram-test PRIVATE ftun_runtime ftun_options)
  target_link_options(ftun-datagram-test PRIVATE -Wl,--wrap=calloc)
  if(FTUN_STATIC)
    target_link_options(ftun-datagram-test PRIVATE -static)
  endif()
  add_test(NAME datagram-contract COMMAND ftun-datagram-test)
  add_executable(ftun-carrier-test tests/carrier.c)
  target_include_directories(ftun-carrier-test PRIVATE src)
  target_link_libraries(ftun-carrier-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-carrier-test PRIVATE -static)
  endif()
  add_test(NAME carrier-owner-contract COMMAND ftun-carrier-test)
  add_executable(ftun-relay-test tests/relay.c)
  target_include_directories(ftun-relay-test PRIVATE src)
  target_link_libraries(ftun-relay-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-relay-test PRIVATE -static)
  endif()
  add_test(NAME relay-contract COMMAND ftun-relay-test)
  add_executable(ftun-protocol-socks5-test tests/protocol_socks5.c)
  target_include_directories(ftun-protocol-socks5-test PRIVATE src)
  target_link_libraries(ftun-protocol-socks5-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-protocol-socks5-test PRIVATE -static)
  endif()
  add_test(NAME protocol-socks5-contract COMMAND ftun-protocol-socks5-test)
  add_executable(ftun-protocol-http-test tests/protocol_http.c)
  target_include_directories(ftun-protocol-http-test PRIVATE src)
  target_link_libraries(ftun-protocol-http-test PRIVATE ftun_runtime ftun_options)
  add_test(NAME protocol-http-contract COMMAND ftun-protocol-http-test)
  if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
    add_executable(ftun-inbound-socks5-test tests/inbound_socks5.c)
    target_include_directories(ftun-inbound-socks5-test PRIVATE src)
    target_link_libraries(ftun-inbound-socks5-test PRIVATE ftun_runtime ftun_options)
    add_test(NAME inbound-socks5-contract COMMAND ftun-inbound-socks5-test)
    add_executable(ftun-inbound-mixed-test tests/inbound_mixed.c)
    target_include_directories(ftun-inbound-mixed-test PRIVATE src)
    target_link_libraries(ftun-inbound-mixed-test PRIVATE
      ftun_runtime ftun_options)
    add_test(NAME inbound-mixed-contract COMMAND ftun-inbound-mixed-test)
    add_executable(ftun-inbound-adapter-test tests/inbound_adapter.c)
    target_include_directories(ftun-inbound-adapter-test PRIVATE src)
    target_link_libraries(ftun-inbound-adapter-test PRIVATE ftun_runtime ftun_options)
    add_test(NAME inbound-adapter-contract COMMAND ftun-inbound-adapter-test)
    add_executable(ftun-outbound-path-test tests/outbound_path.c tests/memory_path_factory.c)
    target_include_directories(ftun-outbound-path-test PRIVATE src)
    target_link_libraries(ftun-outbound-path-test PRIVATE ftun_runtime ftun_options)
    add_test(NAME outbound-path-contract COMMAND ftun-outbound-path-test)
    add_executable(ftun-socks-path-test tests/socks_path.c tests/memory_path_factory.c)
    target_include_directories(ftun-socks-path-test PRIVATE src)
    target_link_libraries(ftun-socks-path-test PRIVATE ftun_runtime ftun_options)
    add_test(NAME socks-path-contract COMMAND ftun-socks-path-test)
    add_executable(ftun-socks-datagram-test tests/socks_datagram.c tests/memory_path_factory.c)
    target_include_directories(ftun-socks-datagram-test PRIVATE src)
    target_link_libraries(ftun-socks-datagram-test PRIVATE ftun_runtime ftun_options)
    add_test(NAME socks-datagram-contract COMMAND ftun-socks-datagram-test)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      add_executable(ftun-memory-path-test src/app/main.c tests/memory_path_factory.c)
      target_include_directories(ftun-memory-path-test PRIVATE src)
      target_link_libraries(ftun-memory-path-test PRIVATE ftun_runtime ftun_options)
      target_link_options(ftun-memory-path-test PRIVATE -Wl,--wrap=ftun_socket_path_open)
      if(FTUN_MODULE_DNS STREQUAL "BUILTIN")
        add_executable(ftun-resolver-production-test src/app/main.c tests/resolver_factory_probe.c)
        target_include_directories(ftun-resolver-production-test PRIVATE src)
        target_link_libraries(ftun-resolver-production-test PRIVATE ftun_runtime ftun_options)
        target_link_options(ftun-resolver-production-test PRIVATE -Wl,--wrap=ftun_resolver_scope_start)
      endif()
    endif()
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      add_executable(ftun-control-channel-test tests/control_channel.c)
      target_include_directories(ftun-control-channel-test PRIVATE src)
      target_link_libraries(ftun-control-channel-test PRIVATE ftun_runtime ftun_options)
      target_link_options(ftun-control-channel-test PRIVATE -Wl,--wrap=ftun_socket_path_open)
      add_test(NAME control-channel-contract COMMAND ftun-control-channel-test)
      add_executable(ftun-control-resolution-test tests/control_resolution.c)
      target_include_directories(ftun-control-resolution-test PRIVATE src)
      target_link_libraries(ftun-control-resolution-test PRIVATE ftun_runtime ftun_options)
      add_test(NAME control-resolution-contract COMMAND ftun-control-resolution-test)
      add_executable(ftun-control-system-worker-test tests/control_system_worker.c)
      target_include_directories(ftun-control-system-worker-test PRIVATE src)
      target_link_libraries(ftun-control-system-worker-test PRIVATE ftun_runtime ftun_options Threads::Threads)
      target_link_options(ftun-control-system-worker-test PRIVATE -Wl,--wrap=getaddrinfo)
      add_test(NAME control-system-worker-contract COMMAND ftun-control-system-worker-test)
      add_executable(ftun-control-datagram-test tests/control_datagram.c)
      target_include_directories(ftun-control-datagram-test PRIVATE src)
      target_link_libraries(ftun-control-datagram-test PRIVATE ftun_runtime ftun_options)
      target_link_options(ftun-control-datagram-test PRIVATE -Wl,--wrap=ftun_socket_path_open)
      add_test(NAME control-datagram-contract COMMAND ftun-control-datagram-test)
      add_executable(ftun-http-fetch-test tests/http_fetch.c)
      target_include_directories(ftun-http-fetch-test PRIVATE src)
      target_link_libraries(ftun-http-fetch-test PRIVATE ftun_runtime ftun_options)
      target_link_options(ftun-http-fetch-test PRIVATE -Wl,--wrap=ftun_tls_client_open)
      if(FTUN_MODULE_DNS STREQUAL "BUILTIN")
        add_executable(ftun-control-dns-test tests/control_dns.c)
        target_include_directories(ftun-control-dns-test PRIVATE src)
        target_link_libraries(ftun-control-dns-test PRIVATE ftun_runtime ftun_options)
        target_link_options(ftun-control-dns-test PRIVATE -Wl,--wrap=ftun_resolver_provider_start -Wl,--wrap=getaddrinfo)
      endif()
    endif()
    add_executable(ftun-v04-group-test tests/group.c)
    target_include_directories(ftun-v04-group-test PRIVATE src)
    target_link_libraries(ftun-v04-group-test PRIVATE ftun_runtime ftun_options)
    add_test(NAME group-contract COMMAND ftun-v04-group-test)
    add_executable(ftun-sniff-tls-test tests/sniff_tls.c)
    target_include_directories(ftun-sniff-tls-test PRIVATE src)
    target_link_libraries(ftun-sniff-tls-test PRIVATE ftun_runtime ftun_options)
    add_test(NAME sniff-tls-contract COMMAND ftun-sniff-tls-test)
    add_executable(ftun-sniff-http-test tests/sniff_http.c)
    target_include_directories(ftun-sniff-http-test PRIVATE src)
    target_link_libraries(ftun-sniff-http-test PRIVATE ftun_runtime ftun_options)
    add_test(NAME sniff-http-contract COMMAND ftun-sniff-http-test)
    add_executable(ftun-sniff-test tests/sniff.c)
    target_include_directories(ftun-sniff-test PRIVATE src)
    target_link_libraries(ftun-sniff-test PRIVATE ftun_runtime ftun_options)
    add_test(NAME sniff-contract COMMAND ftun-sniff-test)
    set(ftun_untrusted_parser_sources tests/untrusted_parsers.c)
    if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
      list(APPEND ftun_untrusted_parser_sources tests/frs_fixture.c)
    endif()
    add_executable(ftun-untrusted-parsers-test
      ${ftun_untrusted_parser_sources})
    target_include_directories(ftun-untrusted-parsers-test PRIVATE src tests)
    target_link_libraries(ftun-untrusted-parsers-test PRIVATE
      ftun_runtime ftun_options)
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
    target_link_libraries(ftun-group-cache-test PRIVATE ftun_runtime ftun_options)
    add_test(NAME group-cache-contract COMMAND ftun-group-cache-test)
    add_executable(ftun-core-state-test tests/core_state.c)
    target_include_directories(ftun-core-state-test PRIVATE src)
    target_link_libraries(ftun-core-state-test PRIVATE ftun_runtime ftun_options)
    add_test(NAME core-state-contract COMMAND ftun-core-state-test)
    add_executable(ftun-v05-integration-test tests/integration_v05.c)
    target_include_directories(ftun-v05-integration-test PRIVATE src)
    target_link_libraries(ftun-v05-integration-test PRIVATE
      ftun_runtime ftun_options Threads::Threads)
    add_test(NAME integration-v05-contract COMMAND ftun-v05-integration-test)
    add_executable(ftun-control-resolver-test tests/control_resolver.c)
    target_include_directories(ftun-control-resolver-test PRIVATE src)
    target_link_libraries(ftun-control-resolver-test PRIVATE
      ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-control-resolver-test PRIVATE -static)
    endif()
    add_test(NAME control-resolver-contract COMMAND ftun-control-resolver-test)
    if(FTUN_MODULE_FRS STREQUAL "BUILTIN" AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
      add_executable(ftun-control-memory-test src/app/main.c tests/control_memory_factory.c tests/frs_fixture.c)
      target_include_directories(ftun-control-memory-test PRIVATE src tests)
      target_link_libraries(ftun-control-memory-test PRIVATE ftun_runtime ftun_options)
      target_link_options(ftun-control-memory-test PRIVATE -Wl,--wrap=ftun_socket_path_open -Wl,--wrap=ftun_resolver_provider_start)
    endif()
    if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
      add_executable(ftun-v04-frs-test tests/frs.c tests/frs_fixture.c)
      target_include_directories(ftun-v04-frs-test PRIVATE src tests)
      target_link_libraries(ftun-v04-frs-test PRIVATE ftun_runtime ftun_options)
      add_test(NAME frs-contract COMMAND ftun-v04-frs-test)
      add_executable(ftun-v04-frs-update-test
        tests/frs_update.c tests/frs_fixture.c)
      target_include_directories(ftun-v04-frs-update-test PRIVATE src tests)
      target_link_libraries(ftun-v04-frs-update-test PRIVATE
        ftun_runtime ftun_options)
      add_test(NAME frs-update-contract COMMAND ftun-v04-frs-update-test)
      add_executable(ftun-app-frs-test tests/app_frs.c tests/frs_fixture.c)
      target_include_directories(ftun-app-frs-test PRIVATE src tests)
      target_link_libraries(ftun-app-frs-test PRIVATE ftun_runtime ftun_options Threads::Threads)
      target_link_options(ftun-app-frs-test PRIVATE
        -Wl,--wrap=ftun_http_fetch -Wl,--wrap=ftun_file_write_atomic_budget)
      if(FTUN_STATIC)
        target_link_options(ftun-app-frs-test PRIVATE -static)
      endif()
      add_test(NAME app-frs-contract COMMAND ftun-app-frs-test)
      add_executable(ftun-runtime-worker-cleanup-test
        tests/runtime_worker_cleanup.c tests/frs_fixture.c)
      target_include_directories(ftun-runtime-worker-cleanup-test PRIVATE src tests)
      target_link_libraries(ftun-runtime-worker-cleanup-test PRIVATE
        ftun_runtime ftun_options Threads::Threads)
      target_link_options(ftun-runtime-worker-cleanup-test PRIVATE
        -Wl,--wrap=ftun_http_fetch -Wl,--wrap=ftun_runtime_prepared_release)
      if(FTUN_STATIC)
        target_link_options(ftun-runtime-worker-cleanup-test PRIVATE -static)
      endif()
      add_test(NAME runtime-worker-cleanup-contract COMMAND ftun-runtime-worker-cleanup-test)
      set_tests_properties(runtime-worker-cleanup-contract PROPERTIES TIMEOUT 20)
    endif()
  endif()
  add_executable(ftun-v04-tls-test tests/tls.c)
  target_include_directories(ftun-v04-tls-test PRIVATE src)
  target_compile_definitions(ftun-v04-tls-test PRIVATE
    "FTUN_TEST_CERT_DIR=${CMAKE_CURRENT_SOURCE_DIR}/third_party/wolfssl/certs")
  target_link_libraries(ftun-v04-tls-test PRIVATE
    ftun_runtime ftun_options wolfssl::wolfssl)
  add_test(NAME tls-wolfssl-contract COMMAND ftun-v04-tls-test)
  add_executable(ftun-tls-resources-test tests/tls_resources.c)
  target_include_directories(ftun-tls-resources-test PRIVATE src)
  target_compile_definitions(ftun-tls-resources-test PRIVATE
    "FTUN_TEST_CERT_DIR=${CMAKE_CURRENT_SOURCE_DIR}/third_party/wolfssl/certs")
  target_link_libraries(ftun-tls-resources-test PRIVATE
    ftun_runtime ftun_options wolfssl::wolfssl)
  target_link_options(ftun-tls-resources-test PRIVATE
    -Wl,--wrap=wolfSSL_Init -Wl,--wrap=wolfSSL_CTX_new
    -Wl,--wrap=wolfSSL_new -Wl,--wrap=wolfSSL_UseSNI)
  add_test(NAME tls-resources-contract COMMAND ftun-tls-resources-test)
  add_executable(ftun-tls-global-test tests/tls_global.c)
  target_include_directories(ftun-tls-global-test PRIVATE src)
  target_compile_definitions(ftun-tls-global-test PRIVATE
    "FTUN_TEST_CERT_DIR=${CMAKE_CURRENT_SOURCE_DIR}/third_party/wolfssl/certs")
  target_link_libraries(ftun-tls-global-test PRIVATE
    ftun_runtime ftun_options wolfssl::wolfssl Threads::Threads)
  target_link_options(ftun-tls-global-test PRIVATE
    -Wl,--wrap=wolfSSL_Init -Wl,--wrap=wolfSSL_Cleanup -Wl,--wrap=atexit)
  add_test(NAME tls-global-contract COMMAND ftun-tls-global-test)
  set_tests_properties(tls-global-contract PROPERTIES TIMEOUT 30)
  if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
    add_executable(ftun-v04-integration-test
      tests/integration_v04.c tests/frs_fixture.c)
    target_include_directories(ftun-v04-integration-test PRIVATE src tests)
    target_link_libraries(ftun-v04-integration-test PRIVATE
      ftun_runtime ftun_options)
    add_test(NAME integration-v04-contract COMMAND ftun-v04-integration-test)
  endif()
  if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
    add_executable(ftun-route-target-test tests/route_target.c)
    target_include_directories(ftun-route-target-test PRIVATE src)
    target_link_libraries(ftun-route-target-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-route-target-test PRIVATE -static)
    endif()
    add_test(NAME route-target-contract COMMAND ftun-route-target-test)
    add_executable(ftun-route-rule-test tests/route_rule.c)
    target_include_directories(ftun-route-rule-test PRIVATE src)
    target_link_libraries(ftun-route-rule-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-route-rule-test PRIVATE -static)
    endif()
    add_test(NAME route-rule-contract COMMAND ftun-route-rule-test)
    add_executable(ftun-route-router-test tests/route_router.c)
    target_include_directories(ftun-route-router-test PRIVATE src)
    target_link_libraries(ftun-route-router-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-route-router-test PRIVATE -static)
    endif()
    add_test(NAME route-router-contract COMMAND ftun-route-router-test)
    add_executable(ftun-route-memory-test tests/route_memory.c)
    target_include_directories(ftun-route-memory-test PRIVATE src)
    target_link_libraries(ftun-route-memory-test PRIVATE ftun_runtime ftun_options)
    target_link_options(ftun-route-memory-test PRIVATE
      -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=free)
    if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
      target_sources(ftun-route-memory-test PRIVATE tests/frs_fixture.c)
      target_compile_definitions(ftun-route-memory-test PRIVATE FTUN_HAVE_MODULE_FRS=1)
      target_link_options(ftun-route-memory-test PRIVATE -Wl,--wrap=open -Wl,--wrap=read)
    endif()
    if(FTUN_STATIC)
      target_link_options(ftun-route-memory-test PRIVATE -static)
    endif()
    add_test(NAME route-memory-contract COMMAND ftun-route-memory-test)
    set_tests_properties(route-memory-contract PROPERTIES TIMEOUT 30)
    add_executable(ftun-outbound-reject-test tests/outbound_reject.c)
    target_include_directories(ftun-outbound-reject-test PRIVATE src)
    target_link_libraries(ftun-outbound-reject-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-outbound-reject-test PRIVATE -static)
    endif()
    add_test(NAME outbound-reject-contract COMMAND ftun-outbound-reject-test)
    add_executable(ftun-outbound-direct-test tests/outbound_direct.c)
    target_include_directories(ftun-outbound-direct-test PRIVATE src)
    target_link_libraries(ftun-outbound-direct-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-outbound-direct-test PRIVATE -static)
    endif()
    add_test(NAME outbound-direct-contract COMMAND ftun-outbound-direct-test)
    add_executable(ftun-outbound-socks5-test tests/outbound_socks5.c)
    target_include_directories(ftun-outbound-socks5-test PRIVATE src)
    target_link_libraries(ftun-outbound-socks5-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-outbound-socks5-test PRIVATE -static)
    endif()
    add_test(NAME outbound-socks5-contract COMMAND ftun-outbound-socks5-test)
    add_executable(ftun-outbound-test tests/outbound.c)
    target_include_directories(ftun-outbound-test PRIVATE src)
    target_link_libraries(ftun-outbound-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-outbound-test PRIVATE -static)
    endif()
    add_test(NAME outbound-contract COMMAND ftun-outbound-test)
  endif()
  if(TARGET ftun_libev)
    add_executable(ftun-libev-test tests/libev_adapter.c)
    target_include_directories(ftun-libev-test PRIVATE src)
    target_link_libraries(ftun-libev-test PRIVATE ftun_runtime ftun_options Threads::Threads)
    target_link_options(ftun-libev-test PRIVATE
      -Wl,--wrap=ftun_event_io_ready -Wl,--wrap=epoll_wait -Wl,--wrap=epoll_ctl
      -Wl,--wrap=read -Wl,--wrap=write)
    if(FTUN_STATIC)
      target_link_options(ftun-libev-test PRIVATE -static)
    endif()
    add_test(NAME libev-adapter COMMAND ftun-libev-test)
    set_tests_properties(libev-adapter PROPERTIES TIMEOUT 20)
    add_executable(ftun-event-resources-test tests/event_resources.c)
    target_include_directories(ftun-event-resources-test PRIVATE src)
    target_link_libraries(ftun-event-resources-test PRIVATE ftun_runtime ftun_options Threads::Threads)
    target_link_options(ftun-event-resources-test PRIVATE
      -Wl,--wrap=eventfd -Wl,--wrap=pipe -Wl,--wrap=ftun_event_source_backend_data)
    if(FTUN_STATIC)
      target_link_options(ftun-event-resources-test PRIVATE -static)
    endif()
    add_test(NAME event-resources-contract COMMAND ftun-event-resources-test)
    set_tests_properties(event-resources-contract PROPERTIES TIMEOUT 20)
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
  add_executable(ftun-config-memory-test tests/config_memory.c)
  target_include_directories(ftun-config-memory-test PRIVATE src)
  target_link_libraries(ftun-config-memory-test PRIVATE ftun_runtime ftun_options Threads::Threads)
  target_link_options(ftun-config-memory-test PRIVATE
    -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc -Wl,--wrap=free
    -Wl,--wrap=fstat -Wl,--wrap=getpwuid_r)
  if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
    target_compile_definitions(ftun-config-memory-test PRIVATE FTUN_HAVE_MODULE_PROXY=1)
  endif()
  if(FTUN_STATIC)
    target_link_options(ftun-config-memory-test PRIVATE -static)
  endif()
  add_test(NAME config-memory-contract COMMAND ftun-config-memory-test)
  set_tests_properties(config-memory-contract PROPERTIES TIMEOUT 30)
  target_include_directories(ftun-config-parser-test PRIVATE src)
  target_link_libraries(ftun-config-parser-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-config-parser-test PRIVATE -static)
  endif()
  add_test(NAME config-parser COMMAND ftun-config-parser-test
    ${CMAKE_CURRENT_SOURCE_DIR}/examples/full.json)
  add_executable(ftun-config-validate-test tests/config_validate.c)
  target_include_directories(ftun-config-validate-test PRIVATE src)
  target_link_libraries(ftun-config-validate-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-config-validate-test PRIVATE -static)
  endif()
  add_executable(ftun-config-compile-test tests/config_compile.c)
  target_include_directories(ftun-config-compile-test PRIVATE src)
  target_link_libraries(ftun-config-compile-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-config-compile-test PRIVATE -static)
  endif()
  add_executable(ftun-config-load-test tests/config_load.c)
  target_include_directories(ftun-config-load-test PRIVATE src)
  target_link_libraries(ftun-config-load-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-config-load-test PRIVATE -static)
  endif()
  # 这三项深入验证完整配置的 FRS/DNS/FakeIP/TUN 计划；裁剪档由
  # build-modules-capabilities 覆盖缺席能力的拒绝语义。
  if(FTUN_MODULE_DNS STREQUAL "BUILTIN" AND
     FTUN_MODULE_FAKEIP STREQUAL "BUILTIN" AND
     FTUN_MODULE_TUN STREQUAL "BUILTIN" AND
     FTUN_MODULE_FRS STREQUAL "BUILTIN")
    add_test(NAME config-validate COMMAND ftun-config-validate-test
      ${CMAKE_CURRENT_SOURCE_DIR}/examples/full.json)
    add_test(NAME config-compile COMMAND ftun-config-compile-test
      ${CMAKE_CURRENT_SOURCE_DIR}/examples/full.json)
    add_test(NAME config-load COMMAND ftun-config-load-test)
  endif()
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(ftun-platform-file-test tests/platform_file.c)
    target_include_directories(ftun-platform-file-test PRIVATE src)
    target_link_libraries(ftun-platform-file-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-platform-file-test PRIVATE -static)
    endif()
    add_test(NAME platform-file-contract COMMAND ftun-platform-file-test)
    add_executable(ftun-platform-linux-socket-protect-test
      tests/platform_linux_socket_protect.c)
    target_include_directories(ftun-platform-linux-socket-protect-test PRIVATE src)
    target_link_libraries(ftun-platform-linux-socket-protect-test PRIVATE
      ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-platform-linux-socket-protect-test PRIVATE -static)
    endif()
    add_test(NAME platform-linux-socket-protect
      COMMAND ftun-platform-linux-socket-protect-test)
    add_executable(ftun-platform-system-resolver-test
      tests/platform_system_resolver.c)
    target_include_directories(ftun-platform-system-resolver-test PRIVATE src)
    target_link_libraries(ftun-platform-system-resolver-test PRIVATE
      ftun_runtime ftun_options Threads::Threads)
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
      ftun_runtime ftun_options Threads::Threads)
    target_link_options(ftun-fakeip-store-test PRIVATE
      -Wl,--wrap=open -Wl,--wrap=close -Wl,--wrap=mkstemp)
    if(FTUN_STATIC)
      target_link_options(ftun-fakeip-store-test PRIVATE -static)
    endif()
    add_test(NAME fakeip-store-contract COMMAND ftun-fakeip-store-test)
    add_executable(ftun-fakeip-snapshot-test tests/fakeip_snapshot.c)
    target_include_directories(ftun-fakeip-snapshot-test PRIVATE src)
    target_link_libraries(ftun-fakeip-snapshot-test PRIVATE
      ftun_runtime ftun_options Threads::Threads)
    if(FTUN_STATIC)
      target_link_options(ftun-fakeip-snapshot-test PRIVATE -static)
    endif()
    add_test(NAME fakeip-snapshot-contract COMMAND ftun-fakeip-snapshot-test)
    add_executable(ftun-fakeip-test tests/fakeip.c)
    target_include_directories(ftun-fakeip-test PRIVATE src)
    target_link_libraries(ftun-fakeip-test PRIVATE
      ftun_runtime ftun_options Threads::Threads)
    if(FTUN_STATIC)
      target_link_options(ftun-fakeip-test PRIVATE -static)
    endif()
    add_test(NAME fakeip-contract COMMAND ftun-fakeip-test)
  endif()
  if(FTUN_MODULE_DNS STREQUAL "BUILTIN")
    add_executable(ftun-dns-dependencies-test tests/dns_dependencies.c)
    target_include_directories(ftun-dns-dependencies-test PRIVATE src)
    target_compile_definitions(ftun-dns-dependencies-test PRIVATE
      FTUN_HAVE_MODULE_DNS=1)
    if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
      target_compile_definitions(ftun-dns-dependencies-test PRIVATE FTUN_TEST_PROXY=1)
    endif()
    target_link_libraries(ftun-dns-dependencies-test PRIVATE
      ftun_runtime ftun_options Threads::Threads)
    target_link_options(ftun-dns-dependencies-test PRIVATE
      -Wl,--wrap=calloc -Wl,--wrap=ftun_config_destroy)
    if(FTUN_STATIC)
      target_link_options(ftun-dns-dependencies-test PRIVATE -static)
    endif()
    add_test(NAME dns-dependencies-contract COMMAND ftun-dns-dependencies-test)
    set_tests_properties(dns-dependencies-contract PROPERTIES TIMEOUT 30)
    add_executable(ftun-dns-service-test
      tests/dns_service.c
      $<TARGET_OBJECTS:ftun_core>
      $<TARGET_OBJECTS:ftun_shared_services>
      $<TARGET_OBJECTS:ftun_module_dns>)
    target_include_directories(ftun-dns-service-test PRIVATE include src)
    target_link_options(ftun-dns-service-test PRIVATE
      -Wl,--wrap=ftun_monotonic_now -Wl,--wrap=ftun_event_loop_run_once)
    target_compile_definitions(ftun-dns-service-test PRIVATE
      FTUN_HAVE_MODULE_DNS=1)
    target_link_libraries(ftun-dns-service-test PRIVATE
      ftun_options Threads::Threads ftun_cjson wolfssl::wolfssl)
    if(TARGET ftun_libev)
      target_link_libraries(ftun-dns-service-test PRIVATE ftun_libev)
    endif()
    if(FTUN_STATIC)
      target_link_options(ftun-dns-service-test PRIVATE -static)
    endif()
    add_test(NAME dns-service-independent-contract
      COMMAND ftun-dns-service-test)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      add_executable(ftun-dns-memory-path-test src/app/main.c tests/memory_path_factory.c)
      target_include_directories(ftun-dns-memory-path-test PRIVATE src)
      target_link_libraries(ftun-dns-memory-path-test PRIVATE ftun_runtime ftun_options)
      target_link_options(ftun-dns-memory-path-test PRIVATE -Wl,--wrap=ftun_socket_path_open)
    endif()
    add_executable(ftun-dns-service-failures-test tests/dns_service_failures.c)
    target_include_directories(ftun-dns-service-failures-test PRIVATE src)
    target_compile_definitions(ftun-dns-service-failures-test PRIVATE
      FTUN_HAVE_MODULE_DNS=1)
    if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
      target_compile_definitions(ftun-dns-service-failures-test PRIVATE
        FTUN_TEST_PROXY=1)
    endif()
    target_link_libraries(ftun-dns-service-failures-test PRIVATE
      ftun_runtime ftun_options Threads::Threads)
    target_link_options(ftun-dns-service-failures-test PRIVATE
      -Wl,--wrap=send -Wl,--wrap=recv -Wl,--wrap=close -Wl,--wrap=socket
      -Wl,--wrap=calloc -Wl,--wrap=ftun_event_source_cancel
      -Wl,--wrap=ftun_event_io_start -Wl,--wrap=ftun_dns_cache_create)
    if(FTUN_STATIC)
      target_link_options(ftun-dns-service-failures-test PRIVATE -static)
    endif()
    add_test(NAME dns-service-failures-contract
      COMMAND ftun-dns-service-failures-test)
    add_executable(ftun-dns-path-lifecycle-test tests/dns_path_lifecycle.c)
    target_include_directories(ftun-dns-path-lifecycle-test PRIVATE src)
    target_compile_definitions(ftun-dns-path-lifecycle-test PRIVATE FTUN_HAVE_MODULE_DNS=1)
    target_link_libraries(ftun-dns-path-lifecycle-test PRIVATE ftun_runtime ftun_options)
    add_test(NAME dns-path-lifecycle-contract COMMAND ftun-dns-path-lifecycle-test)
    if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
      add_executable(ftun-service-leaf-cleanup-test tests/service_leaf_cleanup.c)
      target_include_directories(ftun-service-leaf-cleanup-test PRIVATE src)
      target_link_libraries(ftun-service-leaf-cleanup-test PRIVATE
        ftun_runtime ftun_options Threads::Threads)
      target_link_options(ftun-service-leaf-cleanup-test PRIVATE
        -Wl,--wrap=ftun_proxy_slot_pool_create
        -Wl,--wrap=ftun_worker_set_wakeup
        -Wl,--wrap=ftun_dns_dispatcher_destroy -Wl,--wrap=socket -Wl,--wrap=close)
      if(FTUN_STATIC)
        target_link_options(ftun-service-leaf-cleanup-test PRIVATE -static)
      endif()
      add_test(NAME service-leaf-cleanup-contract
        COMMAND ftun-service-leaf-cleanup-test)
    endif()
    add_executable(ftun-dns-cache-test tests/dns_cache.c)
    target_include_directories(ftun-dns-cache-test PRIVATE src)
    target_link_libraries(ftun-dns-cache-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-dns-cache-test PRIVATE -static)
    endif()
    add_test(NAME dns-cache-contract COMMAND ftun-dns-cache-test)
    if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
      add_executable(ftun-dns-server-test tests/dns_server.c)
      target_include_directories(ftun-dns-server-test PRIVATE src)
      target_link_libraries(ftun-dns-server-test PRIVATE ftun_runtime ftun_options)
      if(FTUN_STATIC)
        target_link_options(ftun-dns-server-test PRIVATE -static)
      endif()
      add_test(NAME dns-server-contract COMMAND ftun-dns-server-test)
      add_executable(ftun-dns-query-binding-test tests/dns_query_binding.c)
      target_include_directories(ftun-dns-query-binding-test PRIVATE src)
      target_compile_definitions(ftun-dns-query-binding-test PRIVATE
        FTUN_HAVE_MODULE_DNS=1)
      target_link_libraries(ftun-dns-query-binding-test PRIVATE
        ftun_runtime ftun_options Threads::Threads)
      if(FTUN_STATIC)
        target_link_options(ftun-dns-query-binding-test PRIVATE -static)
      endif()
      add_test(NAME dns-query-binding-contract COMMAND ftun-dns-query-binding-test)
      add_executable(ftun-dns-dispatch-test tests/dns_dispatch.c)
      target_include_directories(ftun-dns-dispatch-test PRIVATE src)
      target_link_libraries(ftun-dns-dispatch-test PRIVATE ftun_runtime ftun_options)
      if(FTUN_STATIC)
        target_link_options(ftun-dns-dispatch-test PRIVATE -static)
      endif()
      add_test(NAME dns-dispatch-contract COMMAND ftun-dns-dispatch-test)
      add_executable(ftun-dns-listener-test tests/dns_listener.c)
      target_include_directories(ftun-dns-listener-test PRIVATE src)
      target_link_libraries(ftun-dns-listener-test PRIVATE ftun_runtime ftun_options)
      if(FTUN_STATIC)
        target_link_options(ftun-dns-listener-test PRIVATE -static)
      endif()
      add_test(NAME dns-listener-contract COMMAND ftun-dns-listener-test)
      add_executable(ftun-v03-integration-test tests/integration_v03.c)
      target_include_directories(ftun-v03-integration-test PRIVATE src)
      target_link_libraries(ftun-v03-integration-test PRIVATE
        ftun_runtime ftun_options Threads::Threads)
      if(FTUN_STATIC)
        target_link_options(ftun-v03-integration-test PRIVATE -static)
      endif()
      add_test(NAME integration-v03-contract COMMAND ftun-v03-integration-test)
    endif()
    add_executable(ftun-dns-wire-test tests/dns_wire.c)
    target_include_directories(ftun-dns-wire-test PRIVATE src)
    target_link_libraries(ftun-dns-wire-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-dns-wire-test PRIVATE -static)
    endif()
    add_test(NAME dns-wire-contract COMMAND ftun-dns-wire-test)
    add_executable(ftun-dns-bootstrap-test tests/dns_bootstrap.c)
    target_include_directories(ftun-dns-bootstrap-test PRIVATE src)
    target_link_libraries(ftun-dns-bootstrap-test PRIVATE
      ftun_runtime ftun_options Threads::Threads)
    if(FTUN_STATIC)
      target_link_options(ftun-dns-bootstrap-test PRIVATE -static)
    endif()
    add_test(NAME dns-bootstrap-contract COMMAND ftun-dns-bootstrap-test)
    if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
      add_executable(ftun-dns-resolver-test tests/dns_resolver.c)
      target_include_directories(ftun-dns-resolver-test PRIVATE src)
      target_link_libraries(ftun-dns-resolver-test PRIVATE ftun_runtime ftun_options)
      if(FTUN_STATIC)
        target_link_options(ftun-dns-resolver-test PRIVATE -static)
      endif()
      add_test(NAME dns-resolver-contract COMMAND ftun-dns-resolver-test)
    endif()
  endif()
  if(FTUN_MODULE_TUN STREQUAL "BUILTIN")
    if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
      add_executable(ftun-inbound-test tests/inbound.c)
      target_include_directories(ftun-inbound-test PRIVATE src)
      target_link_libraries(ftun-inbound-test PRIVATE ftun_runtime ftun_options)
      if(FTUN_STATIC)
        target_link_options(ftun-inbound-test PRIVATE -static)
      endif()
      add_test(NAME inbound-contract COMMAND ftun-inbound-test)
    endif()
    add_executable(ftun-platform-linux-tun-test tests/platform_linux_tun.c)
    target_include_directories(ftun-platform-linux-tun-test PRIVATE src)
    target_link_libraries(ftun-platform-linux-tun-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-platform-linux-tun-test PRIVATE -static)
    endif()
    add_test(NAME platform-linux-tun COMMAND ftun-platform-linux-tun-test)
    add_executable(ftun-platform-linux-route-test tests/platform_linux_route.c)
    target_include_directories(ftun-platform-linux-route-test PRIVATE src)
    target_link_libraries(ftun-platform-linux-route-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-platform-linux-route-test PRIVATE -static)
    endif()
    add_test(NAME platform-linux-route COMMAND ftun-platform-linux-route-test)
    add_executable(ftun-platform-linux-route-async-test
      tests/platform_linux_route_async.c)
    target_include_directories(ftun-platform-linux-route-async-test PRIVATE src)
    target_link_libraries(ftun-platform-linux-route-async-test PRIVATE
      ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-platform-linux-route-async-test PRIVATE -static)
    endif()
    add_test(NAME platform-linux-route-async
      COMMAND ftun-platform-linux-route-async-test)
    add_executable(ftun-tun-port-test tests/tun_port.c)
    target_include_directories(ftun-tun-port-test PRIVATE src)
    target_link_libraries(ftun-tun-port-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-tun-port-test PRIVATE -static)
    endif()
    add_test(NAME tun-packet-port COMMAND ftun-tun-port-test)
    add_executable(ftun-tun-service-test tests/tun_service.c)
    target_include_directories(ftun-tun-service-test PRIVATE src)
    target_link_libraries(ftun-tun-service-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-tun-service-test PRIVATE -static)
    endif()
    add_test(NAME tun-service-contract COMMAND ftun-tun-service-test)
    add_executable(ftun-tun-owner-test tests/tun_owner.c)
    target_include_directories(ftun-tun-owner-test PRIVATE src)
  target_link_libraries(ftun-tun-owner-test PRIVATE ftun_runtime ftun_options)
  target_link_options(ftun-tun-owner-test PRIVATE -Wl,--wrap=calloc)
    if(FTUN_STATIC)
      target_link_options(ftun-tun-owner-test PRIVATE -static)
    endif()
    add_test(NAME tun-owner-composition-contract COMMAND ftun-tun-owner-test)
    if(FTUN_MODULE_PROXY STREQUAL "OFF")
      # 真实 Mesh 尚未进入产品；此测试用窄 L3 provider 模拟未来 consumer。
      add_test(NAME mesh-provider-fixture-contract COMMAND ftun-tun-owner-test)
    endif()
    # raw-L3 仅为共享 TUN 生产接口的测试消费者，不进入能力清单。
    if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
      add_executable(ftun-tun-shared-test tests/tun_shared.c)
      target_include_directories(ftun-tun-shared-test PRIVATE src)
      target_link_libraries(ftun-tun-shared-test PRIVATE ftun_runtime ftun_options)
      if(FTUN_STATIC)
        target_link_options(ftun-tun-shared-test PRIVATE -static)
      endif()
      add_test(NAME tun-shared-consumers-contract COMMAND ftun-tun-shared-test)
    endif()
    add_executable(ftun-tun-path-test tests/tun_path.c)
    target_include_directories(ftun-tun-path-test PRIVATE src)
    target_link_libraries(ftun-tun-path-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-tun-path-test PRIVATE -static)
    endif()
    add_test(NAME tun-path-contract COMMAND ftun-tun-path-test)
    if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
      add_executable(ftun-lwip-adapter-test tests/lwip_adapter.c)
      target_include_directories(ftun-lwip-adapter-test PRIVATE src)
      target_link_libraries(ftun-lwip-adapter-test PRIVATE ftun_runtime ftun_options)
      if(FTUN_STATIC)
        target_link_options(ftun-lwip-adapter-test PRIVATE -static)
      endif()
      add_test(NAME tun-lwip-adapter COMMAND ftun-lwip-adapter-test)
      add_executable(ftun-inbound-tun-test tests/inbound_tun.c)
      target_include_directories(ftun-inbound-tun-test PRIVATE src)
      target_link_libraries(ftun-inbound-tun-test PRIVATE ftun_runtime ftun_options)
      if(FTUN_STATIC)
        target_link_options(ftun-inbound-tun-test PRIVATE -static)
      endif()
      add_test(NAME inbound-tun-contract COMMAND ftun-inbound-tun-test)
      add_executable(ftun-udp-session-test tests/udp_session.c)
      target_include_directories(ftun-udp-session-test PRIVATE src)
      target_link_libraries(ftun-udp-session-test PRIVATE ftun_runtime ftun_options)
      if(FTUN_STATIC)
        target_link_options(ftun-udp-session-test PRIVATE -static)
      endif()
      add_test(NAME tun-udp-flow-contract COMMAND ftun-udp-session-test)
    endif()
    if(UNIX AND FTUN_MODULE_PROXY STREQUAL "BUILTIN")
      add_executable(ftun-linux-integration-test tests/integration_linux.c)
      target_include_directories(ftun-linux-integration-test PRIVATE src)
      target_link_libraries(ftun-linux-integration-test PRIVATE
        ftun_runtime ftun_options Threads::Threads)
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
        add_executable(ftun-send-eagain-test
          src/app/main.c tests/send_eagain_wrap.c)
        target_include_directories(ftun-send-eagain-test PRIVATE src)
        target_compile_definitions(ftun-send-eagain-test PRIVATE
          ${ftun_module_definitions}
          FTUN_SOURCE_REVISION="${ftun_source_revision}")
        target_link_libraries(ftun-send-eagain-test PRIVATE
          ftun_runtime ftun_options)
        target_link_options(ftun-send-eagain-test PRIVATE -Wl,--wrap=send)
        if(FTUN_STATIC)
          target_link_options(ftun-send-eagain-test PRIVATE -static)
        endif()
        add_test(NAME release-linux-udp-eagain
          COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/release_linux.sh
                     $<TARGET_FILE:ftun-send-eagain-test>
                     $<TARGET_FILE:ftun-linux-integration-test>
                     $<TARGET_FILE:ftun-v04-frs-test>)
        set_tests_properties(release-linux-udp-eagain PROPERTIES
          SKIP_RETURN_CODE 77 RESOURCE_LOCK ftun_linux_namespace
          ENVIRONMENT "FTUN_TEST_SEND_EAGAIN_PORT=18081;FTUN_TEST_FAKEIP_BOUNDARY_COUNT=4200;FTUN_TEST_UDP_CONTROL_CLOSE=1;FTUN_RELEASE_RESOURCE_LIMIT_KIB=196608")
      endif()
      add_test(NAME socket-inbounds-production
        COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/socket_inbounds.sh
                   $<TARGET_FILE:ftun>
                   $<TARGET_FILE:ftun-linux-integration-test>)
      set_tests_properties(socket-inbounds-production PROPERTIES
        TIMEOUT 20 RESOURCE_LOCK ftun_host_socket)
      add_test(NAME dns-concurrency-production
        COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/dns_concurrency.sh
                   $<TARGET_FILE:ftun>
                   $<TARGET_FILE:ftun-linux-integration-test>)
      set_tests_properties(dns-concurrency-production PROPERTIES
        TIMEOUT 15 RESOURCE_LOCK ftun_host_socket)
      add_test(NAME dns-tcp-concurrency-production
        COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/dns_tcp_concurrency.sh
                   $<TARGET_FILE:ftun>
                   $<TARGET_FILE:ftun-linux-integration-test>)
      set_tests_properties(dns-tcp-concurrency-production PROPERTIES
        TIMEOUT 15 RESOURCE_LOCK ftun_host_socket)
      add_test(NAME dns-fairness-production
        COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/dns_fairness.sh
                   $<TARGET_FILE:ftun>
                   $<TARGET_FILE:ftun-linux-integration-test>)
      set_tests_properties(dns-fairness-production PROPERTIES
        TIMEOUT 15 RESOURCE_LOCK ftun_host_socket)
      add_test(NAME reload-async-production
        COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/reload_async.sh
                   $<TARGET_FILE:ftun>
                   $<TARGET_FILE:ftun-linux-integration-test>)
      set_tests_properties(reload-async-production PROPERTIES
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
    target_link_libraries(ftun-time-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-time-test PRIVATE -static)
    endif()
    add_test(NAME monotonic-time COMMAND ftun-time-test)
  endif()
  if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
    add_executable(ftun-performance-test tests/performance.c)
    target_include_directories(ftun-performance-test PRIVATE src)
    target_link_libraries(ftun-performance-test PRIVATE
      ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-performance-test PRIVATE -static)
    endif()
    if(CMAKE_BUILD_TYPE MATCHES "^(Release|MinSizeRel)$")
      add_test(NAME performance-baseline COMMAND ftun-performance-test)
    endif()
  endif()
  set(ftun_cli_capabilities "core")
  if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
    string(APPEND ftun_cli_capabilities ",proxy")
  endif()
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
  if(UNIX AND FTUN_MODULE_PROXY STREQUAL "BUILTIN")
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
    set_tests_properties(cli-v05-contract PROPERTIES
      TIMEOUT 10 RESOURCE_LOCK ftun_host_socket)
  endif()
  find_package(Python3 QUIET COMPONENTS Interpreter)
  if(Python3_Interpreter_FOUND)
    if(TARGET ftun-control-dns-test)
      add_test(NAME control-dns-production COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/control_dns_production.py $<TARGET_FILE:ftun-control-dns-test>)
      set_tests_properties(control-dns-production PROPERTIES TIMEOUT 30 RESOURCE_LOCK ftun_host_socket)
    endif()
    if(TARGET ftun-control-datagram-test)
      add_test(NAME control-datagram-socket COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/control_datagram_socket.py $<TARGET_FILE:ftun-control-datagram-test>)
      set_tests_properties(control-datagram-socket PROPERTIES TIMEOUT 15 RESOURCE_LOCK ftun_host_socket)
    endif()
    if(TARGET ftun-control-memory-test)
      add_test(NAME control-memory-production COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/control_memory_production.py $<TARGET_FILE:ftun-control-memory-test>)
      set_tests_properties(control-memory-production PROPERTIES TIMEOUT 30 RESOURCE_LOCK ftun_host_socket)
    endif()
    if(TARGET ftun-http-fetch-test)
      add_test(NAME http-fetch-production COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/http_fetch_production.py $<TARGET_FILE:ftun-http-fetch-test>)
      set_tests_properties(http-fetch-production PROPERTIES TIMEOUT 45 RESOURCE_LOCK ftun_host_socket)
    endif()
    if(TARGET ftun-resolver-production-test)
      add_test(NAME resolver-production
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/resolver_production.py
          $<TARGET_FILE:ftun-resolver-production-test>)
      set_tests_properties(resolver-production PROPERTIES TIMEOUT 45 RESOURCE_LOCK ftun_host_socket)
    endif()
    if(TARGET ftun-dns-memory-path-test)
      add_test(NAME dns-memory-path-production
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/dns_memory_path.py
          $<TARGET_FILE:ftun-dns-memory-path-test>)
      set_tests_properties(dns-memory-path-production PROPERTIES TIMEOUT 30 RESOURCE_LOCK ftun_host_socket)
      if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
        add_test(NAME dns-memory-socks-path-production
          COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/dns_memory_path.py
            $<TARGET_FILE:ftun-dns-memory-path-test> --proxy)
        set_tests_properties(dns-memory-socks-path-production PROPERTIES TIMEOUT 30 RESOURCE_LOCK ftun_host_socket)
      endif()
    endif()
    if(FTUN_MODULE_PROXY STREQUAL "BUILTIN" AND UNIX)
      if(TARGET ftun-memory-path-test)
        add_test(NAME runtime-memory-path-production
          COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/runtime_memory_path.py
            $<TARGET_FILE:ftun-memory-path-test>)
        set_tests_properties(runtime-memory-path-production PROPERTIES
          TIMEOUT 30 RESOURCE_LOCK ftun_host_socket)
        foreach(ftun_socks_mode noauth auth)
          add_test(NAME runtime-memory-socks-${ftun_socks_mode}-production
            COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/tests/runtime_memory_path.py
              $<TARGET_FILE:ftun-memory-path-test> --socks5 ${ftun_socks_mode})
          set_tests_properties(runtime-memory-socks-${ftun_socks_mode}-production PROPERTIES
            TIMEOUT 30 RESOURCE_LOCK ftun_host_socket)
        endforeach()
        add_test(NAME runtime-memory-datagram-production
          COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/runtime_memory_datagram.py
            $<TARGET_FILE:ftun-memory-path-test>)
        add_test(NAME runtime-memory-socks-datagram-production
          COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/runtime_memory_datagram.py
            $<TARGET_FILE:ftun-memory-path-test> --socks5)
        set_tests_properties(runtime-memory-datagram-production runtime-memory-socks-datagram-production PROPERTIES
          TIMEOUT 30 RESOURCE_LOCK ftun_host_socket)
      endif()
      add_test(NAME inbound-adapter-production
        COMMAND ${Python3_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/inbound_adapter_product.py
          $<TARGET_FILE:ftun>)
      set_tests_properties(inbound-adapter-production PROPERTIES
        TIMEOUT 30 RESOURCE_LOCK ftun_host_socket)
    endif()
    if(FTUN_MODULE_DNS STREQUAL "BUILTIN")
      set(ftun_cli_result_proxy_argument)
      if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
        set(ftun_cli_result_proxy_argument --proxy)
      endif()
      add_test(NAME cli-results-product
        COMMAND ${Python3_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_results_product.py
          $<TARGET_FILE:ftun> ${ftun_cli_result_proxy_argument})
      set_tests_properties(cli-results-product PROPERTIES
        TIMEOUT 45 RESOURCE_LOCK ftun_host_socket)
      add_test(NAME lifecycle-events-product
        COMMAND ${Python3_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/lifecycle_events.py
          --ftun $<TARGET_FILE:ftun> ${ftun_cli_result_proxy_argument})
      set_tests_properties(lifecycle-events-product PROPERTIES
        TIMEOUT 60 RESOURCE_LOCK ftun_host_socket)
    endif()
    add_test(NAME core-proxy-boundary
      COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/core_proxy_boundary.py
        ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME build-target-boundaries
      COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/build_target_boundaries.py
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json
        ${CMAKE_CURRENT_BINARY_DIR}/ftun-build-targets.txt)
    add_test(NAME structure-boundaries
      COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/structure_boundaries.py
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json
        ${CMAKE_CURRENT_BINARY_DIR}/ftun-build-targets.txt
        ${ftun_layer_policy})
    add_test(NAME structure-boundaries-illegal-include
      COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/structure_boundaries.py
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json
        ${CMAKE_CURRENT_BINARY_DIR}/ftun-build-targets.txt
        ${ftun_layer_policy} --self-test illegal-include)
    add_test(NAME structure-boundaries-illegal-source
      COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/structure_boundaries.py
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json
        ${CMAKE_CURRENT_BINARY_DIR}/ftun-build-targets.txt
        ${ftun_layer_policy} --self-test illegal-source)
    add_test(NAME dependency-lock
      COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/dependency_lock.py
        ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME cross-build-contract
      COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/cross_build_contract.py
        ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_COMMAND})
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
      if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
        add_test(NAME proxy-reload-established-flows
          COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/core_qualification.py reload
            $<TARGET_FILE:ftun>)
        add_test(NAME proxy-reload-minimum-flows
          COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/core_qualification.py reload-minimum
            $<TARGET_FILE:ftun>)
        set_tests_properties(proxy-reload-minimum-flows PROPERTIES
          RESOURCE_LOCK "ftun_capacity;ftun_host_socket"
          SKIP_RETURN_CODE 77 TIMEOUT 60)
        set_tests_properties(proxy-reload-established-flows PROPERTIES
          RESOURCE_LOCK "ftun_host_socket;ftun_capacity"
          SKIP_RETURN_CODE 77 TIMEOUT 60)
      endif()
      if(CMAKE_BUILD_TYPE MATCHES "^(Release|MinSizeRel)$" AND
         FTUN_MODULE_PROXY STREQUAL "BUILTIN")
        add_test(NAME core-capacity-production
          COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/core_capacity.py
            $<TARGET_FILE:ftun>)
        set_tests_properties(core-capacity-production PROPERTIES
          RESOURCE_LOCK "ftun_host_socket;ftun_capacity"
          SKIP_RETURN_CODE 77 TIMEOUT 240)
        add_test(NAME core-qualification-formal
          COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/core_qualification.py formal
            $<TARGET_FILE:ftun>)
        set_tests_properties(core-qualification-formal PROPERTIES
          RESOURCE_LOCK "ftun_host_socket;ftun_capacity"
          SKIP_RETURN_CODE 77 TIMEOUT 300)
        if(UNIX AND FTUN_MODULE_TUN STREQUAL "BUILTIN")
          add_test(NAME core-capacity-matrix-production
            COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/tests/core_capacity_matrix.py
              $<TARGET_FILE:ftun>)
          set_tests_properties(core-capacity-matrix-production PROPERTIES
            RESOURCE_LOCK "ftun_linux_namespace;ftun_capacity"
            SKIP_RETURN_CODE 77 TIMEOUT 420)
        endif()
        add_test(NAME release-resource-profile
          COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/resource_profile.py
            $<TARGET_FILE:ftun> ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/cli-run.json.in)
        set_tests_properties(release-resource-profile PROPERTIES
          RESOURCE_LOCK ftun_host_socket)
        add_test(NAME core-baseline-profile
          COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/core_baseline.py
            $<TARGET_FILE:ftun>)
        set_tests_properties(core-baseline-profile PROPERTIES
          ENVIRONMENT "FTUN_BASELINE_RUNS=1;FTUN_BASELINE_ACTIVE_SECONDS=1;FTUN_BASELINE_TOTAL_TIMEOUT_SECONDS=120"
          RESOURCE_LOCK ftun_host_socket TIMEOUT 180)
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
      -DFTUN_MATRIX_PYTHON=${Python3_EXECUTABLE}
      -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/build_modules.cmake)
  # 工程检查不能因运行环境或工具故障无限阻塞。
  get_property(ftun_tests DIRECTORY PROPERTY TESTS)
  set_tests_properties(${ftun_tests} PROPERTIES TIMEOUT 30)
  set_tests_properties(build-modules-matrix PROPERTIES TIMEOUT 180)
  if(TEST release-linux-production)
    set_tests_properties(release-linux-production PROPERTIES TIMEOUT 90)
  endif()
  if(TEST release-linux-udp-eagain)
    set_tests_properties(release-linux-udp-eagain PROPERTIES TIMEOUT 120)
  endif()
  if(TEST idle-tcp-resource-profile)
    set_tests_properties(idle-tcp-resource-profile PROPERTIES TIMEOUT 75)
  endif()
  if(TEST core-baseline-profile)
    set_tests_properties(core-baseline-profile PROPERTIES TIMEOUT 180)
  endif()
endif()
