# 第三方源码在仓库内锁定，配置过程不联网。
set(ftun_internal_dependencies)
add_library(ftun_cjson STATIC third_party/cjson/cJSON.c)
target_include_directories(ftun_cjson PUBLIC
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/third_party/cjson>")
target_compile_definitions(ftun_cjson PRIVATE CJSON_NESTING_LIMIT=32)
if(FTUN_HARDENING)
  target_compile_options(ftun_cjson PRIVATE ${ftun_hardening_codegen_options})
  target_compile_definitions(ftun_cjson PRIVATE
    ${ftun_hardening_compile_definitions})
endif()
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(ftun_cjson PRIVATE -Wall -Wextra -fno-strict-aliasing
    "$<$<CONFIG:Debug>:-O0;-g>" "$<$<NOT:$<CONFIG:Debug>>:${ftun_opt}>")
  if(FTUN_SECTION_GC)
    target_compile_options(ftun_cjson PRIVATE -ffunction-sections -fdata-sections)
  endif()
  if(FTUN_SANITIZERS OR FTUN_TSAN)
    target_compile_options(ftun_cjson PRIVATE
      -fsanitize=${FTUN_SANITIZE_KINDS} -fno-omit-frame-pointer)
  endif()
endif()
target_compile_options(ftun_cjson PRIVATE ${FTUN_EXTRA_COMPILE_OPTIONS})
list(APPEND ftun_internal_dependencies ftun_cjson)
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
set(WOLFSSL_IP_ALT_NAME yes CACHE STRING "Verify numeric IPv4/IPv6 certificate identities" FORCE)
set(WOLFSSL_OPENSSLEXTRA no CACHE STRING "Disable unused OpenSSL compatibility layer" FORCE)
set(WOLFSSL_SNI yes CACHE STRING "Enable required TLS server name indication" FORCE)
set(WOLFSSL_TLS13 yes CACHE STRING "Enable wolfSSL TLS 1.3" FORCE)
set(WOLFSSL_DTLS no CACHE STRING "Disable unused wolfSSL DTLS" FORCE)
set(WOLFSSL_OLD_TLS no CACHE STRING "Disable obsolete TLS versions" FORCE)
# TLS上下文只接受配置的CA文件/内存证书，不使用上游系统证书仓库。
set(WOLFSSL_SYS_CA_CERTS no CACHE STRING "Disable unused system trust store loader" FORCE)
add_subdirectory(third_party/wolfssl EXCLUDE_FROM_ALL)
# IP SAN校验回调也必须在证书链验证成功时执行。
target_compile_definitions(wolfssl PUBLIC WOLFSSL_ALWAYS_VERIFY_CB)
if(CMAKE_C_BYTE_ORDER STREQUAL "BIG_ENDIAN")
  # 上游CMake未把端序检测写入config/options头；库与调用方必须一致。
  target_compile_definitions(wolfssl PUBLIC BIG_ENDIAN_ORDER)
endif()
if(FTUN_HARDENING)
  target_compile_options(wolfssl PRIVATE ${ftun_hardening_codegen_options})
  target_compile_definitions(wolfssl PRIVATE
    ${ftun_hardening_compile_definitions})
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_compile_definitions(wolfssl PRIVATE _POSIX_C_SOURCE=200809L)
endif()
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  if(FTUN_SECTION_GC)
    target_compile_options(wolfssl PRIVATE
      -ffunction-sections -fdata-sections)
  endif()
  if(FTUN_SANITIZERS OR FTUN_TSAN)
    target_compile_options(wolfssl PRIVATE
      -fsanitize=${FTUN_SANITIZE_KINDS} -fno-omit-frame-pointer)
    if(FTUN_TSAN)
      # GCC 的 TSan 不支持 atomic_thread_fence，wolfSSL 的内存屏障会触发 -Wtsan；
      # 这是第三方库，TSan 对它的屏障不建模，不把该告警当作错误。
      target_compile_options(wolfssl PRIVATE -Wno-tsan)
    endif()
  endif()
endif()
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND
   CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 13)
  # 常量时间 HMAC 的 macLen 来自已选摘要算法；GCC 13/14 的向量化
  # 对 innerHash 报对象大小误告警。仅此上游源文件不将该告警升级为错误。
  set_property(SOURCE "${PROJECT_SOURCE_DIR}/third_party/wolfssl/src/tls.c"
    DIRECTORY third_party/wolfssl APPEND
    PROPERTY COMPILE_OPTIONS -Wno-error=stringop-overflow)
endif()
target_compile_options(wolfssl PRIVATE ${FTUN_EXTRA_COMPILE_OPTIONS})
list(APPEND ftun_internal_dependencies wolfssl::wolfssl)

if(FTUN_MODULE_PROXY STREQUAL "BUILTIN" AND FTUN_MODULE_TUN STREQUAL "BUILTIN")
    add_library(ftun_lwip STATIC
    ${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/def.c
    ${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/inet_chksum.c
    ${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/init.c
    ${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/ip.c
    ${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/mem.c
    ${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/memp.c
    ${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/netif.c
    ${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/pbuf.c
    ${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/stats.c
    ${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/sys.c
    ${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/tcp.c
    ${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/tcp_in.c
    ${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/tcp_out.c
    ${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/timeouts.c
    ${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/udp.c
    ${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/ipv4/ip4.c
    ${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/ipv4/ip4_addr.c
    ${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/ipv4/ip4_frag.c
    ${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/ipv6/ip6.c
    ${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/ipv6/ip6_addr.c
    ${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/ipv6/ip6_frag.c
    ${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/ipv6/icmp6.c
    ${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/ipv6/nd6.c)
    target_include_directories(ftun_lwip PUBLIC
      "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/third_party/lwip/src/include>"
      "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/proxy/netstack>")
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
      target_compile_options(ftun_lwip PRIVATE -Wall -Wextra -fno-strict-aliasing
        "$<$<CONFIG:Debug>:-O0;-g>" "$<$<NOT:$<CONFIG:Debug>>:${ftun_opt}>")
      # 禁用自动配置和路由发现后，上游两份 IPv6 源保留未使用的形参/变量。
      set_property(SOURCE
        "${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/ipv6/ip6.c"
        "${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/ipv6/nd6.c"
        APPEND PROPERTY COMPILE_OPTIONS -Wno-unused-parameter)
      set_property(SOURCE "${PROJECT_SOURCE_DIR}/third_party/lwip/src/core/ipv6/nd6.c"
        APPEND PROPERTY COMPILE_OPTIONS -Wno-unused-variable)
      if(FTUN_SECTION_GC)
        target_compile_options(ftun_lwip PRIVATE -ffunction-sections -fdata-sections)
      endif()
      if(FTUN_SANITIZERS OR FTUN_TSAN)
        target_compile_options(ftun_lwip PRIVATE
          -fsanitize=${FTUN_SANITIZE_KINDS} -fno-omit-frame-pointer)
      endif()
    endif()
    target_compile_options(ftun_lwip PRIVATE ${FTUN_EXTRA_COMPILE_OPTIONS})
    if(FTUN_HARDENING)
      target_compile_options(ftun_lwip PRIVATE
        ${ftun_hardening_codegen_options})
      target_compile_definitions(ftun_lwip PRIVATE
        ${ftun_hardening_compile_definitions})
    endif()
endif()
