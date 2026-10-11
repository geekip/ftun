if(NOT DEFINED FTUN_SOURCE_DIR OR NOT DEFINED FTUN_MATRIX_DIR OR
   NOT DEFINED FTUN_MATRIX_GENERATOR OR NOT DEFINED FTUN_MATRIX_COMPILER)
  message(FATAL_ERROR "module matrix arguments are required")
endif()

function(ftun_configure result output build_dir)
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -S "${FTUN_SOURCE_DIR}" -B "${build_dir}"
      -G "${FTUN_MATRIX_GENERATOR}"
      -DCMAKE_C_COMPILER=${FTUN_MATRIX_COMPILER}
      -DCMAKE_BUILD_TYPE=Debug
      -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
      -DBUILD_TESTING=ON
      ${ARGN}
    RESULT_VARIABLE command_result
    OUTPUT_VARIABLE command_output
    ERROR_VARIABLE command_error)
  set(${result} "${command_result}" PARENT_SCOPE)
  set(${output} "${command_output}\n${command_error}" PARENT_SCOPE)
endfunction()

file(REMOVE_RECURSE "${FTUN_MATRIX_DIR}")

set(core_dir "${FTUN_MATRIX_DIR}/core")
ftun_configure(result output "${core_dir}"
  -DFTUN_MODULE_DNS=OFF -DFTUN_MODULE_TUN=OFF -DFTUN_MODULE_FRS=OFF)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "core-only configure failed:\n${output}")
endif()
execute_process(COMMAND "${CMAKE_COMMAND}" --build "${core_dir}" --target ftun-build-modules-test
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "core-only build failed:\n${output}\n${error}")
endif()
execute_process(COMMAND "${core_dir}/ftun-build-modules-test"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "core-only capability check failed:\n${output}\n${error}")
endif()
file(READ "${core_dir}/compile_commands.json" core_commands)
foreach(source
    src/dns/dns.c src/dns/server.c src/dns/listener.c src/dns/bootstrap.c
    src/dns/cache.c src/dns/wire.c src/inbound/tun.c src/tun/tun.c
    src/tun/lwip_adapter.c src/tun/udp_session.c src/platform/linux/tun.c
    src/platform/linux/route.c src/frs/format.c src/frs/frs.c src/frs/ip.c
    src/frs/domain.c src/frs/update.c)
  string(FIND "${core_commands}" "${FTUN_SOURCE_DIR}/${source}" found)
  if(NOT found EQUAL -1)
    message(FATAL_ERROR "OFF module source entered core-only build: ${source}")
  endif()
endforeach()
string(FIND "${core_commands}" "${FTUN_SOURCE_DIR}/third_party/lwip/src/core/init.c"
  lwip_found)
if(NOT lwip_found EQUAL -1)
  message(FATAL_ERROR "TUN-only lwIP entered core-only build")
endif()
foreach(source src/dns/resolver.c src/platform/system_resolver.c
               src/transport/datagram.c src/protocol/socks5.c)
  string(FIND "${core_commands}" "${FTUN_SOURCE_DIR}/${source}" found)
  if(found EQUAL -1)
    message(FATAL_ERROR "required core source is missing: ${source}")
  endif()
endforeach()
file(READ "${core_dir}/ftun-build-modules.txt" manifest)
if(NOT manifest STREQUAL "core=BUILTIN\ndns=OFF\ntun=OFF\nfrs=OFF\n")
  message(FATAL_ERROR "unexpected core-only manifest:\n${manifest}")
endif()

set(builtin_dir "${FTUN_MATRIX_DIR}/builtin")
ftun_configure(result output "${builtin_dir}"
  -DFTUN_MODULE_DNS=BUILTIN -DFTUN_MODULE_TUN=BUILTIN
  -DFTUN_MODULE_FRS=BUILTIN)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "builtin configure failed:\n${output}")
endif()
execute_process(COMMAND "${CMAKE_COMMAND}" --build "${builtin_dir}" --target ftun-build-modules-test
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "builtin build failed:\n${output}\n${error}")
endif()
execute_process(COMMAND "${builtin_dir}/ftun-build-modules-test"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "builtin capability check failed:\n${output}\n${error}")
endif()
file(READ "${builtin_dir}/compile_commands.json" builtin_commands)
foreach(source src/dns/dns.c src/dns/wire.c src/inbound/tun.c src/tun/lwip_adapter.c
               src/frs/format.c src/frs/frs.c src/frs/ip.c src/frs/domain.c
               src/frs/update.c)
  string(FIND "${builtin_commands}" "${FTUN_SOURCE_DIR}/${source}" found)
  if(found EQUAL -1)
    message(FATAL_ERROR "BUILTIN module source is missing: ${source}")
  endif()
endforeach()
string(FIND "${builtin_commands}" "${FTUN_SOURCE_DIR}/third_party/lwip/src/core/init.c"
  lwip_found)
if(lwip_found EQUAL -1)
  message(FATAL_ERROR "BUILTIN TUN dependency lwIP is missing")
endif()
file(READ "${builtin_dir}/ftun-build-modules.txt" manifest)
if(NOT manifest STREQUAL
   "core=BUILTIN\ndns=BUILTIN\ntun=BUILTIN\nfrs=BUILTIN\n")
  message(FATAL_ERROR "unexpected builtin manifest:\n${manifest}")
endif()

set(dynamic_dir "${FTUN_MATRIX_DIR}/dynamic")
ftun_configure(result output "${dynamic_dir}"
  -DFTUN_MODULE_DNS=MODULE -DFTUN_MODULE_TUN=OFF -DFTUN_MODULE_FRS=OFF)
if(result EQUAL 0 OR NOT output MATCHES "must be OFF or BUILTIN")
  message(FATAL_ERROR "dynamic module mode was not explicitly rejected:\n${output}")
endif()

set(platform_dir "${FTUN_MATRIX_DIR}/unsupported-platform")
execute_process(
  COMMAND "${CMAKE_COMMAND}" -S "${FTUN_SOURCE_DIR}" -B "${platform_dir}"
    -G "${FTUN_MATRIX_GENERATOR}"
    -DCMAKE_C_COMPILER=${FTUN_MATRIX_COMPILER}
    -DCMAKE_SYSTEM_NAME=Generic
    -DFTUN_SECTION_GC=OFF
    -DBUILD_TESTING=OFF
    -DFTUN_MODULE_DNS=OFF
    -DFTUN_MODULE_TUN=BUILTIN
    -DFTUN_MODULE_FRS=OFF
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(result EQUAL 0 OR NOT "${output}\n${error}" MATCHES "requires a Linux target")
  message(FATAL_ERROR "unsupported TUN target was not explicitly rejected:\n${output}\n${error}")
endif()

set(frs_platform_dir "${FTUN_MATRIX_DIR}/unsupported-frs-platform")
execute_process(
  COMMAND "${CMAKE_COMMAND}" -S "${FTUN_SOURCE_DIR}" -B "${frs_platform_dir}"
    -G "${FTUN_MATRIX_GENERATOR}"
    -DCMAKE_C_COMPILER=${FTUN_MATRIX_COMPILER}
    -DCMAKE_SYSTEM_NAME=Generic
    -DFTUN_SECTION_GC=OFF
    -DBUILD_TESTING=OFF
    -DFTUN_MODULE_DNS=OFF
    -DFTUN_MODULE_TUN=OFF
    -DFTUN_MODULE_FRS=BUILTIN
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(result EQUAL 0 OR NOT "${output}\n${error}" MATCHES "requires a Linux target")
  message(FATAL_ERROR "unsupported FRS target was not explicitly rejected:\n${output}\n${error}")
endif()
