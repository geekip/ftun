if(NOT DEFINED FTUN_SOURCE_DIR OR NOT DEFINED FTUN_MATRIX_DIR OR
   NOT DEFINED FTUN_MATRIX_GENERATOR OR NOT DEFINED FTUN_MATRIX_COMPILER OR
   NOT DEFINED FTUN_MATRIX_PYTHON)
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
  if(command_result EQUAL 0)
    execute_process(
      COMMAND "${FTUN_MATRIX_PYTHON}"
        "${FTUN_SOURCE_DIR}/tests/structure_boundaries.py"
        "${FTUN_SOURCE_DIR}"
        "${build_dir}/compile_commands.json"
        "${build_dir}/ftun-build-targets.txt"
        "${FTUN_SOURCE_DIR}/cmake/ftun-layer-policy.json"
      RESULT_VARIABLE boundary_result
      OUTPUT_VARIABLE boundary_output
      ERROR_VARIABLE boundary_error)
    if(NOT boundary_result EQUAL 0)
      set(command_result "${boundary_result}")
      string(APPEND command_output
        "\nstructure boundary failed:\n${boundary_output}\n${boundary_error}")
    else()
      execute_process(
        COMMAND "${FTUN_MATRIX_PYTHON}"
          "${FTUN_SOURCE_DIR}/tests/build_target_boundaries.py"
          "${FTUN_SOURCE_DIR}"
          "${build_dir}/compile_commands.json"
          "${build_dir}/ftun-build-targets.txt"
        RESULT_VARIABLE target_boundary_result
        OUTPUT_VARIABLE target_boundary_output
        ERROR_VARIABLE target_boundary_error)
      if(NOT target_boundary_result EQUAL 0)
        set(command_result "${target_boundary_result}")
        string(APPEND command_output
          "\ntarget boundary failed:\n${target_boundary_output}\n${target_boundary_error}")
      endif()
    endif()
  endif()
  set(${result} "${command_result}" PARENT_SCOPE)
  set(${output} "${command_output}\n${command_error}" PARENT_SCOPE)
endfunction()

file(REMOVE_RECURSE "${FTUN_MATRIX_DIR}")

set(core_layer_dir "${FTUN_MATRIX_DIR}/core-layer")
ftun_configure(result output "${core_layer_dir}"
  -DFTUN_MODULE_PROXY=OFF
  -DFTUN_MODULE_DNS=OFF -DFTUN_MODULE_FAKEIP=OFF
  -DFTUN_MODULE_TUN=OFF -DFTUN_MODULE_FRS=OFF)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "core layer configure failed:\n${output}")
endif()
execute_process(COMMAND "${CMAKE_COMMAND}" --build "${core_layer_dir}"
  --target ftun ftun-build-modules-test
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "core layer build failed:\n${output}\n${error}")
endif()
execute_process(COMMAND "${core_layer_dir}/ftun-build-modules-test"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "Core-only capability check failed:\n${output}\n${error}")
endif()
file(WRITE "${core_layer_dir}/core-only.json"
  "{\"dns\":{\"enable\":false}}\n")
execute_process(COMMAND "${core_layer_dir}/ftun" check
    "${core_layer_dir}/core-only.json"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "Core-only product check failed:\n${output}\n${error}")
endif()
file(GLOB_RECURSE core_objects
  "${core_layer_dir}/CMakeFiles/ftun_core.dir/*.o")
list(LENGTH core_objects core_object_count)
if(NOT core_object_count EQUAL 7)
  message(FATAL_ERROR
    "core layer should contain exactly 7 objects, found ${core_object_count}")
endif()
file(GLOB_RECURSE forbidden_core_objects
  "${core_layer_dir}/CMakeFiles/ftun_proxy.dir/*.o"
  "${core_layer_dir}/CMakeFiles/ftun_tun.dir/*.o"
  "${core_layer_dir}/CMakeFiles/ftun_lwip.dir/*.o")
if(forbidden_core_objects)
  message(FATAL_ERROR "core layer build pulled Proxy/TUN/lwIP objects")
endif()
file(READ "${core_layer_dir}/ftun-build-modules.txt" manifest)
if(NOT manifest STREQUAL
   "core=BUILTIN\nproxy=OFF\ndns=OFF\nfakeip=OFF\ntun=OFF\nfrs=OFF\nmesh=OFF\n")
  message(FATAL_ERROR "unexpected Core-only manifest:\n${manifest}")
endif()
file(READ "${core_layer_dir}/ftun-build-targets.txt" targets)
if(NOT targets MATCHES "proxy=OFF" OR NOT targets MATCHES "dns=OFF" OR
   NOT targets MATCHES "tun=OFF" OR NOT targets MATCHES "lwip=OFF" OR
   NOT targets MATCHES "mesh=OFF")
  message(FATAL_ERROR "unexpected Core-only target map:\n${targets}")
endif()

set(dns_only_dir "${FTUN_MATRIX_DIR}/dns-only")
ftun_configure(result output "${dns_only_dir}"
  -DFTUN_MODULE_PROXY=OFF
  -DFTUN_MODULE_DNS=BUILTIN -DFTUN_MODULE_FAKEIP=OFF
  -DFTUN_MODULE_TUN=OFF -DFTUN_MODULE_FRS=OFF)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "DNS-only configure failed:\n${output}")
endif()
execute_process(COMMAND "${CMAKE_COMMAND}" --build "${dns_only_dir}"
  --target ftun ftun-build-modules-test ftun-dns-service-test
    ftun-service-runtime-test
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "DNS-only build failed:\n${output}\n${error}")
endif()
execute_process(COMMAND "${dns_only_dir}/ftun-build-modules-test"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "DNS-only capability check failed:\n${output}\n${error}")
endif()
execute_process(COMMAND "${dns_only_dir}/ftun-dns-service-test"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "DNS-only service contract failed:\n${output}\n${error}")
endif()
execute_process(COMMAND "${dns_only_dir}/ftun-service-runtime-test"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR
    "DNS-only service runtime stop contract failed:\n${output}\n${error}")
endif()
execute_process(COMMAND "${FTUN_MATRIX_PYTHON}"
    "${FTUN_SOURCE_DIR}/tests/dns_only_product.py" "${dns_only_dir}/ftun"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "DNS-only product run failed:\n${output}\n${error}")
endif()
file(READ "${dns_only_dir}/compile_commands.json" dns_only_commands)
foreach(source src/proxy/runtime.c src/proxy/service.c src/app/composition/proxy_runtime.c)
  string(FIND "${dns_only_commands}" "${FTUN_SOURCE_DIR}/${source}" found)
  if(NOT found EQUAL -1)
    message(FATAL_ERROR "DNS-only composition retained Proxy source: ${source}")
  endif()
endforeach()
string(FIND "${dns_only_commands}"
  "${FTUN_SOURCE_DIR}/src/app/runtime.c" service_runtime_found)
if(service_runtime_found EQUAL -1)
  message(FATAL_ERROR "DNS-only composition lost the generic service runtime")
endif()
file(READ "${dns_only_dir}/ftun-build-modules.txt" manifest)
if(NOT manifest STREQUAL
   "core=BUILTIN\nproxy=OFF\ndns=BUILTIN\nfakeip=OFF\ntun=OFF\nfrs=OFF\nmesh=OFF\n")
  message(FATAL_ERROR "unexpected DNS-only manifest:\n${manifest}")
endif()

set(mesh_fixture_dir "${FTUN_MATRIX_DIR}/mesh-provider-fixture")
ftun_configure(result output "${mesh_fixture_dir}"
  -DFTUN_MODULE_PROXY=OFF
  -DFTUN_MODULE_DNS=OFF -DFTUN_MODULE_FAKEIP=OFF
  -DFTUN_MODULE_TUN=BUILTIN -DFTUN_MODULE_FRS=OFF)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "Mesh provider fixture configure failed:\n${output}")
endif()
execute_process(COMMAND "${CMAKE_COMMAND}" --build "${mesh_fixture_dir}"
  --target ftun-build-modules-test ftun-provider-bindings-test
    ftun-tun-service-test ftun-tun-owner-test ftun-tun-path-test
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "Mesh provider fixture build failed:\n${output}\n${error}")
endif()
foreach(test ftun-build-modules-test ftun-provider-bindings-test
             ftun-tun-service-test ftun-tun-owner-test ftun-tun-path-test)
  execute_process(COMMAND "${mesh_fixture_dir}/${test}"
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
  if(NOT result EQUAL 0)
    message(FATAL_ERROR "Mesh provider fixture ${test} failed:\n${output}\n${error}")
  endif()
endforeach()
file(READ "${mesh_fixture_dir}/ftun-build-targets.txt" targets)
if(NOT targets MATCHES "proxy=OFF" OR
   NOT targets MATCHES "tun=ftun_tun" OR
   NOT targets MATCHES "lwip=OFF" OR NOT targets MATCHES "mesh=OFF")
  message(FATAL_ERROR "unexpected Mesh provider fixture target map:\n${targets}")
endif()

set(proxy_socket_dir "${FTUN_MATRIX_DIR}/proxy-socket")
ftun_configure(result output "${proxy_socket_dir}"
  -DFTUN_MODULE_PROXY=BUILTIN
  -DFTUN_MODULE_DNS=OFF -DFTUN_MODULE_FAKEIP=OFF
  -DFTUN_MODULE_TUN=OFF -DFTUN_MODULE_FRS=OFF)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "Proxy socket-only configure failed:\n${output}")
endif()
execute_process(COMMAND "${CMAKE_COMMAND}" --build "${proxy_socket_dir}"
  --target ftun ftun-build-modules-test
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "Proxy socket-only build failed:\n${output}\n${error}")
endif()
execute_process(COMMAND "${proxy_socket_dir}/ftun-build-modules-test"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR
    "Proxy socket-only capability check failed:\n${output}\n${error}")
endif()
file(READ "${proxy_socket_dir}/compile_commands.json" core_commands)
foreach(source
    src/dns/dispatcher.c src/dns/service.c src/dns/core_service.c
    src/dns/server.c src/dns/listener.c src/dns/bootstrap.c
    src/dns/cache.c src/dns/wire.c src/proxy/dns/fakeip.c tests/dns_service.c
    src/proxy/state/fakeip_store.c src/proxy/state/fakeip_snapshot.c
    src/proxy/tun/ingress.c src/proxy/tun/lwip_adapter.c
    src/tun/device.c src/tun/service.c src/tun/dispatch.c src/tun/route.c
    src/tun/path.c src/platform/linux/tun.c
    src/platform/linux/route.c src/platform/linux/route_async.c
    tests/tun_shared.c tests/tun_path.c tests/platform_linux_route_async.c
    src/proxy/frs/format.c src/proxy/frs/frs.c src/proxy/frs/ip.c
    src/proxy/frs/domain.c src/proxy/frs/update.c)
  string(FIND "${core_commands}" "${FTUN_SOURCE_DIR}/${source}" found)
  if(NOT found EQUAL -1)
    message(FATAL_ERROR "OFF module source entered Proxy socket-only build: ${source}")
  endif()
endforeach()
string(FIND "${core_commands}" "${FTUN_SOURCE_DIR}/third_party/lwip/src/core/init.c"
  lwip_found)
if(NOT lwip_found EQUAL -1)
  message(FATAL_ERROR "TUN-only lwIP entered core-only build")
endif()
foreach(source src/proxy/dns/resolver_adapter.c src/platform/system_resolver.c
               src/transport/carrier.c src/transport/datagram.c
               src/protocol/socks5.c
               src/proxy/udp/session.c)
  string(FIND "${core_commands}" "${FTUN_SOURCE_DIR}/${source}" found)
  if(found EQUAL -1)
    message(FATAL_ERROR "required core source is missing: ${source}")
  endif()
endforeach()
file(READ "${proxy_socket_dir}/ftun-build-modules.txt" manifest)
if(NOT manifest STREQUAL
   "core=BUILTIN\nproxy=BUILTIN\ndns=OFF\nfakeip=OFF\ntun=OFF\nfrs=OFF\nmesh=OFF\n")
  message(FATAL_ERROR "unexpected Proxy socket-only manifest:\n${manifest}")
endif()
file(READ "${proxy_socket_dir}/ftun-build-targets.txt" targets)
if(NOT targets MATCHES "core=ftun_core" OR
   NOT targets MATCHES "shared=ftun_shared_services" OR
   NOT targets MATCHES "proxy=ftun_proxy" OR
   NOT targets MATCHES "app=ftun_app" OR
   NOT targets MATCHES "tun=OFF" OR NOT targets MATCHES "lwip=OFF" OR
   NOT targets MATCHES "mesh=OFF")
  message(FATAL_ERROR "unexpected Proxy socket-only target map:\n${targets}")
endif()

set(builtin_dir "${FTUN_MATRIX_DIR}/builtin")
ftun_configure(result output "${builtin_dir}"
  -DFTUN_MODULE_PROXY=BUILTIN
  -DFTUN_MODULE_DNS=BUILTIN -DFTUN_MODULE_FAKEIP=BUILTIN
  -DFTUN_MODULE_TUN=BUILTIN
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
foreach(source src/dns/dispatcher.c src/dns/service.c src/dns/core_service.c
               src/dns/wire.c src/proxy/dns/fakeip.c tests/dns_service.c
               src/proxy/state/fakeip_store.c src/proxy/state/fakeip_snapshot.c
               src/proxy/tun/ingress.c src/proxy/tun/lwip_adapter.c
               src/proxy/frs/format.c src/proxy/frs/frs.c src/proxy/frs/ip.c
               src/proxy/frs/domain.c src/proxy/frs/update.c)
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
   "core=BUILTIN\nproxy=BUILTIN\ndns=BUILTIN\nfakeip=BUILTIN\ntun=BUILTIN\nfrs=BUILTIN\nmesh=OFF\n")
  message(FATAL_ERROR "unexpected builtin manifest:\n${manifest}")
endif()
file(READ "${builtin_dir}/ftun-build-targets.txt" targets)
foreach(expected
    "tun=ftun_tun" "lwip=ftun_lwip" "dns=ftun_module_dns"
    "fakeip=ftun_module_fakeip" "frs=ftun_module_frs" "mesh=OFF")
  if(NOT targets MATCHES "${expected}")
    message(FATAL_ERROR "builtin target map lost ${expected}:\n${targets}")
  endif()
endforeach()

set(proxy_tun_dir "${FTUN_MATRIX_DIR}/proxy-tun")
ftun_configure(result output "${proxy_tun_dir}"
  -DFTUN_MODULE_PROXY=BUILTIN
  -DFTUN_MODULE_DNS=OFF -DFTUN_MODULE_FAKEIP=OFF
  -DFTUN_MODULE_TUN=BUILTIN -DFTUN_MODULE_FRS=OFF)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "Proxy+TUN configure failed:\n${output}")
endif()
execute_process(COMMAND "${CMAKE_COMMAND}" --build "${proxy_tun_dir}"
  --target ftun ftun-build-modules-test
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "Proxy+TUN build failed:\n${output}\n${error}")
endif()
execute_process(COMMAND "${proxy_tun_dir}/ftun-build-modules-test"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "Proxy+TUN capability check failed:\n${output}\n${error}")
endif()
execute_process(COMMAND "${CMAKE_COMMAND}" --build "${proxy_tun_dir}"
  --target ftun-tun-shared-test ftun-tun-path-test
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR
    "test-only raw-L3 consumer build failed:\n${output}\n${error}")
endif()
execute_process(COMMAND "${proxy_tun_dir}/ftun-tun-shared-test"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR
    "test-only raw-L3 consumer contract failed:\n${output}\n${error}")
endif()
file(READ "${proxy_tun_dir}/compile_commands.json" proxy_tun_commands)
string(FIND "${proxy_tun_commands}"
  "${FTUN_SOURCE_DIR}/tests/tun_shared.c" raw_l3_found)
if(raw_l3_found EQUAL -1)
  message(FATAL_ERROR "Proxy+TUN matrix lost the test-only raw-L3 source")
endif()
string(FIND "${proxy_tun_commands}"
  "${FTUN_SOURCE_DIR}/tests/tun_path.c" tun_path_found)
if(tun_path_found EQUAL -1)
  message(FATAL_ERROR "Proxy+TUN matrix lost the path contract source")
endif()
file(READ "${proxy_tun_dir}/ftun-build-targets.txt" targets)
if(NOT targets MATCHES "tun=ftun_tun" OR
   NOT targets MATCHES "lwip=ftun_lwip" OR
   NOT targets MATCHES "dns=OFF" OR NOT targets MATCHES "fakeip=OFF" OR
   NOT targets MATCHES "frs=OFF" OR NOT targets MATCHES "mesh=OFF")
  message(FATAL_ERROR "unexpected Proxy+TUN target map:\n${targets}")
endif()

function(ftun_check_variant name dns fakeip tun frs excluded_source)
  set(build_dir "${FTUN_MATRIX_DIR}/${name}")
  ftun_configure(result output "${build_dir}"
    -DFTUN_MODULE_PROXY=BUILTIN
    -DFTUN_MODULE_DNS=${dns} -DFTUN_MODULE_FAKEIP=${fakeip}
    -DFTUN_MODULE_TUN=${tun} -DFTUN_MODULE_FRS=${frs})
  if(NOT result EQUAL 0)
    message(FATAL_ERROR "${name} configure failed:\n${output}")
  endif()
  execute_process(
    COMMAND "${CMAKE_COMMAND}" --build "${build_dir}"
      --target ftun-build-modules-test
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
  if(NOT result EQUAL 0)
    message(FATAL_ERROR "${name} build failed:\n${output}\n${error}")
  endif()
  execute_process(COMMAND "${build_dir}/ftun-build-modules-test"
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
  if(NOT result EQUAL 0)
    message(FATAL_ERROR "${name} capability check failed:\n${output}\n${error}")
  endif()
  file(READ "${build_dir}/compile_commands.json" commands)
  string(FIND "${commands}" "${FTUN_SOURCE_DIR}/${excluded_source}" found)
  if(NOT found EQUAL -1)
    message(FATAL_ERROR "${name} retained disabled source: ${excluded_source}")
  endif()
  foreach(source src/proxy/inbound/socks5.c src/protocol/socks5.c
                 src/transport/carrier.c src/transport/datagram.c
                 src/platform/system_resolver.c)
    string(FIND "${commands}" "${FTUN_SOURCE_DIR}/${source}" found)
    if(found EQUAL -1)
      message(FATAL_ERROR "${name} lost core SOCKS/SystemResolver source: ${source}")
    endif()
  endforeach()
endfunction()

# Each shipped optional capability has an independently verified legal OFF
# profile. DNS OFF also turns off its dependent FakeIP capability.
ftun_check_variant(no-tun BUILTIN BUILTIN OFF BUILTIN src/proxy/tun/ingress.c)
ftun_check_variant(no-dns OFF OFF BUILTIN BUILTIN src/dns/dispatcher.c)
ftun_check_variant(no-fakeip BUILTIN OFF BUILTIN BUILTIN src/proxy/dns/fakeip.c)
ftun_check_variant(no-frs BUILTIN BUILTIN BUILTIN OFF src/proxy/frs/frs.c)

set(fakeip_dependency_dir "${FTUN_MATRIX_DIR}/illegal-fakeip-dependency")
ftun_configure(result output "${fakeip_dependency_dir}"
  -DFTUN_MODULE_PROXY=BUILTIN
  -DFTUN_MODULE_DNS=OFF -DFTUN_MODULE_FAKEIP=BUILTIN
  -DFTUN_MODULE_TUN=OFF -DFTUN_MODULE_FRS=OFF)
if(result EQUAL 0 OR NOT output MATCHES "FTUN_MODULE_DNS=BUILTIN")
  message(FATAL_ERROR "illegal FakeIP dependency was not rejected:\n${output}")
endif()

set(fakeip_proxy_dependency_dir
  "${FTUN_MATRIX_DIR}/illegal-fakeip-proxy-dependency")
ftun_configure(result output "${fakeip_proxy_dependency_dir}"
  -DFTUN_MODULE_PROXY=OFF
  -DFTUN_MODULE_DNS=BUILTIN -DFTUN_MODULE_FAKEIP=BUILTIN
  -DFTUN_MODULE_TUN=OFF -DFTUN_MODULE_FRS=OFF)
if(result EQUAL 0 OR NOT output MATCHES "requires FTUN_MODULE_PROXY=BUILTIN")
  message(FATAL_ERROR
    "illegal FakeIP/Proxy dependency was not rejected:\n${output}")
endif()

set(frs_proxy_dependency_dir
  "${FTUN_MATRIX_DIR}/illegal-frs-proxy-dependency")
ftun_configure(result output "${frs_proxy_dependency_dir}"
  -DFTUN_MODULE_PROXY=OFF
  -DFTUN_MODULE_DNS=OFF -DFTUN_MODULE_FAKEIP=OFF
  -DFTUN_MODULE_TUN=OFF -DFTUN_MODULE_FRS=BUILTIN)
if(result EQUAL 0 OR NOT output MATCHES "requires FTUN_MODULE_PROXY=BUILTIN")
  message(FATAL_ERROR
    "illegal FRS/Proxy dependency was not rejected:\n${output}")
endif()

set(dynamic_dir "${FTUN_MATRIX_DIR}/dynamic")
ftun_configure(result output "${dynamic_dir}"
  -DFTUN_MODULE_PROXY=BUILTIN
  -DFTUN_MODULE_DNS=MODULE -DFTUN_MODULE_FAKEIP=OFF
  -DFTUN_MODULE_TUN=OFF -DFTUN_MODULE_FRS=OFF)
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
    -DFTUN_MODULE_PROXY=OFF
    -DFTUN_MODULE_DNS=OFF
    -DFTUN_MODULE_FAKEIP=OFF
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
    -DFTUN_MODULE_PROXY=BUILTIN
    -DFTUN_MODULE_DNS=OFF
    -DFTUN_MODULE_FAKEIP=OFF
    -DFTUN_MODULE_TUN=OFF
    -DFTUN_MODULE_FRS=BUILTIN
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(result EQUAL 0 OR NOT "${output}\n${error}" MATCHES "requires a Linux target")
  message(FATAL_ERROR "unsupported FRS target was not explicitly rejected:\n${output}\n${error}")
endif()
