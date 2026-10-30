include_directories("${PROJECT_SOURCE_DIR}/tests")
if(BUILD_TESTING)
  add_executable(ftun-contract-test tests/unit/libs/transport/test_skeleton_contract.c)
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
    add_library(ftun-abi-${ftun_abi_caller}-caller OBJECT tests/abi/c_api_abi.c)
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
    add_executable(ftun-abi-${ftun_abi_caller}-test tests/abi/c_api_abi_host.c
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
  add_executable(ftun-core-service-test tests/unit/core/test_core_service.c)
  add_executable(ftun-app-cleanup-test tests/unit/core/test_app_cleanup.c)
  target_include_directories(ftun-app-cleanup-test PRIVATE src)
  target_link_libraries(ftun-app-cleanup-test PRIVATE ftun_runtime ftun_options Threads::Threads)
  if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
    target_compile_definitions(ftun-app-cleanup-test PRIVATE FTUN_TEST_PROXY=1)
  endif()
  if(FTUN_STATIC)
    target_link_options(ftun-app-cleanup-test PRIVATE -static)
  endif()
  add_test(NAME app-cleanup-contract COMMAND ftun-app-cleanup-test)
  add_executable(ftun-app-service-fault-test tests/unit/app/test_app_service_fault.c)
  target_include_directories(ftun-app-service-fault-test PRIVATE src)
  target_link_libraries(ftun-app-service-fault-test PRIVATE ftun_runtime ftun_options Threads::Threads)
  if(FTUN_STATIC)
    target_link_options(ftun-app-service-fault-test PRIVATE -static)
  endif()
  add_test(NAME app-service-fault-contract COMMAND ftun-app-service-fault-test)
  set_tests_properties(app-service-fault-contract PROPERTIES TIMEOUT 30)
  add_executable(ftun-watchdog-test tests/unit/app/test_watchdog.c)
  target_include_directories(ftun-watchdog-test PRIVATE src)
  target_link_libraries(ftun-watchdog-test PRIVATE ftun_runtime ftun_options Threads::Threads)
  if(FTUN_STATIC)
    target_link_options(ftun-watchdog-test PRIVATE -static)
  endif()
  add_test(NAME watchdog-contract COMMAND ftun-watchdog-test)
  set_tests_properties(watchdog-contract PROPERTIES TIMEOUT 30)
  add_executable(ftun-app-control-test tests/unit/app/test_app_control.c)
  target_include_directories(ftun-app-control-test PRIVATE src)
  target_link_libraries(ftun-app-control-test PRIVATE ftun_runtime ftun_options Threads::Threads)
  if(FTUN_STATIC)
    target_link_options(ftun-app-control-test PRIVATE -static)
  endif()
  add_test(NAME app-control-contract COMMAND ftun-app-control-test)
  set_tests_properties(app-control-contract PROPERTIES TIMEOUT 15)
  add_executable(ftun-app-host-test tests/unit/core/test_app_host.c)
  target_include_directories(ftun-app-host-test PRIVATE src)
  target_link_libraries(ftun-app-host-test PRIVATE ftun_runtime ftun_options Threads::Threads)
  if(FTUN_STATIC)
    target_link_options(ftun-app-host-test PRIVATE -static)
  endif()
  add_test(NAME app-host-contract COMMAND ftun-app-host-test)
  set_tests_properties(app-host-contract PROPERTIES TIMEOUT 15)
  add_executable(ftun-app-composition-test tests/unit/core/config/test_app_composition.c)
  add_executable(ftun-app-event-cleanup-test tests/unit/core/config/test_app_composition.c tests/support/app_event_cleanup.c)
  target_compile_definitions(ftun-app-event-cleanup-test PRIVATE FTUN_TEST_EVENT_CLEANUP=1)
  foreach(operation ftun_event_backend_attach ftun_core_module_runtime_prepare ftun_core_module_runtime_drain_until)
    target_link_options(ftun-app-event-cleanup-test PRIVATE "-Wl,--wrap=${operation}")
  endforeach()
  set(ftun_composition_test_targets ftun-app-composition-test ftun-app-event-cleanup-test)
  if(FTUN_MODULE_PROXY STREQUAL "BUILTIN" AND FTUN_MODULE_TUN STREQUAL "BUILTIN"
      AND FTUN_MODULE_DNS STREQUAL "BUILTIN")
    add_executable(ftun-runtime-tun-admission-test tests/unit/core/config/test_app_composition.c tests/support/runtime_tun_admission.c)
    target_compile_definitions(ftun-runtime-tun-admission-test PRIVATE FTUN_TEST_TUN_ADMISSION=1)
    foreach(operation ftun_proxy_runtime_prepare ftun_tun_ingress_bind ftun_socket_path_open
        ftun_proxy_dns_has_hijack ftun_proxy_dns_hijack_tcp ftun_stream_create
        ftun_session_transition ftun_relay_start_with_pool_options socketpair close)
      target_link_options(ftun-runtime-tun-admission-test PRIVATE "-Wl,--wrap=${operation}")
    endforeach()
    list(APPEND ftun_composition_test_targets ftun-runtime-tun-admission-test)
    add_test(NAME runtime-tun-admission-contract COMMAND ftun-runtime-tun-admission-test)
    set_tests_properties(runtime-tun-admission-contract PROPERTIES TIMEOUT 30)
    add_executable(ftun-runtime-tun-recovery-test tests/unit/core/config/test_app_composition.c tests/support/runtime_tun_admission.c)
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
    add_executable(ftun-runtime-tun-async-test tests/unit/core/config/test_app_composition.c tests/support/runtime_tun_async.c)
    target_compile_definitions(ftun-runtime-tun-async-test PRIVATE FTUN_TEST_TUN_ADMISSION=1 FTUN_TEST_TUN_ASYNC=1)
    foreach(operation ftun_tun_ingress_bind ftun_l3_provider_acquire
        ftun_route_prepare ftun_route_prepare_with_budget ftun_route_async_start ftun_route_async_adopt)
      target_link_options(ftun-runtime-tun-async-test PRIVATE "-Wl,--wrap=${operation}")
    endforeach()
    list(APPEND ftun_composition_test_targets ftun-runtime-tun-async-test)
    add_test(NAME runtime-tun-async-contract COMMAND ftun-runtime-tun-async-test)
    set_tests_properties(runtime-tun-async-contract PROPERTIES TIMEOUT 30)
    add_executable(ftun-runtime-udp-retention-test tests/unit/core/config/test_app_composition.c tests/support/runtime_udp_retention.c)
    target_compile_definitions(ftun-runtime-udp-retention-test PRIVATE FTUN_TEST_TUN_ADMISSION=1)
    foreach(operation ftun_tun_ingress_bind ftun_proxy_dns_resolve_with_provider ftun_socket_path_open)
      target_link_options(ftun-runtime-udp-retention-test PRIVATE "-Wl,--wrap=${operation}")
    endforeach()
    list(APPEND ftun_composition_test_targets ftun-runtime-udp-retention-test)
    add_test(NAME runtime-udp-retention-contract COMMAND ftun-runtime-udp-retention-test)
    set_tests_properties(runtime-udp-retention-contract PROPERTIES TIMEOUT 30)
    add_executable(ftun-runtime-tun-udp-recovery-test tests/unit/core/config/test_app_composition.c tests/support/runtime_udp_retention.c)
    target_compile_definitions(ftun-runtime-tun-udp-recovery-test PRIVATE FTUN_TEST_TUN_ADMISSION=1 FTUN_TEST_TUN_UDP_RECOVERY=1)
    foreach(operation ftun_tun_ingress_bind ftun_proxy_dns_resolve_with_provider ftun_socket_path_open ftun_l3_provider_acquire)
      target_link_options(ftun-runtime-tun-udp-recovery-test PRIVATE "-Wl,--wrap=${operation}")
    endforeach()
    list(APPEND ftun_composition_test_targets ftun-runtime-tun-udp-recovery-test)
    add_test(NAME runtime-tun-udp-recovery-contract COMMAND ftun-runtime-tun-udp-recovery-test)
    set_tests_properties(runtime-tun-udp-recovery-contract PROPERTIES TIMEOUT 30)
    add_executable(ftun-app-control-policy-test tests/unit/core/config/test_app_composition.c tests/support/app_control_policy.c)
    target_compile_definitions(ftun-app-control-policy-test PRIVATE FTUN_TEST_CONTROL_POLICY=1)
    target_link_options(ftun-app-control-policy-test PRIVATE
      -Wl,--wrap=ftun_app_runtime_support -Wl,--wrap=ftun_route_prepare
      -Wl,--wrap=ftun_route_prepare_with_budget
      -Wl,--wrap=ftun_route_async_adopt)
    list(APPEND ftun_composition_test_targets ftun-app-control-policy-test)
    foreach(route true false)
      add_test(NAME app-control-policy-${route} COMMAND ftun-app-control-policy-test)
      set_tests_properties(app-control-policy-${route} PROPERTIES TIMEOUT 15
        RESOURCE_LOCK ftun_host_socket
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
  target_link_libraries(ftun-core-service-test PRIVATE ftun_core ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-core-service-test PRIVATE -static)
  endif()
  add_test(NAME core-service-contract COMMAND ftun-core-service-test)
  if(FTUN_MODULE_PROXY STREQUAL "OFF" AND
     FTUN_MODULE_DNS STREQUAL "BUILTIN")
    add_executable(ftun-service-runtime-test tests/unit/platform/test_service_runtime.c)
    target_include_directories(ftun-service-runtime-test PRIVATE src)
    target_link_libraries(ftun-service-runtime-test PRIVATE
      ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-service-runtime-test PRIVATE -static)
    endif()
    add_test(NAME service-runtime-stop-contract
      COMMAND ftun-service-runtime-test)
  endif()
  add_executable(ftun-core-module-plan-test tests/unit/core/test_core_module_plan.c)
  target_include_directories(ftun-core-module-plan-test PRIVATE src)
  target_link_libraries(ftun-core-module-plan-test PRIVATE
    ftun_core ftun_options)
  target_link_options(ftun-core-module-plan-test PRIVATE -Wl,--wrap=calloc)
  if(FTUN_STATIC)
    target_link_options(ftun-core-module-plan-test PRIVATE -static)
  endif()
  add_test(NAME core-module-plan-contract COMMAND ftun-core-module-plan-test)
  if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
    add_executable(ftun-proxy-resources-test tests/unit/core/config/test_proxy_resources.c)
    target_include_directories(ftun-proxy-resources-test PRIVATE src)
    target_link_libraries(ftun-proxy-resources-test PRIVATE ftun_runtime ftun_options)
    target_link_options(ftun-proxy-resources-test PRIVATE
      -Wl,--wrap=socket -Wl,--wrap=accept4 -Wl,--wrap=ftun_event_source_backend_data)
    if(FTUN_STATIC)
      target_link_options(ftun-proxy-resources-test PRIVATE -static)
    endif()
    add_test(NAME proxy-resources-contract COMMAND ftun-proxy-resources-test)
    set_tests_properties(proxy-resources-contract PROPERTIES TIMEOUT 30)
    add_executable(ftun-proxy-owned-memory-test tests/unit/proxy/test_proxy_owned_memory.c)
    target_include_directories(ftun-proxy-owned-memory-test PRIVATE src)
    target_link_libraries(ftun-proxy-owned-memory-test PRIVATE ftun_runtime ftun_options)
    foreach(module DNS FAKEIP TUN FRS)
      if(FTUN_MODULE_${module} STREQUAL "BUILTIN")
        target_compile_definitions(ftun-proxy-owned-memory-test PRIVATE FTUN_HAVE_MODULE_${module}=1)
      endif()
    endforeach()
    target_link_options(ftun-proxy-owned-memory-test PRIVATE
      -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=ftun_worker_submit
      -Wl,--wrap=ftun_inbound_adapter_destroy -Wl,--wrap=ftun_http_fetch)
    if(FTUN_STATIC)
      target_link_options(ftun-proxy-owned-memory-test PRIVATE -static)
    endif()
    add_test(NAME proxy-owned-memory-contract COMMAND ftun-proxy-owned-memory-test)
    set_tests_properties(proxy-owned-memory-contract PROPERTIES TIMEOUT 30)
    add_executable(ftun-proxy-slot-pool-test tests/unit/proxy/test_proxy_slot_pool.c)
    target_include_directories(ftun-proxy-slot-pool-test PRIVATE src)
    target_link_libraries(ftun-proxy-slot-pool-test PRIVATE
      ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-proxy-slot-pool-test PRIVATE -static)
    endif()
    add_test(NAME proxy-slot-pool-contract COMMAND ftun-proxy-slot-pool-test)
  endif()
  add_executable(ftun-build-modules-test tests/unit/app/config/test_build_modules.c)
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
  add_executable(ftun-budget-test tests/unit/core/test_budget.c)
  target_include_directories(ftun-budget-test PRIVATE src)
  target_link_libraries(ftun-budget-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-budget-test PRIVATE -static)
  endif()
  add_test(NAME budget-contract COMMAND ftun-budget-test)
  add_executable(ftun-core-resources-test tests/unit/core/test_core_resources.c)
  target_include_directories(ftun-core-resources-test PRIVATE src)
  target_link_libraries(ftun-core-resources-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-core-resources-test PRIVATE -static)
  endif()
  add_test(NAME core-resources-contract COMMAND ftun-core-resources-test)
  add_executable(ftun-app-owned-memory-test tests/unit/app/test_app_owned_memory.c)
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
  add_executable(ftun-budget-faults-test tests/unit/core/test_budget_faults.c)
  target_include_directories(ftun-budget-faults-test PRIVATE include src)
  target_link_libraries(ftun-budget-faults-test PRIVATE ftun_platform ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-budget-faults-test PRIVATE -static)
  endif()
  add_test(NAME budget-faults-contract COMMAND ftun-budget-faults-test)
  add_executable(ftun-budget-consumers-test tests/unit/core/test_budget_consumers.c)
  target_include_directories(ftun-budget-consumers-test PRIVATE src)
  target_link_libraries(ftun-budget-consumers-test PRIVATE
    ftun_runtime ftun_options Threads::Threads)
  if(FTUN_STATIC)
    target_link_options(ftun-budget-consumers-test PRIVATE -static)
  endif()
  add_test(NAME budget-consumers-contract COMMAND ftun-budget-consumers-test)
  if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
    add_executable(ftun-app-proxy-memory-test tests/unit/app/composition/test_app_proxy_memory.c)
    target_include_directories(ftun-app-proxy-memory-test PRIVATE src tests)
    target_link_libraries(ftun-app-proxy-memory-test PRIVATE ftun_runtime ftun_options)
    target_compile_options(ftun-app-proxy-memory-test PRIVATE
      -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-free)
    target_link_options(ftun-app-proxy-memory-test PRIVATE
      -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=free -Wl,--wrap=open -Wl,--wrap=__open_2
      -Wl,--wrap=ftun_route_table_destroy -Wl,--wrap=read
      -Wl,--wrap=close -Wl,--wrap=mkstemp)
    if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
      target_sources(ftun-app-proxy-memory-test PRIVATE tests/support/frs_fixture.c)
      target_compile_definitions(ftun-app-proxy-memory-test PRIVATE FTUN_HAVE_MODULE_FRS=1)
      target_link_options(ftun-app-proxy-memory-test PRIVATE -Wl,--wrap=ftun_http_fetch)
    endif()
    if(FTUN_STATIC)
      target_link_options(ftun-app-proxy-memory-test PRIVATE -static)
    endif()
    add_test(NAME app-proxy-memory-contract COMMAND ftun-app-proxy-memory-test)
    set_tests_properties(app-proxy-memory-contract PROPERTIES TIMEOUT 15)
    add_executable(ftun-runtime-test tests/unit/core/config/test_runtime.c)
    target_include_directories(ftun-runtime-test PRIVATE src)
    target_link_libraries(ftun-runtime-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-runtime-test PRIVATE -static)
    endif()
    add_test(NAME runtime-contract COMMAND ftun-runtime-test)
    add_executable(ftun-runtime-cleanup-test tests/unit/core/config/test_runtime_cleanup.c)
    target_include_directories(ftun-runtime-cleanup-test PRIVATE src)
    target_link_libraries(ftun-runtime-cleanup-test PRIVATE ftun_runtime ftun_options)
    target_link_options(ftun-runtime-cleanup-test PRIVATE -Wl,--wrap=ftun_route_table_destroy)
    if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
      target_sources(ftun-runtime-cleanup-test PRIVATE tests/support/frs_fixture.c)
      target_compile_definitions(ftun-runtime-cleanup-test PRIVATE FTUN_HAVE_MODULE_FRS=1)
      target_link_options(ftun-runtime-cleanup-test PRIVATE -Wl,--wrap=munmap -Wl,--wrap=calloc)
    endif()
    if(FTUN_STATIC)
      target_link_options(ftun-runtime-cleanup-test PRIVATE -static)
    endif()
    add_test(NAME runtime-cleanup-contract COMMAND ftun-runtime-cleanup-test)
    set_tests_properties(runtime-cleanup-contract PROPERTIES TIMEOUT 15)
    if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
      add_executable(ftun-runtime-detached-test tests/unit/core/config/test_runtime_detached.c tests/support/frs_fixture.c)
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
    add_executable(ftun-session-test tests/unit/core/config/test_session.c)
    target_include_directories(ftun-session-test PRIVATE src)
    target_link_libraries(ftun-session-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-session-test PRIVATE -static)
    endif()
    add_test(NAME session-contract COMMAND ftun-session-test)
  endif()
  add_executable(ftun-buffer-test tests/unit/libs/buffer/test_buffer.c)
  target_include_directories(ftun-buffer-test PRIVATE src)
  target_link_libraries(ftun-buffer-test PRIVATE ftun_runtime ftun_options)
  target_link_options(ftun-buffer-test PRIVATE -Wl,--wrap=calloc)
  if(FTUN_STATIC)
    target_link_options(ftun-buffer-test PRIVATE -static)
  endif()
  add_test(NAME buffer-contract COMMAND ftun-buffer-test)
  add_executable(ftun-hash-test tests/unit/core/test_hash.c)
  target_include_directories(ftun-hash-test PRIVATE src)
  target_link_libraries(ftun-hash-test PRIVATE ftun_runtime ftun_options)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_options(ftun-hash-test PRIVATE -Wl,--wrap=getrandom)
  endif()
  if(FTUN_STATIC)
    target_link_options(ftun-hash-test PRIVATE -static)
  endif()
  add_test(NAME hash-contract COMMAND ftun-hash-test)
  add_executable(ftun-logger-test tests/unit/core/test_logger.c)
  target_include_directories(ftun-logger-test PRIVATE src)
  target_link_libraries(ftun-logger-test PRIVATE
    ftun_runtime ftun_options Threads::Threads)
  if(FTUN_STATIC)
    target_link_options(ftun-logger-test PRIVATE -static)
  endif()
  add_test(NAME logger-contract COMMAND ftun-logger-test)
  add_executable(ftun-log-ledger-test tests/unit/core/log/test_log_ledger.c)
  target_include_directories(ftun-log-ledger-test PRIVATE src)
  target_link_libraries(ftun-log-ledger-test PRIVATE
    ftun_runtime ftun_options Threads::Threads)
  target_link_options(ftun-log-ledger-test PRIVATE -Wl,--wrap=close)
  if(FTUN_STATIC)
    target_link_options(ftun-log-ledger-test PRIVATE -static)
  endif()
  add_test(NAME log-ledger-contract COMMAND ftun-log-ledger-test)
  set_tests_properties(log-ledger-contract PROPERTIES TIMEOUT 30)
  add_executable(ftun-app-logging-test tests/unit/core/test_app_logging.c)
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
  add_executable(ftun-event-log-test tests/unit/core/log/test_event_log.c)
  target_include_directories(ftun-event-log-test PRIVATE src)
  target_link_libraries(ftun-event-log-test PRIVATE
    ftun_runtime ftun_options Threads::Threads)
  if(FTUN_STATIC)
    target_link_options(ftun-event-log-test PRIVATE -static)
  endif()
  add_test(NAME event-log-contract COMMAND ftun-event-log-test)
  add_executable(ftun-cli-result-test tests/unit/app/cli/test_cli_result.c)
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
  add_executable(ftun-cli-preflight-test tests/unit/app/cli/test_cli_preflight.c)
  target_include_directories(ftun-cli-preflight-test PRIVATE src)
  target_link_libraries(ftun-cli-preflight-test PRIVATE
    ftun_runtime ftun_options Threads::Threads)
  target_link_options(ftun-cli-preflight-test PRIVATE
    -Wl,--wrap=ftun_config_load_budget_traced
    -Wl,--wrap=ftun_config_destroy -Wl,--wrap=ftun_core_destroy)
  if(FTUN_MODULE_FAKEIP STREQUAL "BUILTIN")
    target_compile_definitions(ftun-cli-preflight-test PRIVATE FTUN_HAVE_MODULE_FAKEIP=1)
    target_link_options(ftun-cli-preflight-test PRIVATE
      -Wl,--wrap=ftun_random_bytes -Wl,--wrap=ftun_random_device_bytes)
  endif()
  if(FTUN_STATIC)
    target_link_options(ftun-cli-preflight-test PRIVATE -static)
  endif()
  add_test(NAME cli-preflight-contract COMMAND ftun-cli-preflight-test)
  set_tests_properties(cli-preflight-contract PROPERTIES TIMEOUT 30)
  add_executable(ftun-operation-test tests/unit/core/test_operation.c)
  target_include_directories(ftun-operation-test PRIVATE src)
  target_link_libraries(ftun-operation-test PRIVATE
    ftun_runtime ftun_options Threads::Threads)
  if(FTUN_STATIC)
    target_link_options(ftun-operation-test PRIVATE -static)
  endif()
  add_test(NAME operation-contract COMMAND ftun-operation-test)
  add_executable(ftun-worker-test tests/unit/core/test_worker.c)
  target_include_directories(ftun-worker-test PRIVATE src)
  target_link_libraries(ftun-worker-test PRIVATE ftun_runtime ftun_options Threads::Threads)
  if(FTUN_STATIC)
    target_link_options(ftun-worker-test PRIVATE -static)
  endif()
  add_test(NAME worker-contract COMMAND ftun-worker-test)
  add_executable(ftun-recovery-test tests/unit/core/test_recovery.c)
  target_include_directories(ftun-recovery-test PRIVATE src)
  target_link_libraries(ftun-recovery-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-recovery-test PRIVATE -static)
  endif()
  add_test(NAME recovery-contract COMMAND ftun-recovery-test)
  add_executable(ftun-event-test tests/unit/core/event/test_event.c)
  target_include_directories(ftun-event-test PRIVATE src)
  target_link_libraries(ftun-event-test PRIVATE ftun_runtime ftun_options Threads::Threads)
  if(FTUN_STATIC)
    target_link_options(ftun-event-test PRIVATE -static)
  endif()
  add_test(NAME event-contract COMMAND ftun-event-test)
  add_executable(ftun-dialer-test tests/unit/libs/transport/test_dialer.c)
  target_include_directories(ftun-dialer-test PRIVATE src)
  target_link_libraries(ftun-dialer-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-dialer-test PRIVATE -static)
  endif()
  add_test(NAME dialer-contract COMMAND ftun-dialer-test)
  add_test(NAME dialer-real-loopback COMMAND ftun-dialer-test --real-loopback)
  add_executable(ftun-network-view-test tests/unit/libs/transport/test_network_view.c)
  target_include_directories(ftun-network-view-test PRIVATE src)
  target_link_libraries(ftun-network-view-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-network-view-test PRIVATE -static)
  endif()
  add_test(NAME network-view-contract COMMAND ftun-network-view-test)
  add_executable(ftun-network-address-test tests/unit/util/test_network_address.c)
  target_include_directories(ftun-network-address-test PRIVATE src)
  target_link_libraries(ftun-network-address-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-network-address-test PRIVATE -static)
  endif()
  add_test(NAME network-address-contract COMMAND ftun-network-address-test)
  add_executable(ftun-tls-worker-stack-test tests/unit/libs/tls/test_tls_worker_stack.c)
  target_include_directories(ftun-tls-worker-stack-test PRIVATE src)
  target_compile_definitions(ftun-tls-worker-stack-test PRIVATE
    "FTUN_TEST_CERT_DIR=${CMAKE_CURRENT_SOURCE_DIR}/third_party/wolfssl/certs")
  target_link_libraries(ftun-tls-worker-stack-test PRIVATE ftun_lib_tls ftun_runtime ftun_options
    Threads::Threads wolfssl::wolfssl)
  if(FTUN_STATIC)
    target_link_options(ftun-tls-worker-stack-test PRIVATE -static)
  endif()
  add_test(NAME tls-worker-stack COMMAND ftun-tls-worker-stack-test)

  add_executable(ftun-provider-bindings-test tests/unit/core/test_provider_bindings.c)
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
  add_executable(ftun-resolver-provider-test tests/unit/core/test_resolver_provider.c)
  target_include_directories(ftun-resolver-provider-test PRIVATE src)
  target_link_libraries(ftun-resolver-provider-test PRIVATE ftun_runtime ftun_options)
  add_test(NAME resolver-provider-contract COMMAND ftun-resolver-provider-test)
  add_executable(ftun-resolver-dual-test tests/unit/core/test_resolver_dual.c)
  target_include_directories(ftun-resolver-dual-test PRIVATE src)
  target_link_libraries(ftun-resolver-dual-test PRIVATE ftun_runtime ftun_options)
  add_test(NAME resolver-dual-contract COMMAND ftun-resolver-dual-test)
  add_executable(ftun-path-test tests/unit/core/test_path.c)
  target_include_directories(ftun-path-test PRIVATE src)
  target_link_libraries(ftun-path-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-path-test PRIVATE -static)
  endif()
  add_test(NAME path-contract COMMAND ftun-path-test)
  add_executable(ftun-path-result-test tests/unit/libs/transport/test_path_result.c)
  target_include_directories(ftun-path-result-test PRIVATE src)
  target_link_libraries(ftun-path-result-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-path-result-test PRIVATE -static)
  endif()
  add_test(NAME path-result-contract COMMAND ftun-path-result-test)
  add_executable(ftun-egress-test tests/unit/libs/transport/test_egress.c)
  target_include_directories(ftun-egress-test PRIVATE src)
  target_link_libraries(ftun-egress-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-egress-test PRIVATE -static)
  endif()
  if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
    target_compile_definitions(ftun-egress-test PRIVATE FTUN_TEST_PROXY=1)
  endif()
  add_test(NAME egress-contract COMMAND ftun-egress-test)
  add_executable(ftun-path-provider-test tests/unit/core/test_path_provider.c)
  target_include_directories(ftun-path-provider-test PRIVATE src)
  target_link_libraries(ftun-path-provider-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-path-provider-test PRIVATE -static)
  endif()
  add_test(NAME path-provider-contract COMMAND ftun-path-provider-test)

  add_executable(ftun-socket-path-test tests/unit/core/test_socket_path.c)
  target_include_directories(ftun-socket-path-test PRIVATE src)
  target_link_libraries(ftun-socket-path-test PRIVATE ftun_runtime ftun_options)
  target_link_options(ftun-socket-path-test PRIVATE -Wl,--wrap=send)
  if(FTUN_STATIC)
    target_link_options(ftun-socket-path-test PRIVATE -static)
  endif()
  add_test(NAME socket-path-contract COMMAND ftun-socket-path-test)
  add_executable(ftun-stream-test tests/unit/libs/transport/test_stream.c)
  target_include_directories(ftun-stream-test PRIVATE src)
  target_link_libraries(ftun-stream-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-stream-test PRIVATE -static)
  endif()
  add_test(NAME stream-contract COMMAND ftun-stream-test)
  add_executable(ftun-stream-abort-test tests/unit/libs/transport/test_stream_abort.c)
  target_include_directories(ftun-stream-abort-test PRIVATE src)
  target_link_libraries(ftun-stream-abort-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-stream-abort-test PRIVATE -static)
  endif()
  add_test(NAME stream-abort-contract COMMAND ftun-stream-abort-test)
  add_executable(ftun-datagram-test tests/unit/libs/transport/test_datagram.c)
  target_include_directories(ftun-datagram-test PRIVATE src)
  target_link_libraries(ftun-datagram-test PRIVATE ftun_runtime ftun_options)
  target_link_options(ftun-datagram-test PRIVATE -Wl,--wrap=calloc)
  if(FTUN_STATIC)
    target_link_options(ftun-datagram-test PRIVATE -static)
  endif()
  add_test(NAME datagram-contract COMMAND ftun-datagram-test)
  add_executable(ftun-relay-test tests/unit/libs/transport/test_relay.c)
  target_include_directories(ftun-relay-test PRIVATE src)
  target_link_libraries(ftun-relay-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-relay-test PRIVATE -static)
  endif()
  add_test(NAME relay-contract COMMAND ftun-relay-test)
  if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
  add_executable(ftun-protocol-socks5-test tests/unit/libs/transport/test_protocol_socks5.c)
  target_include_directories(ftun-protocol-socks5-test PRIVATE src)
  target_link_libraries(ftun-protocol-socks5-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-protocol-socks5-test PRIVATE -static)
  endif()
  add_test(NAME protocol-socks5-contract COMMAND ftun-protocol-socks5-test)
  endif()
  add_executable(ftun-netmon-test tests/unit/libs/transport/test_netmon.c)
  target_include_directories(ftun-netmon-test PRIVATE src)
  target_link_libraries(ftun-netmon-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-netmon-test PRIVATE -static)
  endif()
  add_test(NAME netmon-contract COMMAND ftun-netmon-test)
  if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
  add_executable(ftun-protocol-socks5-client-test tests/unit/libs/transport/test_protocol_socks5_client.c)
  target_include_directories(ftun-protocol-socks5-client-test PRIVATE src)
  target_link_libraries(ftun-protocol-socks5-client-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-protocol-socks5-client-test PRIVATE -static)
  endif()
  add_test(NAME protocol-socks5-client-contract COMMAND ftun-protocol-socks5-client-test)
  endif()
  if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
  add_executable(ftun-protocol-http-test tests/unit/proxy/inbound/test_protocol_http.c)
  target_include_directories(ftun-protocol-http-test PRIVATE src)
  target_link_libraries(ftun-protocol-http-test PRIVATE ftun_runtime ftun_options)
  add_test(NAME protocol-http-contract COMMAND ftun-protocol-http-test)
    add_executable(ftun-inbound-socks5-test tests/unit/proxy/inbound/test_inbound_socks5.c)
    target_include_directories(ftun-inbound-socks5-test PRIVATE src)
    target_link_libraries(ftun-inbound-socks5-test PRIVATE ftun_runtime ftun_options)
    add_test(NAME inbound-socks5-contract COMMAND ftun-inbound-socks5-test)
    add_executable(ftun-inbound-mixed-test tests/unit/proxy/inbound/test_inbound_mixed.c)
    target_include_directories(ftun-inbound-mixed-test PRIVATE src)
    target_link_libraries(ftun-inbound-mixed-test PRIVATE
      ftun_runtime ftun_options)
    add_test(NAME inbound-mixed-contract COMMAND ftun-inbound-mixed-test)
    add_executable(ftun-inbound-adapter-test tests/unit/proxy/inbound/test_inbound_adapter.c)
    target_include_directories(ftun-inbound-adapter-test PRIVATE src)
    target_link_libraries(ftun-inbound-adapter-test PRIVATE ftun_runtime ftun_options)
    add_test(NAME inbound-adapter-contract COMMAND ftun-inbound-adapter-test)
    add_executable(ftun-outbound-path-test tests/unit/core/test_outbound_path.c tests/support/memory_path_factory.c)
    target_include_directories(ftun-outbound-path-test PRIVATE src)
    target_link_libraries(ftun-outbound-path-test PRIVATE ftun_runtime ftun_options)
    add_test(NAME outbound-path-contract COMMAND ftun-outbound-path-test)
    add_executable(ftun-socks-path-test tests/unit/core/test_socks_path.c tests/support/memory_path_factory.c)
    target_include_directories(ftun-socks-path-test PRIVATE src)
    target_link_libraries(ftun-socks-path-test PRIVATE ftun_runtime ftun_options)
    add_test(NAME socks-path-contract COMMAND ftun-socks-path-test)
    add_executable(ftun-socks-datagram-test tests/unit/core/test_socks_datagram.c tests/support/memory_path_factory.c)
    target_include_directories(ftun-socks-datagram-test PRIVATE src)
    target_link_libraries(ftun-socks-datagram-test PRIVATE ftun_runtime ftun_options)
    add_test(NAME socks-datagram-contract COMMAND ftun-socks-datagram-test)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      add_executable(ftun-memory-path-test src/app/main.c tests/support/memory_path_factory.c)
      target_include_directories(ftun-memory-path-test PRIVATE src)
      target_link_libraries(ftun-memory-path-test PRIVATE ftun_runtime ftun_options)
      target_link_options(ftun-memory-path-test PRIVATE -Wl,--wrap=ftun_socket_path_open)
      if(FTUN_MODULE_DNS STREQUAL "BUILTIN")
        add_executable(ftun-resolver-production-test src/app/main.c tests/support/resolver_factory_probe.c)
        target_include_directories(ftun-resolver-production-test PRIVATE src)
        target_link_libraries(ftun-resolver-production-test PRIVATE ftun_runtime ftun_options)
        target_link_options(ftun-resolver-production-test PRIVATE -Wl,--wrap=ftun_resolver_scope_start)
      endif()
    endif()
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      add_executable(ftun-control-channel-test tests/unit/libs/resolver/test_control_channel.c)
      target_include_directories(ftun-control-channel-test PRIVATE src)
      target_link_libraries(ftun-control-channel-test PRIVATE ftun_runtime ftun_options)
      target_link_options(ftun-control-channel-test PRIVATE -Wl,--wrap=ftun_socket_path_open)
      add_test(NAME control-channel-contract COMMAND ftun-control-channel-test)
      add_executable(ftun-control-resolution-test tests/unit/libs/resolver/test_control_resolution.c)
      target_include_directories(ftun-control-resolution-test PRIVATE src)
      target_link_libraries(ftun-control-resolution-test PRIVATE ftun_runtime ftun_options)
      add_test(NAME control-resolution-contract COMMAND ftun-control-resolution-test)
      add_executable(ftun-control-system-worker-test tests/unit/proxy/test_control_system_worker.c)
      target_include_directories(ftun-control-system-worker-test PRIVATE src)
      target_link_libraries(ftun-control-system-worker-test PRIVATE ftun_runtime ftun_options Threads::Threads)
      target_link_options(ftun-control-system-worker-test PRIVATE -Wl,--wrap=getaddrinfo)
      add_test(NAME control-system-worker-contract COMMAND ftun-control-system-worker-test)
      add_executable(ftun-control-datagram-test tests/unit/libs/resolver/test_control_datagram.c)
      target_include_directories(ftun-control-datagram-test PRIVATE src)
      target_link_libraries(ftun-control-datagram-test PRIVATE ftun_runtime ftun_options)
      target_link_options(ftun-control-datagram-test PRIVATE -Wl,--wrap=ftun_socket_path_open)
      add_test(NAME control-datagram-contract COMMAND ftun-control-datagram-test)
      add_executable(ftun-http-fetch-test tests/unit/proxy/test_http_fetch.c)
      target_include_directories(ftun-http-fetch-test PRIVATE src)
      target_link_libraries(ftun-http-fetch-test PRIVATE ftun_runtime ftun_options)
      if(FTUN_MODULE_DNS STREQUAL "BUILTIN")
        add_executable(ftun-control-dns-test tests/unit/proxy/test_control_dns.c)
        target_include_directories(ftun-control-dns-test PRIVATE src)
        target_link_libraries(ftun-control-dns-test PRIVATE ftun_runtime ftun_options)
        target_link_options(ftun-control-dns-test PRIVATE -Wl,--wrap=ftun_resolver_provider_start -Wl,--wrap=getaddrinfo)
      endif()
    endif()
    add_executable(ftun-sniff-tls-test tests/unit/proxy/sniff/test_sniff_tls.c)
    target_include_directories(ftun-sniff-tls-test PRIVATE src)
    target_link_libraries(ftun-sniff-tls-test PRIVATE ftun_runtime ftun_options)
    add_test(NAME sniff-tls-contract COMMAND ftun-sniff-tls-test)
    add_executable(ftun-sniff-http-test tests/unit/proxy/sniff/test_sniff_http.c)
    target_include_directories(ftun-sniff-http-test PRIVATE src)
    target_link_libraries(ftun-sniff-http-test PRIVATE ftun_runtime ftun_options)
    add_test(NAME sniff-http-contract COMMAND ftun-sniff-http-test)
    add_executable(ftun-sniff-test tests/unit/proxy/sniff/test_sniff.c)
    target_include_directories(ftun-sniff-test PRIVATE src)
    target_link_libraries(ftun-sniff-test PRIVATE ftun_runtime ftun_options)
    add_test(NAME sniff-contract COMMAND ftun-sniff-test)
    set(ftun_untrusted_parser_sources tests/unit/proxy/inbound/test_untrusted_parsers.c)
    if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
      list(APPEND ftun_untrusted_parser_sources tests/support/frs_fixture.c)
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
    # fuzz：同一批入口既可由 libFuzzer 驱动（FTUN_FUZZ，仅 clang），也可由回放驱动做
    # 确定性变异冒烟（ctest fuzz-*，任何构建都能跑）。语料见 fuzz/corpus。
    set(ftun_fuzz_targets config socks5 http sniff log)
    if(FTUN_MODULE_DNS STREQUAL "BUILTIN")
      list(APPEND ftun_fuzz_targets dns)
    endif()
    if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
      list(APPEND ftun_fuzz_targets frs)
    endif()
    if(FTUN_MODULE_FAKEIP STREQUAL "BUILTIN")
      list(APPEND ftun_fuzz_targets fakeip)
    endif()
    foreach(ftun_fuzz_name IN LISTS ftun_fuzz_targets)
      set(ftun_fuzz_sources fuzz/fuzz_${ftun_fuzz_name}.c)
      if(ftun_fuzz_name STREQUAL "frs")
        list(APPEND ftun_fuzz_sources tests/support/frs_fixture.c)
      endif()
      add_executable(ftun-fuzz-${ftun_fuzz_name}-replay
        ${ftun_fuzz_sources} fuzz/fuzz_replay.c)
      target_include_directories(ftun-fuzz-${ftun_fuzz_name}-replay
        PRIVATE src tests fuzz)
      target_link_libraries(ftun-fuzz-${ftun_fuzz_name}-replay PRIVATE
        ftun_runtime ftun_options Threads::Threads)
      if(FTUN_STATIC)
        target_link_options(ftun-fuzz-${ftun_fuzz_name}-replay PRIVATE -static)
      endif()
      set(ftun_fuzz_corpus
        ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/${ftun_fuzz_name})
      if(ftun_fuzz_name STREQUAL "config")
        list(APPEND ftun_fuzz_corpus ${CMAKE_CURRENT_SOURCE_DIR}/examples)
      endif()
      add_test(NAME fuzz-${ftun_fuzz_name}
        COMMAND ftun-fuzz-${ftun_fuzz_name}-replay ${ftun_fuzz_corpus})
      if(FTUN_FUZZ)
        add_executable(ftun-fuzzer-${ftun_fuzz_name} ${ftun_fuzz_sources})
        target_include_directories(ftun-fuzzer-${ftun_fuzz_name}
          PRIVATE src tests fuzz)
        target_link_libraries(ftun-fuzzer-${ftun_fuzz_name} PRIVATE
          ftun_runtime ftun_options Threads::Threads)
        target_compile_options(ftun-fuzzer-${ftun_fuzz_name} PRIVATE
          -fsanitize=fuzzer-no-link)
        target_link_options(ftun-fuzzer-${ftun_fuzz_name} PRIVATE -fsanitize=fuzzer)
      endif()
    endforeach()
    add_executable(ftun-group-cache-test tests/unit/core/config/test_group_cache.c)
    target_include_directories(ftun-group-cache-test PRIVATE src)
    target_link_libraries(ftun-group-cache-test PRIVATE ftun_runtime ftun_options)
    add_test(NAME group-cache-contract COMMAND ftun-group-cache-test)
    add_executable(ftun-core-state-test tests/unit/core/config/test_core_state.c)
    target_include_directories(ftun-core-state-test PRIVATE src)
    target_link_libraries(ftun-core-state-test PRIVATE ftun_runtime ftun_options)
    add_test(NAME core-state-contract COMMAND ftun-core-state-test)
    add_executable(ftun-v05-integration-test tests/unit/proxy/test_integration_v05.c)
    target_include_directories(ftun-v05-integration-test PRIVATE src)
    target_link_libraries(ftun-v05-integration-test PRIVATE
      ftun_runtime ftun_options Threads::Threads)
    add_test(NAME integration-v05-contract COMMAND ftun-v05-integration-test)
    add_executable(ftun-control-resolver-test tests/unit/proxy/test_control_resolver.c)
    target_include_directories(ftun-control-resolver-test PRIVATE src)
    target_link_libraries(ftun-control-resolver-test PRIVATE
      ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-control-resolver-test PRIVATE -static)
    endif()
    add_test(NAME control-resolver-contract COMMAND ftun-control-resolver-test)
    if(FTUN_MODULE_FRS STREQUAL "BUILTIN" AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
      add_executable(ftun-control-memory-test src/app/main.c tests/support/control_memory_factory.c tests/support/frs_fixture.c)
      target_include_directories(ftun-control-memory-test PRIVATE src tests)
      target_link_libraries(ftun-control-memory-test PRIVATE ftun_runtime ftun_options)
      target_link_options(ftun-control-memory-test PRIVATE -Wl,--wrap=ftun_socket_path_open -Wl,--wrap=ftun_resolver_provider_start)
    endif()
    if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
      add_executable(ftun-v04-frs-test tests/unit/core/test_frs.c tests/support/frs_fixture.c)
      target_include_directories(ftun-v04-frs-test PRIVATE src tests)
      target_link_libraries(ftun-v04-frs-test PRIVATE ftun_runtime ftun_options)
      add_test(NAME frs-contract COMMAND ftun-v04-frs-test)
      add_executable(ftun-app-frs-test tests/unit/core/io/test_app_frs.c tests/support/frs_fixture.c)
      target_include_directories(ftun-app-frs-test PRIVATE src tests)
      target_link_libraries(ftun-app-frs-test PRIVATE ftun_runtime ftun_options Threads::Threads)
      target_link_options(ftun-app-frs-test PRIVATE
        -Wl,--wrap=ftun_http_fetch -Wl,--wrap=ftun_file_write_atomic_budget)
      if(FTUN_STATIC)
        target_link_options(ftun-app-frs-test PRIVATE -static)
      endif()
      add_test(NAME app-frs-contract COMMAND ftun-app-frs-test)
      add_executable(ftun-runtime-worker-cleanup-test
        tests/unit/proxy/test_runtime_worker_cleanup.c tests/support/frs_fixture.c)
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
  add_executable(ftun-v04-tls-test tests/unit/libs/tls/test_tls.c)
  target_include_directories(ftun-v04-tls-test PRIVATE src)
  target_compile_definitions(ftun-v04-tls-test PRIVATE
    "FTUN_TEST_CERT_DIR=${CMAKE_CURRENT_SOURCE_DIR}/third_party/wolfssl/certs")
  target_link_libraries(ftun-v04-tls-test PRIVATE ftun_lib_tls
    ftun_runtime ftun_options wolfssl::wolfssl)
  add_test(NAME tls-wolfssl-contract COMMAND ftun-v04-tls-test)
  add_executable(ftun-tls-resources-test tests/unit/libs/tls/test_tls_resources.c)
  target_include_directories(ftun-tls-resources-test PRIVATE src)
  target_compile_definitions(ftun-tls-resources-test PRIVATE
    "FTUN_TEST_CERT_DIR=${CMAKE_CURRENT_SOURCE_DIR}/third_party/wolfssl/certs")
  target_link_libraries(ftun-tls-resources-test PRIVATE ftun_lib_tls
    ftun_runtime ftun_options wolfssl::wolfssl)
  target_link_options(ftun-tls-resources-test PRIVATE
    -Wl,--wrap=wolfSSL_Init -Wl,--wrap=wolfSSL_CTX_new
    -Wl,--wrap=wolfSSL_new -Wl,--wrap=wolfSSL_UseSNI)
  add_test(NAME tls-resources-contract COMMAND ftun-tls-resources-test)
  add_executable(ftun-tls-global-test tests/unit/libs/tls/test_tls_global.c)
  target_include_directories(ftun-tls-global-test PRIVATE src)
  target_compile_definitions(ftun-tls-global-test PRIVATE
    "FTUN_TEST_CERT_DIR=${CMAKE_CURRENT_SOURCE_DIR}/third_party/wolfssl/certs")
  target_link_libraries(ftun-tls-global-test PRIVATE ftun_lib_tls
    ftun_runtime ftun_options wolfssl::wolfssl Threads::Threads)
  target_link_options(ftun-tls-global-test PRIVATE
    -Wl,--wrap=wolfSSL_Init -Wl,--wrap=wolfSSL_Cleanup -Wl,--wrap=atexit)
  add_test(NAME tls-global-contract COMMAND ftun-tls-global-test)
  set_tests_properties(tls-global-contract PROPERTIES TIMEOUT 30)
  if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
    add_executable(ftun-v04-integration-test
      tests/unit/core/test_integration_v04.c tests/support/frs_fixture.c)
    target_include_directories(ftun-v04-integration-test PRIVATE src tests)
    target_link_libraries(ftun-v04-integration-test PRIVATE
      ftun_runtime ftun_options)
    add_test(NAME integration-v04-contract COMMAND ftun-v04-integration-test)
  endif()
  if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
    add_executable(ftun-route-target-test tests/unit/proxy/route/test_route_target.c)
    target_include_directories(ftun-route-target-test PRIVATE src)
    target_link_libraries(ftun-route-target-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-route-target-test PRIVATE -static)
    endif()
    add_test(NAME route-target-contract COMMAND ftun-route-target-test)
    add_executable(ftun-route-rule-test tests/unit/proxy/route/test_route_rule.c)
    target_include_directories(ftun-route-rule-test PRIVATE src)
    target_link_libraries(ftun-route-rule-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-route-rule-test PRIVATE -static)
    endif()
    add_test(NAME route-rule-contract COMMAND ftun-route-rule-test)
    add_executable(ftun-route-router-test tests/unit/core/config/test_route_router.c)
    target_include_directories(ftun-route-router-test PRIVATE src)
    target_link_libraries(ftun-route-router-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-route-router-test PRIVATE -static)
    endif()
    add_test(NAME route-router-contract COMMAND ftun-route-router-test)
    add_executable(ftun-route-memory-test tests/unit/core/config/test_route_memory.c)
    target_include_directories(ftun-route-memory-test PRIVATE src)
    target_link_libraries(ftun-route-memory-test PRIVATE ftun_runtime ftun_options)
    target_link_options(ftun-route-memory-test PRIVATE
      -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=free)
    if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
      target_sources(ftun-route-memory-test PRIVATE tests/support/frs_fixture.c)
      target_compile_definitions(ftun-route-memory-test PRIVATE FTUN_HAVE_MODULE_FRS=1)
      target_link_options(ftun-route-memory-test PRIVATE -Wl,--wrap=ftun_file_open -Wl,--wrap=read)
    endif()
    if(FTUN_STATIC)
      target_link_options(ftun-route-memory-test PRIVATE -static)
    endif()
    add_test(NAME route-memory-contract COMMAND ftun-route-memory-test)
    set_tests_properties(route-memory-contract PROPERTIES TIMEOUT 30)
    add_executable(ftun-outbound-reject-test tests/unit/proxy/outbound/test_outbound_reject.c)
    target_include_directories(ftun-outbound-reject-test PRIVATE src)
    target_link_libraries(ftun-outbound-reject-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-outbound-reject-test PRIVATE -static)
    endif()
    add_test(NAME outbound-reject-contract COMMAND ftun-outbound-reject-test)
    add_executable(ftun-outbound-direct-test tests/unit/proxy/outbound/test_outbound_direct.c)
    target_include_directories(ftun-outbound-direct-test PRIVATE src)
    target_link_libraries(ftun-outbound-direct-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-outbound-direct-test PRIVATE -static)
    endif()
    add_test(NAME outbound-direct-contract COMMAND ftun-outbound-direct-test)
    add_executable(ftun-outbound-socks5-test tests/unit/proxy/outbound/test_outbound_socks5.c)
    target_include_directories(ftun-outbound-socks5-test PRIVATE src)
    target_link_libraries(ftun-outbound-socks5-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-outbound-socks5-test PRIVATE -static)
    endif()
    add_test(NAME outbound-socks5-contract COMMAND ftun-outbound-socks5-test)
    add_executable(ftun-outbound-test tests/unit/proxy/outbound/test_outbound.c)
    target_include_directories(ftun-outbound-test PRIVATE src)
    target_link_libraries(ftun-outbound-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-outbound-test PRIVATE -static)
    endif()
    add_test(NAME outbound-contract COMMAND ftun-outbound-test)
  endif()
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(ftun-event-backend-test tests/unit/core/event/test_backend.c)
    target_include_directories(ftun-event-backend-test PRIVATE src)
    target_link_libraries(ftun-event-backend-test PRIVATE ftun_runtime ftun_options Threads::Threads)
    target_link_options(ftun-event-backend-test PRIVATE
      -Wl,--wrap=ftun_event_io_ready -Wl,--wrap=epoll_wait -Wl,--wrap=epoll_ctl
      -Wl,--wrap=read -Wl,--wrap=write -Wl,--wrap=ftun_monotonic_now)
    if(FTUN_STATIC)
      target_link_options(ftun-event-backend-test PRIVATE -static)
    endif()
    add_test(NAME event-backend COMMAND ftun-event-backend-test)
    set_tests_properties(event-backend PROPERTIES TIMEOUT 20)
    add_executable(ftun-event-resources-test tests/unit/core/test_event_resources.c)
    target_include_directories(ftun-event-resources-test PRIVATE src)
    target_link_libraries(ftun-event-resources-test PRIVATE ftun_runtime ftun_options Threads::Threads)
    target_link_options(ftun-event-resources-test PRIVATE
      -Wl,--wrap=eventfd -Wl,--wrap=pipe -Wl,--wrap=ftun_event_source_backend_data)
    if(FTUN_STATIC)
      target_link_options(ftun-event-resources-test PRIVATE -static)
    endif()
    add_test(NAME event-resources-contract COMMAND ftun-event-resources-test)
    set_tests_properties(event-resources-contract PROPERTIES TIMEOUT 20)
  endif()
  add_executable(ftun-config-parser-test tests/unit/app/config/test_config_parser.c)
  add_executable(ftun-config-memory-test tests/unit/app/config/test_config_memory.c)
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
    ${CMAKE_CURRENT_SOURCE_DIR}/examples/dns-proxy/full.json)
  add_executable(ftun-config-validate-test tests/unit/app/config/test_config_validate.c)
  target_include_directories(ftun-config-validate-test PRIVATE src)
  target_link_libraries(ftun-config-validate-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-config-validate-test PRIVATE -static)
  endif()
  add_executable(ftun-config-compile-test tests/unit/app/config/test_config_compile.c)
  target_include_directories(ftun-config-compile-test PRIVATE src)
  target_link_libraries(ftun-config-compile-test PRIVATE ftun_runtime ftun_options)
  if(FTUN_STATIC)
    target_link_options(ftun-config-compile-test PRIVATE -static)
  endif()
  add_executable(ftun-config-load-test tests/unit/app/config/test_config_load.c)
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
      ${CMAKE_CURRENT_SOURCE_DIR}/examples/dns-proxy/full.json)
    add_test(NAME config-compile COMMAND ftun-config-compile-test
      ${CMAKE_CURRENT_SOURCE_DIR}/examples/dns-proxy/full.json)
    add_test(NAME config-load COMMAND ftun-config-load-test)
  endif()
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(ftun-platform-file-test tests/unit/core/io/test_platform_file.c)
    target_include_directories(ftun-platform-file-test PRIVATE src)
    target_link_libraries(ftun-platform-file-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-platform-file-test PRIVATE -static)
    endif()
    add_test(NAME platform-file-contract COMMAND ftun-platform-file-test)
    add_executable(ftun-socket-liveness-test tests/unit/platform/posix/test_socket_liveness.c)
    target_include_directories(ftun-socket-liveness-test PRIVATE src)
    target_link_libraries(ftun-socket-liveness-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-socket-liveness-test PRIVATE -static)
    endif()
    add_test(NAME socket-liveness-contract COMMAND ftun-socket-liveness-test)
    add_executable(ftun-socket-error-test tests/unit/platform/posix/test_socket_error.c)
    target_include_directories(ftun-socket-error-test PRIVATE src)
    target_link_libraries(ftun-socket-error-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-socket-error-test PRIVATE -static)
    endif()
    add_test(NAME socket-error-contract COMMAND ftun-socket-error-test)
    add_executable(ftun-platform-linux-socket-protect-test
      tests/unit/platform/linux/test_platform_linux_socket_protect.c)
    target_include_directories(ftun-platform-linux-socket-protect-test PRIVATE src)
    target_link_libraries(ftun-platform-linux-socket-protect-test PRIVATE
      ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-platform-linux-socket-protect-test PRIVATE -static)
    endif()
    add_test(NAME platform-linux-socket-protect
      COMMAND ftun-platform-linux-socket-protect-test)
    add_executable(ftun-platform-system-resolver-test
      tests/unit/core/test_platform_system_resolver.c)
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
    add_executable(ftun-fakeip-store-test tests/unit/core/test_fakeip_store.c)
    target_include_directories(ftun-fakeip-store-test PRIVATE src)
    target_link_libraries(ftun-fakeip-store-test PRIVATE
      ftun_runtime ftun_options Threads::Threads)
    target_link_options(ftun-fakeip-store-test PRIVATE
      -Wl,--wrap=open -Wl,--wrap=close -Wl,--wrap=mkstemp)
    if(FTUN_STATIC)
      target_link_options(ftun-fakeip-store-test PRIVATE -static)
    endif()
    add_test(NAME fakeip-store-contract COMMAND ftun-fakeip-store-test)
    add_executable(ftun-fakeip-snapshot-test tests/unit/core/test_fakeip_snapshot.c)
    target_include_directories(ftun-fakeip-snapshot-test PRIVATE src)
    target_link_libraries(ftun-fakeip-snapshot-test PRIVATE
      ftun_runtime ftun_options Threads::Threads)
    if(FTUN_STATIC)
      target_link_options(ftun-fakeip-snapshot-test PRIVATE -static)
    endif()
    add_test(NAME fakeip-snapshot-contract COMMAND ftun-fakeip-snapshot-test)
    add_executable(ftun-fakeip-test tests/unit/core/test_fakeip.c)
    target_include_directories(ftun-fakeip-test PRIVATE src)
    target_link_libraries(ftun-fakeip-test PRIVATE
      ftun_runtime ftun_options Threads::Threads)
    if(FTUN_STATIC)
      target_link_options(ftun-fakeip-test PRIVATE -static)
    endif()
    add_test(NAME fakeip-contract COMMAND ftun-fakeip-test)
  endif()
  if(FTUN_MODULE_DNS STREQUAL "BUILTIN")
    add_executable(ftun-dns-egress-test tests/unit/dns/test_dns_egress.c)
    target_include_directories(ftun-dns-egress-test PRIVATE src)
    target_compile_definitions(ftun-dns-egress-test PRIVATE FTUN_HAVE_MODULE_DNS=1)
    target_link_libraries(ftun-dns-egress-test PRIVATE ftun_dns ftun_options)
    add_test(NAME dns-egress-contract COMMAND ftun-dns-egress-test)
    add_executable(ftun-dns-dependencies-test tests/unit/dns/test_dns_dependencies.c)
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
      tests/unit/libs/transport/test_dns_service.c)
    target_include_directories(ftun-dns-service-test PRIVATE include src)
    target_link_options(ftun-dns-service-test PRIVATE
      -Wl,--wrap=ftun_monotonic_now -Wl,--wrap=ftun_event_loop_run_once)
    target_compile_definitions(ftun-dns-service-test PRIVATE
      FTUN_HAVE_MODULE_DNS=1)
    target_link_libraries(ftun-dns-service-test PRIVATE
      ftun_dns ftun_app_config ftun_options Threads::Threads)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")

    endif()
    if(FTUN_STATIC)
      target_link_options(ftun-dns-service-test PRIVATE -static)
    endif()
    add_test(NAME dns-service-independent-contract
      COMMAND ftun-dns-service-test)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      add_executable(ftun-dns-memory-path-test src/app/main.c tests/support/memory_path_factory.c)
      target_include_directories(ftun-dns-memory-path-test PRIVATE src)
      target_compile_definitions(ftun-dns-memory-path-test PRIVATE FTUN_TEST_DNS_MEMORY=1)
      target_link_libraries(ftun-dns-memory-path-test PRIVATE ftun_runtime ftun_options)
      target_link_options(ftun-dns-memory-path-test PRIVATE -Wl,--wrap=ftun_socket_path_open)
    endif()
    add_executable(ftun-dns-service-failures-test tests/unit/dns/test_dns_service_failures.c)
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
    add_executable(ftun-dns-path-lifecycle-test tests/unit/platform/test_dns_path_lifecycle.c)
    target_include_directories(ftun-dns-path-lifecycle-test PRIVATE src)
    target_compile_definitions(ftun-dns-path-lifecycle-test PRIVATE FTUN_HAVE_MODULE_DNS=1)
    target_link_libraries(ftun-dns-path-lifecycle-test PRIVATE ftun_runtime ftun_options)
    add_test(NAME dns-path-lifecycle-contract COMMAND ftun-dns-path-lifecycle-test)
    if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
      add_executable(ftun-service-leaf-cleanup-test tests/unit/libs/transport/test_service_leaf_cleanup.c)
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
    add_executable(ftun-dns-cache-test tests/unit/core/test_dns_cache.c)
    target_include_directories(ftun-dns-cache-test PRIVATE src)
    target_link_libraries(ftun-dns-cache-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-dns-cache-test PRIVATE -static)
    endif()
    add_test(NAME dns-cache-contract COMMAND ftun-dns-cache-test)
    if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
      add_executable(ftun-dns-server-test tests/unit/core/test_dns_server.c)
      target_include_directories(ftun-dns-server-test PRIVATE src)
      target_link_libraries(ftun-dns-server-test PRIVATE ftun_runtime ftun_options)
      if(FTUN_STATIC)
        target_link_options(ftun-dns-server-test PRIVATE -static)
      endif()
      add_test(NAME dns-server-contract COMMAND ftun-dns-server-test)
      add_executable(ftun-dns-query-binding-test tests/unit/dns/test_dns_query_binding.c)
      target_include_directories(ftun-dns-query-binding-test PRIVATE src)
      target_compile_definitions(ftun-dns-query-binding-test PRIVATE
        FTUN_HAVE_MODULE_DNS=1)
      target_link_libraries(ftun-dns-query-binding-test PRIVATE
        ftun_runtime ftun_options Threads::Threads)
      if(FTUN_STATIC)
        target_link_options(ftun-dns-query-binding-test PRIVATE -static)
      endif()
      add_test(NAME dns-query-binding-contract COMMAND ftun-dns-query-binding-test)
      add_executable(ftun-dns-dispatch-test tests/unit/core/config/test_dns_dispatch.c)
      target_include_directories(ftun-dns-dispatch-test PRIVATE src)
      target_link_libraries(ftun-dns-dispatch-test PRIVATE ftun_runtime ftun_options)
      if(FTUN_STATIC)
        target_link_options(ftun-dns-dispatch-test PRIVATE -static)
      endif()
      add_test(NAME dns-dispatch-contract COMMAND ftun-dns-dispatch-test)
      add_executable(ftun-dns-listener-test tests/unit/core/test_dns_listener.c)
      target_include_directories(ftun-dns-listener-test PRIVATE src)
      target_link_libraries(ftun-dns-listener-test PRIVATE ftun_runtime ftun_options)
      if(FTUN_STATIC)
        target_link_options(ftun-dns-listener-test PRIVATE -static)
      endif()
      add_test(NAME dns-listener-contract COMMAND ftun-dns-listener-test)
      add_executable(ftun-v03-integration-test tests/unit/core/config/test_integration_v03.c)
      target_include_directories(ftun-v03-integration-test PRIVATE src)
      target_link_libraries(ftun-v03-integration-test PRIVATE
        ftun_runtime ftun_options Threads::Threads)
      if(FTUN_STATIC)
        target_link_options(ftun-v03-integration-test PRIVATE -static)
      endif()
      add_test(NAME integration-v03-contract COMMAND ftun-v03-integration-test)
    endif()
    add_executable(ftun-dns-wire-test tests/unit/libs/resolver/test_dns_wire.c)
    target_include_directories(ftun-dns-wire-test PRIVATE src)
    target_link_libraries(ftun-dns-wire-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-dns-wire-test PRIVATE -static)
    endif()
    add_test(NAME dns-wire-contract COMMAND ftun-dns-wire-test)
    add_executable(ftun-dns-bootstrap-test tests/unit/core/test_dns_bootstrap.c)
    target_include_directories(ftun-dns-bootstrap-test PRIVATE src)
    target_link_libraries(ftun-dns-bootstrap-test PRIVATE
      ftun_runtime ftun_options Threads::Threads)
    if(FTUN_STATIC)
      target_link_options(ftun-dns-bootstrap-test PRIVATE -static)
    endif()
    add_test(NAME dns-bootstrap-contract COMMAND ftun-dns-bootstrap-test)
    if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
      add_executable(ftun-dns-resolver-test tests/unit/core/config/test_dns_resolver.c)
      target_include_directories(ftun-dns-resolver-test PRIVATE src)
      target_link_libraries(ftun-dns-resolver-test PRIVATE ftun_runtime ftun_options)
      if(FTUN_STATIC)
        target_link_options(ftun-dns-resolver-test PRIVATE -static)
      endif()
      add_test(NAME dns-resolver-contract COMMAND ftun-dns-resolver-test)
    endif()
  endif()
  if(FTUN_MODULE_TUN STREQUAL "BUILTIN")
    add_executable(ftun-platform-linux-tun-test tests/unit/libs/tun/linux/test_platform_linux_tun.c)
    target_include_directories(ftun-platform-linux-tun-test PRIVATE src)
    target_link_libraries(ftun-platform-linux-tun-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-platform-linux-tun-test PRIVATE -static)
    endif()
    add_test(NAME platform-linux-tun COMMAND ftun-platform-linux-tun-test)
    add_executable(ftun-platform-linux-route-test tests/unit/libs/tun/linux/test_platform_linux_route.c)
    target_link_options(ftun-platform-linux-route-test PRIVATE -Wl,--wrap=ftun_platform_route_prepare)
    target_include_directories(ftun-platform-linux-route-test PRIVATE src)
    target_link_libraries(ftun-platform-linux-route-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-platform-linux-route-test PRIVATE -static)
    endif()
    add_test(NAME platform-linux-route COMMAND ftun-platform-linux-route-test)
    add_executable(ftun-platform-linux-route-async-test
      tests/unit/libs/tun/linux/test_platform_linux_route_async.c)
    target_include_directories(ftun-platform-linux-route-async-test PRIVATE src)
    target_link_libraries(ftun-platform-linux-route-async-test PRIVATE
      ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-platform-linux-route-async-test PRIVATE -static)
    endif()
    add_test(NAME platform-linux-route-async
      COMMAND ftun-platform-linux-route-async-test)
    add_executable(ftun-tun-port-test tests/unit/libs/tun/linux/test_tun_port.c)
    target_include_directories(ftun-tun-port-test PRIVATE src)
    target_link_libraries(ftun-tun-port-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-tun-port-test PRIVATE -static)
    endif()
    add_test(NAME tun-packet-port COMMAND ftun-tun-port-test)
    add_executable(ftun-tun-service-test tests/unit/libs/tun/test_tun_service.c)
    target_include_directories(ftun-tun-service-test PRIVATE src)
    target_link_libraries(ftun-tun-service-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-tun-service-test PRIVATE -static)
    endif()
    add_test(NAME tun-service-contract COMMAND ftun-tun-service-test)
    add_executable(ftun-tun-owner-test tests/unit/core/config/test_tun_owner.c)
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
      add_executable(ftun-tun-shared-test tests/unit/core/test_tun_shared.c)
      target_include_directories(ftun-tun-shared-test PRIVATE src)
      target_link_libraries(ftun-tun-shared-test PRIVATE ftun_runtime ftun_options)
      if(FTUN_STATIC)
        target_link_options(ftun-tun-shared-test PRIVATE -static)
      endif()
      add_test(NAME tun-shared-consumers-contract COMMAND ftun-tun-shared-test)
    endif()
    add_executable(ftun-tun-path-test tests/unit/libs/tun/test_tun_path.c)
    target_include_directories(ftun-tun-path-test PRIVATE src)
    target_link_libraries(ftun-tun-path-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-tun-path-test PRIVATE -static)
    endif()
    add_test(NAME tun-path-contract COMMAND ftun-tun-path-test)
    if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
      add_executable(ftun-lwip-adapter-test tests/unit/core/test_lwip_adapter.c)
      target_include_directories(ftun-lwip-adapter-test PRIVATE src)
      target_link_libraries(ftun-lwip-adapter-test PRIVATE ftun_runtime ftun_options)
      if(FTUN_STATIC)
        target_link_options(ftun-lwip-adapter-test PRIVATE -static)
      endif()
      add_test(NAME tun-lwip-adapter COMMAND ftun-lwip-adapter-test)
      add_executable(ftun-inbound-tun-test tests/unit/core/test_inbound_tun.c)
      target_include_directories(ftun-inbound-tun-test PRIVATE src)
      target_link_libraries(ftun-inbound-tun-test PRIVATE ftun_runtime ftun_options)
      if(FTUN_STATIC)
        target_link_options(ftun-inbound-tun-test PRIVATE -static)
      endif()
      add_test(NAME inbound-tun-contract COMMAND ftun-inbound-tun-test)
      add_executable(ftun-udp-session-test tests/unit/core/config/test_udp_session.c)
      target_include_directories(ftun-udp-session-test PRIVATE src)
      target_link_libraries(ftun-udp-session-test PRIVATE ftun_runtime ftun_options)
      if(FTUN_STATIC)
        target_link_options(ftun-udp-session-test PRIVATE -static)
      endif()
      add_test(NAME tun-udp-flow-contract COMMAND ftun-udp-session-test)
    endif()
    if(UNIX AND FTUN_MODULE_PROXY STREQUAL "BUILTIN")
      add_executable(ftun-linux-integration-test tests/unit/core/config/test_integration_linux.c)
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
        if(FTUN_SANITIZERS OR FTUN_TSAN)
          # ASan reserves and commits shadow/quarantine pages which are not part
          # of the production memory budget. Keep the same 32-flow functional
          # pressure while applying the 64 MiB gate only to release binaries.
          set_tests_properties(release-linux-production PROPERTIES
            ENVIRONMENT "FTUN_RELEASE_RESOURCE_LIMIT_KIB=262144")
        endif()
        add_executable(ftun-send-eagain-test
          src/app/main.c tests/support/send_eagain_wrap.c)
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
    add_executable(ftun-time-test tests/unit/platform/test_monotonic_time.c)
    target_include_directories(ftun-time-test PRIVATE src)
    target_link_libraries(ftun-time-test PRIVATE ftun_runtime ftun_options)
    if(FTUN_STATIC)
      target_link_options(ftun-time-test PRIVATE -static)
    endif()
    add_test(NAME monotonic-time COMMAND ftun-time-test)
  endif()
  if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
    add_executable(ftun-performance-test bench/bench_ftun.c)
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
    if(TARGET ftun AND FTUN_MODULE_PROXY STREQUAL "BUILTIN" AND FTUN_MODULE_DNS STREQUAL "BUILTIN")
    add_test(NAME egress-resolution-production COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/egress_resolution_product.py $<TARGET_FILE:ftun>)
    set_tests_properties(egress-resolution-production PROPERTIES
      SKIP_RETURN_CODE 77 TIMEOUT 45 RESOURCE_LOCK ftun_host_socket)
    add_test(NAME ipv6-product COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/ipv6_product.py $<TARGET_FILE:ftun>)
    set_tests_properties(ipv6-product PROPERTIES
      SKIP_RETURN_CODE 77 TIMEOUT 60 RESOURCE_LOCK ftun_host_socket)
    if(FTUN_MODULE_TUN STREQUAL "BUILTIN")
      add_test(NAME ipv6-tun-production COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/ipv6_tun.py $<TARGET_FILE:ftun>)
      set_tests_properties(ipv6-tun-production PROPERTIES
        SKIP_RETURN_CODE 77 TIMEOUT 60 RESOURCE_LOCK ftun_linux_namespace)
    endif()
    endif()
    add_test(NAME docs-configuration
      COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/docs_configuration.py
        ${CMAKE_CURRENT_SOURCE_DIR}/schema/ftun.schema.json
        ${CMAKE_CURRENT_SOURCE_DIR}/docs/configuration.md)
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
      add_test(NAME ipv6-http-fetch-production COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/ipv6_http_fetch.py $<TARGET_FILE:ftun-http-fetch-test>)
      set_tests_properties(ipv6-http-fetch-production PROPERTIES
        SKIP_RETURN_CODE 77 TIMEOUT 45 RESOURCE_LOCK ftun_host_socket)
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
      if(FTUN_MODULE_FRS STREQUAL "BUILTIN" AND FTUN_MODULE_DNS STREQUAL "BUILTIN" AND
         FTUN_MODULE_TUN STREQUAL "BUILTIN" AND TARGET ftun-v04-frs-test)
        # 恢复契约验收 R1～R12（缩短版）：全部在 unshare 出来的私有网络/挂载命名空间里
        # 运行，不改动宿主网络。退出码 77 表示依赖尚未实现的能力，不是通过。
        foreach(scenario R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14)
          add_test(NAME resilience-${scenario}
            COMMAND ${Python3_EXECUTABLE}
              ${CMAKE_CURRENT_SOURCE_DIR}/tests/resilience/run.py ${scenario}
              --ftun $<TARGET_FILE:ftun>
              --fixture $<TARGET_FILE:ftun-v04-frs-test>)
          set_tests_properties(resilience-${scenario} PROPERTIES
            SKIP_RETURN_CODE 77 TIMEOUT 240 RESOURCE_LOCK ftun_resilience)
        endforeach()
      endif()
      add_test(NAME liveness-product
        COMMAND ${Python3_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/liveness_product.py
          $<TARGET_FILE:ftun>)
      set_tests_properties(liveness-product PROPERTIES
        SKIP_RETURN_CODE 77 TIMEOUT 45 RESOURCE_LOCK ftun_host_socket)
      if(FTUN_MODULE_DNS STREQUAL "BUILTIN")
        add_test(NAME dns-failover-product
          COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/dns_failover_product.py
            $<TARGET_FILE:ftun>)
        set_tests_properties(dns-failover-product PROPERTIES
          TIMEOUT 60 RESOURCE_LOCK ftun_host_socket)
      endif()
      add_test(NAME log-rotation-product
        COMMAND ${Python3_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/log_rotation_product.py
          $<TARGET_FILE:ftun>)
      set_tests_properties(log-rotation-product PROPERTIES
        TIMEOUT 60 RESOURCE_LOCK ftun_host_socket)
      add_test(NAME watchdog-product
        COMMAND ${Python3_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/watchdog_product.py
          $<TARGET_FILE:ftun>)
      set_tests_properties(watchdog-product PROPERTIES
        TIMEOUT 45 RESOURCE_LOCK ftun_host_socket)
      if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
        add_test(NAME frs-offline-product
          COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/frs_offline_product.py
            $<TARGET_FILE:ftun> $<TARGET_FILE:ftun-v04-frs-test>)
        set_tests_properties(frs-offline-product PROPERTIES
          TIMEOUT 60 RESOURCE_LOCK ftun_host_socket)
      endif()
      if(FTUN_MODULE_FRS STREQUAL "BUILTIN")
        add_test(NAME frs-reload-generation-product
          COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/frs_reload_generation.py
            $<TARGET_FILE:ftun>)
        set_tests_properties(frs-reload-generation-product PROPERTIES
          TIMEOUT 45 RESOURCE_LOCK ftun_host_socket)
      endif()
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
)
    add_test(NAME structure-boundaries-illegal-include
      COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/structure_boundaries.py
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json
        ${CMAKE_CURRENT_BINARY_DIR}/ftun-build-targets.txt
 --self-test illegal-include)
    add_test(NAME structure-boundaries-illegal-source
      COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/structure_boundaries.py
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json
        ${CMAKE_CURRENT_BINARY_DIR}/ftun-build-targets.txt
 --self-test illegal-source)
    add_test(NAME dependency-lock
      COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/dependency_lock.py
        ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_COMMAND})
    add_test(NAME cross-build-contract
      COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/cross_build_contract.py
        ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_COMMAND})
    add_test(NAME config-schema COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/config_schema.py)
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
          ${ftun_expect_static}
          ${FTUN_HARDENING}
          ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json
          ${CMAKE_CURRENT_SOURCE_DIR}
          $<CONFIG>)
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
  # 这几个测试自己先绑定再释放端口号，与其他占用端口的测试并行时可能被抢走。
  foreach(ftun_port_test IN ITEMS service-runtime-stop-contract
          dns-service-independent-contract dns-service-failures-contract
          service-leaf-cleanup-contract)
    if(TEST ${ftun_port_test})
      set_property(TEST ${ftun_port_test} APPEND PROPERTY RESOURCE_LOCK ftun_host_socket)
    endif()
  endforeach()
  # 工程检查不能因运行环境或工具故障无限阻塞。
  get_property(ftun_tests DIRECTORY PROPERTY TESTS)
  set_tests_properties(${ftun_tests} PROPERTIES TIMEOUT 30)
  set_tests_properties(build-modules-matrix PROPERTIES TIMEOUT 900)
  foreach(ftun_fuzz_name IN LISTS ftun_fuzz_targets)
    if(TEST fuzz-${ftun_fuzz_name})
      set_tests_properties(fuzz-${ftun_fuzz_name} PROPERTIES TIMEOUT 300)
    endif()
  endforeach()
  # 恢复契约场景要等退避与网络变化，单个场景可能超过 30 秒。
  foreach(scenario R1 R2 R3 R4 R5 R6 R7 R8 R9 R10 R11 R12 R14)
    if(TEST resilience-${scenario})
      set_tests_properties(resilience-${scenario} PROPERTIES TIMEOUT 240)
    endif()
  endforeach()
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
if(BUILD_TESTING)
  add_test(NAME c-api-installed-package COMMAND ${CMAKE_COMMAND}
    -DFTUN_SOURCE_DIR=${PROJECT_SOURCE_DIR} -DFTUN_BUILD_DIR=${CMAKE_BINARY_DIR}
    -DFTUN_COMPILER=${CMAKE_C_COMPILER}
    -P ${PROJECT_SOURCE_DIR}/tests/abi/installed_package.cmake)
endif()
if(BUILD_TESTING)
  add_executable(ftun-config-document-test tests/unit/core/config/test_document.c)
  target_link_libraries(ftun-config-document-test PRIVATE ftun_core)
  add_test(NAME config-document-contract COMMAND ftun-config-document-test)
endif()
if(BUILD_TESTING)
  add_executable(ftun-config-sections-test tests/unit/app/config/test_sections.c)
  target_link_libraries(ftun-config-sections-test PRIVATE ftun_dns_config ftun_proxy_config ftun_lib_tun_config)
  add_test(NAME config-sections-contract COMMAND ftun-config-sections-test)
endif()

if(BUILD_TESTING)
  add_executable(ftun-platform-thread-test tests/unit/platform/test_thread.c)
  target_link_libraries(ftun-platform-thread-test PRIVATE ftun_platform)
  target_link_options(ftun-platform-thread-test PRIVATE
    -Wl,--wrap=pthread_condattr_init -Wl,--wrap=pthread_condattr_setclock
    -Wl,--wrap=pthread_condattr_destroy -Wl,--wrap=pthread_cond_init
    -Wl,--wrap=pthread_create -Wl,--wrap=pthread_detach)
  add_test(NAME platform-thread-contract COMMAND ftun-platform-thread-test)
  set_tests_properties(platform-thread-contract PROPERTIES TIMEOUT 5)
endif()
if(BUILD_TESTING)
  add_executable(ftun-platform-atomic-test tests/unit/platform/test_atomic.c)
  target_link_libraries(ftun-platform-atomic-test PRIVATE ftun_platform)
  add_test(NAME platform-atomic-contract COMMAND ftun-platform-atomic-test)
  set_tests_properties(platform-atomic-contract PROPERTIES TIMEOUT 5)
endif()
if(BUILD_TESTING)
  add_executable(ftun-platform-file-primitives-test tests/unit/platform/test_file.c)
  target_link_libraries(ftun-platform-file-primitives-test PRIVATE ftun_platform)
  target_link_options(ftun-platform-file-primitives-test PRIVATE -Wl,--wrap=write)
  add_test(NAME platform-file-primitives-contract COMMAND ftun-platform-file-primitives-test)
endif()
if(BUILD_TESTING AND FTUN_MODULE_PROXY STREQUAL "BUILTIN" AND FTUN_MODULE_FAKEIP STREQUAL "BUILTIN")
  add_executable(ftun-fakeip-stop-deadline-test tests/unit/proxy/test_fakeip_stop_deadline.c)
  foreach(module PROXY DNS FAKEIP TUN FRS)
    if(FTUN_MODULE_${module} STREQUAL "BUILTIN")
      target_compile_definitions(ftun-fakeip-stop-deadline-test PRIVATE FTUN_HAVE_MODULE_${module}=1)
    endif()
  endforeach()
  target_link_libraries(ftun-fakeip-stop-deadline-test PRIVATE ftun_proxy)
  target_link_options(ftun-fakeip-stop-deadline-test PRIVATE
    -Wl,--wrap=ftun_monotonic_now -Wl,--wrap=ftun_worker_poll
    -Wl,--wrap=ftun_operation_cancel -Wl,--wrap=ftun_file_write_atomic_budget)
  add_test(NAME fakeip-stop-deadline-contract COMMAND ftun-fakeip-stop-deadline-test)
  set_tests_properties(fakeip-stop-deadline-contract PROPERTIES TIMEOUT 10)
endif()

if(BUILD_TESTING)
  add_executable(ftun-config-views-test tests/unit/libs/transport/test_config_views.c)
  target_link_libraries(ftun-config-views-test PRIVATE ftun_lib_transport ftun_lib_resolver)
  add_test(NAME config-views-contract COMMAND ftun-config-views-test)
endif()
