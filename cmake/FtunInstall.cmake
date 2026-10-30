install(TARGETS ftun ftun_runtime ftun_options ${ftun_layer_targets} EXPORT FTUNTargets RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS ftun_cjson EXPORT FTUNTargets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
if(FTUN_MODULE_PROXY STREQUAL "BUILTIN")
  install(TARGETS wolfssl EXPORT FTUNTargets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()
if(TARGET ftun_lwip)
  install(TARGETS ftun_lwip EXPORT FTUNTargets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
  install(FILES third_party/lwip/LICENSE
    DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/ftun RENAME LICENSE-lwIP)
endif()
install(FILES third_party/cjson/LICENSE
  DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/ftun RENAME LICENSE-cJSON)
install(FILES third_party/wolfssl/COPYING
  DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/ftun RENAME LICENSE-wolfSSL)
if(WIN32)
  install(FILES third_party/wepoll/LICENSE
    DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/ftun RENAME LICENSE-wepoll)
endif()
install(DIRECTORY include/ftun DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
set(FTUN_DEPENDENCY_LOCK "${CMAKE_CURRENT_SOURCE_DIR}/third_party/LOCK.json")
set(FTUN_NOTICES_OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/THIRD_PARTY_NOTICES.md")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${FTUN_DEPENDENCY_LOCK}")
include(cmake/ThirdPartyNotices.cmake)
install(FILES LICENSE README.md "${FTUN_NOTICES_OUTPUT}" third_party/LOCK.json
  DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/ftun)
install(DIRECTORY docs DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/ftun
  FILES_MATCHING PATTERN "*.md")
configure_file(cmake/uninstall.cmake.in uninstall.cmake @ONLY)
add_custom_target(uninstall COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/uninstall.cmake)

install(FILES third_party/README.md
  DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/ftun RENAME README-third-party.md)

set_target_properties(ftun_runtime PROPERTIES EXPORT_NAME Runtime)
include(CMakePackageConfigHelpers)
configure_package_config_file(cmake/FTUNConfig.cmake.in
  "${CMAKE_BINARY_DIR}/FTUNConfig.cmake"
  INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/FTUN")
write_basic_package_version_file("${CMAKE_BINARY_DIR}/FTUNConfigVersion.cmake"
  VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
install(EXPORT FTUNTargets NAMESPACE FTUN:: DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/FTUN")
install(FILES "${CMAKE_BINARY_DIR}/FTUNConfig.cmake" "${CMAKE_BINARY_DIR}/FTUNConfigVersion.cmake"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/FTUN")

# 发行工具链注入的编译器运行库和C运行库也随程序保留原始许可。
if(DEFINED FTUN_ZIG)
  get_filename_component(ftun_zig_root "${FTUN_ZIG}" DIRECTORY)
  file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/toolchain-licenses")
  configure_file("${ftun_zig_root}/LICENSE"
    "${CMAKE_BINARY_DIR}/toolchain-licenses/LICENSE-Zig" COPYONLY)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    configure_file("${ftun_zig_root}/lib/libc/musl/COPYRIGHT"
      "${CMAKE_BINARY_DIR}/toolchain-licenses/LICENSE-musl-libc" COPYONLY)
  elseif(WIN32)
    configure_file("${ftun_zig_root}/lib/libc/mingw/COPYING"
      "${CMAKE_BINARY_DIR}/toolchain-licenses/LICENSE-MinGW-w64" COPYONLY)
  endif()
  install(DIRECTORY "${CMAKE_BINARY_DIR}/toolchain-licenses/"
    DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/ftun)
endif()

include(cmake/FtunWintun.cmake)
