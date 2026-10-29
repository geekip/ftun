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
install(DIRECTORY include/ftun DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
set(FTUN_DEPENDENCY_LOCK "${CMAKE_CURRENT_SOURCE_DIR}/third_party/LOCK.json")
set(FTUN_NOTICES_OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/THIRD_PARTY_NOTICES.md")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${FTUN_DEPENDENCY_LOCK}")
include(cmake/ThirdPartyNotices.cmake)
install(FILES LICENSE README.md "${FTUN_NOTICES_OUTPUT}" third_party/LOCK.json
  DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/ftun)
configure_file(cmake/uninstall.cmake.in uninstall.cmake @ONLY)
add_custom_target(uninstall COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/uninstall.cmake)

install(FILES third_party/musl/COPYRIGHT DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/ftun RENAME LICENSE-musl)

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
