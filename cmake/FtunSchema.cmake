set(ftun_schema_dir "${PROJECT_SOURCE_DIR}/schema")
set(ftun_schema_fragments)
foreach(section app core dns proxy)
  list(APPEND ftun_schema_fragments "${ftun_schema_dir}/${section}.schema.json")
endforeach()
set(ftun_schema_output "${CMAKE_BINARY_DIR}/schema/ftun.schema.json")
add_custom_command(OUTPUT "${ftun_schema_output}"
  COMMAND ${CMAKE_COMMAND} "-DFTUN_SCHEMA_DIR=${ftun_schema_dir}"
    "-DFTUN_SCHEMA_OUTPUT=${ftun_schema_output}"
    -P "${PROJECT_SOURCE_DIR}/tools/schema/merge.cmake"
  DEPENDS ${ftun_schema_fragments} "${PROJECT_SOURCE_DIR}/tools/schema/merge.cmake"
  VERBATIM)
add_custom_target(ftun_schema ALL DEPENDS "${ftun_schema_output}")
add_dependencies(ftun ftun_schema)
install(FILES "${ftun_schema_output}" DESTINATION "${CMAKE_INSTALL_DATADIR}/ftun/schema")
if(BUILD_TESTING)
  add_test(NAME config-schema-generated COMMAND ${CMAKE_COMMAND}
    "-DFTUN_SCHEMA_DIR=${ftun_schema_dir}"
    "-DFTUN_SCHEMA_OUTPUT=${ftun_schema_dir}/ftun.schema.json"
    -DFTUN_SCHEMA_CHECK=ON -P "${PROJECT_SOURCE_DIR}/tools/schema/merge.cmake")
endif()
