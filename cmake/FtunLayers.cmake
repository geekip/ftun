function(ftun_add_layer name)
  add_library(ftun_${name} STATIC ${ftun_sources_${name}})
  file(RELATIVE_PATH prefix "${PROJECT_SOURCE_DIR}/src" "${CMAKE_CURRENT_SOURCE_DIR}")
  set(exports "${CMAKE_BINARY_DIR}/headers/ftun_${name}")
  get_filename_component(parent "${exports}/${prefix}" DIRECTORY)
  file(MAKE_DIRECTORY "${parent}")
  file(CREATE_LINK "${CMAKE_CURRENT_SOURCE_DIR}" "${exports}/${prefix}" SYMBOLIC)
  target_include_directories(ftun_${name} PUBLIC
    "$<BUILD_INTERFACE:${exports}>"
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:include>"
    )
  target_link_libraries(ftun_${name} PUBLIC ftun_options ${ARGN})
  target_compile_definitions(ftun_${name} PRIVATE ${ftun_module_definitions} FTUN_HAVE_EPOLL=1)
  if(FTUN_LTO)
    set_property(TARGET ftun_${name} PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
  endif()
endfunction()
