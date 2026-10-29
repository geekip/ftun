set(prefix "${FTUN_BUILD_DIR}/installed-abi")
execute_process(COMMAND "${CMAKE_COMMAND}" --install "${FTUN_BUILD_DIR}" --prefix "${prefix}"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "Install failed: ${output}\n${error}")
endif()
set(consumer "${FTUN_BUILD_DIR}/abi-consumer")
file(MAKE_DIRECTORY "${consumer}")
file(WRITE "${consumer}/CMakeLists.txt"
  "cmake_minimum_required(VERSION 3.21)\nproject(FTUNHost C)\nfind_package(FTUN 1 REQUIRED CONFIG)\nadd_executable(host \"${FTUN_SOURCE_DIR}/tests/abi/installed_host.c\")\ntarget_link_libraries(host PRIVATE FTUN::Runtime)\n")
execute_process(COMMAND "${CMAKE_COMMAND}" -S "${consumer}" -B "${consumer}/build"
  "-DCMAKE_C_COMPILER=${FTUN_COMPILER}" "-DCMAKE_PREFIX_PATH=${prefix}"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "Host configure failed: ${output}\n${error}")
endif()
execute_process(COMMAND "${CMAKE_COMMAND}" --build "${consumer}/build"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "Host build failed: ${output}\n${error}")
endif()
execute_process(COMMAND "${consumer}/build/host" RESULT_VARIABLE result)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "Installed host failed: ${result}")
endif()
