# ARM/OpenWrt 交叉构建必须显式给出同一 SDK 的编译器、sysroot 和归档工具。
# 不从 PATH 猜测工具，防止宿主头文件、库或 binutils 混入目标产物。
set(CMAKE_SYSTEM_NAME Linux)

function(ftun_openwrt_input name output)
  if(DEFINED ${name} AND NOT "${${name}}" STREQUAL "")
    set(value "${${name}}")
  elseif(DEFINED ENV{${name}} AND NOT "$ENV{${name}}" STREQUAL "")
    set(value "$ENV{${name}}")
  else()
    message(FATAL_ERROR
      "${name} is required for the linux-openwrt-arm toolchain")
  endif()
  set(${output} "${value}" PARENT_SCOPE)
endfunction()

function(ftun_openwrt_file name output)
  ftun_openwrt_input(${name} value)
  if(NOT IS_ABSOLUTE "${value}" OR NOT EXISTS "${value}")
    message(FATAL_ERROR "${name} must be an existing absolute path: ${value}")
  endif()
  set(${output} "${value}" PARENT_SCOPE)
endfunction()

ftun_openwrt_input(FTUN_OPENWRT_PROCESSOR ftun_openwrt_processor)
if(NOT ftun_openwrt_processor MATCHES "^(arm|armv7|aarch64)$")
  message(FATAL_ERROR
    "FTUN_OPENWRT_PROCESSOR must be arm, armv7 or aarch64")
endif()
set(FTUN_OPENWRT_PROCESSOR "${ftun_openwrt_processor}" CACHE STRING
  "ARM processor name used by the OpenWrt SDK" FORCE)
set(CMAKE_SYSTEM_PROCESSOR "${ftun_openwrt_processor}")

ftun_openwrt_file(FTUN_OPENWRT_CC ftun_openwrt_cc)
ftun_openwrt_file(FTUN_OPENWRT_AR ftun_openwrt_ar)
ftun_openwrt_file(FTUN_OPENWRT_RANLIB ftun_openwrt_ranlib)
ftun_openwrt_file(FTUN_OPENWRT_SYSROOT ftun_openwrt_sysroot)
if(NOT IS_DIRECTORY "${ftun_openwrt_sysroot}")
  message(FATAL_ERROR
    "FTUN_OPENWRT_SYSROOT must name the target sysroot directory")
endif()
execute_process(
  COMMAND "${ftun_openwrt_cc}" -dumpmachine
  RESULT_VARIABLE ftun_openwrt_dump_result
  OUTPUT_VARIABLE ftun_openwrt_machine
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET)
if(NOT ftun_openwrt_dump_result EQUAL 0 OR
   NOT ftun_openwrt_machine MATCHES "(^|[-_])(arm|armv[0-9]*|aarch64)([-_]|$)")
  message(FATAL_ERROR
    "FTUN_OPENWRT_CC does not target ARM: ${ftun_openwrt_machine}")
endif()
set(FTUN_OPENWRT_CC "${ftun_openwrt_cc}" CACHE FILEPATH
  "OpenWrt target C compiler" FORCE)
set(FTUN_OPENWRT_AR "${ftun_openwrt_ar}" CACHE FILEPATH
  "OpenWrt target archiver" FORCE)
set(FTUN_OPENWRT_RANLIB "${ftun_openwrt_ranlib}" CACHE FILEPATH
  "OpenWrt target ranlib" FORCE)
set(FTUN_OPENWRT_SYSROOT "${ftun_openwrt_sysroot}" CACHE PATH
  "OpenWrt target sysroot" FORCE)

set(CMAKE_C_COMPILER "${ftun_openwrt_cc}")
set(CMAKE_C_COMPILER_AR "${ftun_openwrt_ar}")
set(CMAKE_C_COMPILER_RANLIB "${ftun_openwrt_ranlib}")
set(CMAKE_AR "${ftun_openwrt_ar}")
set(CMAKE_RANLIB "${ftun_openwrt_ranlib}")
set(CMAKE_SYSROOT "${ftun_openwrt_sysroot}")
set(CMAKE_FIND_ROOT_PATH "${ftun_openwrt_sysroot}")

if((DEFINED FTUN_OPENWRT_STRIP AND NOT "${FTUN_OPENWRT_STRIP}" STREQUAL "") OR
   (DEFINED ENV{FTUN_OPENWRT_STRIP} AND NOT "$ENV{FTUN_OPENWRT_STRIP}" STREQUAL ""))
  ftun_openwrt_file(FTUN_OPENWRT_STRIP ftun_openwrt_strip)
  set(CMAKE_STRIP "${ftun_openwrt_strip}")
endif()

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES
  FTUN_OPENWRT_PROCESSOR FTUN_OPENWRT_CC FTUN_OPENWRT_AR
  FTUN_OPENWRT_RANLIB FTUN_OPENWRT_SYSROOT FTUN_OPENWRT_STRIP)
