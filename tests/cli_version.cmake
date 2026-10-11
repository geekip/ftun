if(NOT DEFINED FTUN_BINARY OR NOT DEFINED FTUN_EXPECTED_REVISION OR
   NOT DEFINED FTUN_EXPECTED_CAPABILITIES)
  message(FATAL_ERROR "binary, revision and capabilities are required")
endif()

execute_process(
  COMMAND "${FTUN_BINARY}" version
  RESULT_VARIABLE status
  OUTPUT_VARIABLE output
  ERROR_VARIABLE error
  OUTPUT_STRIP_TRAILING_WHITESPACE)
set(expected
  "FTUN 1.0.0\nsource: ${FTUN_EXPECTED_REVISION}\ncapabilities: ${FTUN_EXPECTED_CAPABILITIES}")
if(NOT status EQUAL 0 OR NOT output STREQUAL expected OR NOT error STREQUAL "")
  message(FATAL_ERROR
    "unexpected version output\nexpected:\n${expected}\nactual:\n${output}\nstderr:\n${error}")
endif()
