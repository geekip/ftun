execute_process(COMMAND "${FTUN_MATRIX_PYTHON}"
  "${FTUN_SOURCE_DIR}/tests/layering/build_matrix.py"
  --source "${FTUN_SOURCE_DIR}" --build "${FTUN_MATRIX_DIR}"
  --cmake "${CMAKE_COMMAND}" --compiler "${FTUN_MATRIX_COMPILER}"
  --generator "${FTUN_MATRIX_GENERATOR}"
  RESULT_VARIABLE result)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "Module build matrix failed")
endif()
