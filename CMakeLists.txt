cmake_minimum_required(VERSION 3.5)

set( CMAKE_C_STANDARD 99 )
set( CMAKE_CXX_STANDARD 11 )


option(BUILD_TESTING "Enable test (depends on googletest)." OFF)
option(FINGERA_LIBC_ENABLE_BENCHMARKS "Benchmarks" OFF)

add_library(fingera_libc
  src/hex.c
  src/base64.c
)

target_link_libraries(fingera_libc)
target_include_directories(fingera_libc
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if (${BUILD_TESTING} STREQUAL "ON")
  include(CTest)
  add_subdirectory(tests)
endif()

if (${FINGERA_LIBC_ENABLE_BENCHMARKS} STREQUAL "ON")
  add_subdirectory(benchmarks)
endif()