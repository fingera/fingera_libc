cmake_minimum_required(VERSION 3.5)

set( CMAKE_C_STANDARD 99 )
set( CMAKE_CXX_STANDARD 11 )

option(BUILD_TESTING "Enable test (depends on googletest)." OFF)
option(BUILD_VALGRIND "Enable valgrind (depends on BUILD_TESTING)." OFF)
option(FINGERA_LIBC_ENABLE_BENCHMARKS "Benchmarks" OFF)

add_library(fingera_libc
  src/hex.c
  src/base64.c
  src/base32.c
  src/base58.c
  src/compress_integer.c
  src/error.c
  src/random.c
  src/cleanse.c
  src/hash/ripemd160.c
  src/hash/sha1.c
  src/hash/sha2.c
  src/btc/hash.c
  src/btc/bech32.c
  src/btc/base58_check.c
  src/btc/chain_parameters.c
  src/btc/address.c
  src/btc/key.c
  src/btc/exkey.c
)

add_subdirectory(external)

target_link_libraries(fingera_libc secp256k1)
target_include_directories(fingera_libc
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if (${BUILD_TESTING} STREQUAL "ON")
  include(CTest)
  add_subdirectory(tests)
endif()

if (${FINGERA_LIBC_ENABLE_BENCHMARKS} STREQUAL "ON")
  add_subdirectory(benchmarks)
endif()