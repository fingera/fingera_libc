
# google test
if (${BUILD_TESTING} STREQUAL "ON")
  set(BUILD_GMOCK OFF)
  set(BUILD_GTEST ON)
  set(gtest_disable_pthreads ON)
  add_subdirectory(googletest)
endif()

# secp256k1
add_compile_definitions(USE_NUM_NONE=1)
add_compile_definitions(USE_FIELD_INV_BUILTIN=1)
add_compile_definitions(USE_SCALAR_INV_BUILTIN=1)
add_compile_definitions(USE_FIELD_10X26=1)
add_compile_definitions(USE_SCALAR_8X32=1)
add_library(secp256k1 secp256k1/src/secp256k1.c)
target_link_libraries(secp256k1)
target_include_directories(secp256k1
  PUBLIC secp256k1/include secp256k1)