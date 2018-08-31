

add_executable( test_fingera 
  hex.cpp
  base64.cpp
  compress_integer.cpp
  hash.cpp
  base32.cpp
  base58.cpp
  btc/bech32.cpp
  btc/btc_bech32.cpp
  btc/address.cpp
  random.cpp
  btc/key.cpp
)

target_link_libraries( test_fingera fingera_libc gtest_main )
add_test(NAME test_fingera COMMAND test_fingera)

if (${BUILD_VALGRIND} STREQUAL "ON")
  find_program(VALGRIND "valgrind")
  if(VALGRIND)
    add_custom_target(valgrind
        COMMAND "${VALGRIND}" --leak-check=full --track-fds=yes $<TARGET_FILE:test_fingera>)
  endif()
endif()
