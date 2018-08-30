
add_executable( hex_test hex.cpp )
target_link_libraries( hex_test fingera_libc gtest_main )
add_test(NAME hex_test COMMAND hex_test)

add_executable( base64_test base64.cpp )
target_link_libraries( base64_test fingera_libc gtest_main )
add_test(NAME base64_test COMMAND base64_test)

add_executable( compress_integer_test compress_integer.cpp )
target_link_libraries( compress_integer_test fingera_libc gtest_main )
add_test(NAME compress_integer_test COMMAND compress_integer_test)

add_executable( hash_test hash.cpp )
target_link_libraries( hash_test fingera_libc gtest_main )
add_test(NAME hash_test COMMAND hash_test)

add_executable( base32_test base32.cpp )
target_link_libraries( base32_test fingera_libc gtest_main )
add_test(NAME base32_test COMMAND base32_test)

add_executable( base58_test base58.cpp )
target_link_libraries( base58_test fingera_libc gtest_main )
add_test(NAME base58_test COMMAND base58_test)

add_executable( bech32_test btc/bech32.cpp btc/btc_bech32.cpp )
target_link_libraries( bech32_test fingera_libc gtest_main )
add_test(NAME bech32_test COMMAND bech32_test)

add_executable( address_test btc/address.cpp )
target_link_libraries( address_test fingera_libc gtest_main )
add_test(NAME address_test COMMAND address_test)

add_executable( random_test random.cpp )
target_link_libraries( random_test fingera_libc gtest_main )
add_test(NAME random_test COMMAND random_test)

add_executable( key_test btc/key.cpp )
target_link_libraries( key_test fingera_libc gtest_main )
add_test(NAME key_test COMMAND key_test)

