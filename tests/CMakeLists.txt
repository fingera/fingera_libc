
# download google test
configure_file(
    cmake/googletest.CMakeLists.txt.in
    googletest-download/CMakeLists.txt)

# generate cmake build
execute_process(
    COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
    RESULT_VARIABLE result
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/tests/googletest-download)

if(result)
    message(FATAL_ERROR "CMake step for googletest failed: ${result}")
endif()

# build gtest
execute_process(
    COMMAND ${CMAKE_COMMAND} --build .
    RESULT_VARIABLE result
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/tests/googletest-download)

if(result)
    message(FATAL_ERROR "Build step for googletest failed: ${result}")
endif()


# Prevent overriding the parent project's compiler/linker settings on
# Windows.
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

# Add googletest directly to our build. This defines the gtest and
# gtest_main targets.
add_subdirectory(${CMAKE_BINARY_DIR}/googletest-src
                    ${CMAKE_BINARY_DIR}/googletest-build
                    EXCLUDE_FROM_ALL)

# link gtest
link_libraries(gtest gtest_main)



add_executable( hex_test hex.cpp )
target_link_libraries( hex_test fingera_libc )
add_test(NAME hex_test COMMAND hex_test)

add_executable( base64_test base64.cpp )
target_link_libraries( base64_test fingera_libc )
add_test(NAME base64_test COMMAND base64_test)

add_executable( compress_integer_test compress_integer.cpp )
target_link_libraries( compress_integer_test fingera_libc )
add_test(NAME compress_integer_test COMMAND compress_integer_test)

