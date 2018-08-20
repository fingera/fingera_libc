file(GLOB BENCHMARKS "*.cpp" "**/*.cpp")
add_executable( benchmarks ${BENCHMARKS} )
# Install https://github.com/google/benchmark.git
target_link_libraries( benchmarks fingera_libc benchmark benchmark_main pthread )
