#include <fingera_libc/hex.h>

#include <benchmark/benchmark.h>

static void to_hex(benchmark::State& state) {
  char buffer[2048];
  char str[4096];
  for (auto _ : state) {
    fingera_to_hex(buffer, sizeof(buffer), str, 1);
    fingera_to_hex(buffer, sizeof(buffer), str, 0);
  }
}

static void from_hex(benchmark::State& state) {
  char buffer[2048];
  char str[4096];
  for (auto _ : state) {
    fingera_from_hex(str, sizeof(str), buffer);
  }
}

BENCHMARK(to_hex);
BENCHMARK(from_hex);
