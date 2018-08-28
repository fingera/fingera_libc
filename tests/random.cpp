#include <fingera_libc/error.h>
#include <fingera_libc/hex.h>
#include <fingera_libc/random.h>

#include <gtest/gtest.h>
#include <stdint.h>
#include <stdio.h>
#include <string>

TEST(random, custom) {
  char buffer[32] = {0};
  char zero[32] = {0};
  fingera_os_rand_bytes(buffer, sizeof(buffer));
  fingera_hex_dump(buffer, sizeof(buffer), 1);
  EXPECT_NE(memcmp(buffer, zero, sizeof(zero)), 0);
}