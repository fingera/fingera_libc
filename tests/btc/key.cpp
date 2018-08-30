#include <fingera_libc/btc/key.h>
#include <fingera_libc/hex.h>
#include <fingera_libc/random.h>

#include <gtest/gtest.h>
#include <stdint.h>
#include <stdio.h>
#include <string>

TEST(key, custom) {
  fingera_btc_key_init();

  uint8_t key[32];
  uint8_t pubkey[64];
  uint8_t msg[32];
  uint8_t signature[64];
  fingera_os_rand_bytes(msg, 32);
  fingera_btc_key_new(key);
  fingera_btc_key_get_pub(key, pubkey);
  fingera_btc_key_sign(key, msg, signature);
  EXPECT_TRUE(fingera_btc_key_verify(pubkey, msg, signature));
  fingera_hex_dump(key, 32, 1);
  fingera_hex_dump(pubkey, 64, 1);
  fingera_hex_dump(msg, 32, 1);
  fingera_hex_dump(signature, 64, 1);
  memset(signature, 0, sizeof(signature));
  EXPECT_TRUE(!fingera_btc_key_verify(pubkey, msg, signature));

  fingera_btc_key_uninit();
}