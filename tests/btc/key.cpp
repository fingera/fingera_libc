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
  uint8_t priv_key_compress[BTC_COMPRESSED_PRIVATE_KEY_SIZE];
  uint8_t priv_key[BTC_PRIVATE_KEY_SIZE];
  uint8_t out_key[32];
  uint8_t pub_key_compress[BTC_COMPRESSED_PUBLIC_KEY_SIZE];
  uint8_t pub_key[BTC_PUBLIC_KEY_SIZE];
  uint8_t out_pub_key[64];
  uint8_t signature_enc[BTC_SIGNATURE_SIZE];
  uint8_t out_signature[64];
  fingera_os_rand_bytes(msg, 32);
  fingera_btc_key_new(key);
  fingera_btc_key_get_pub(key, pubkey);
  fingera_btc_key_sign(key, msg, signature);
  EXPECT_TRUE(fingera_btc_key_verify(pubkey, msg, signature));
  /*
  fingera_hex_dump(key, 32, 1);
  fingera_hex_dump(pubkey, 64, 1);
  fingera_hex_dump(msg, 32, 1);
  fingera_hex_dump(signature, 64, 1);
  */
  EXPECT_TRUE(fingera_btc_key_encode(key, priv_key_compress,
                                     sizeof(priv_key_compress)));
  EXPECT_TRUE(fingera_btc_key_encode(key, priv_key, sizeof(priv_key)));
  EXPECT_TRUE(fingera_btc_key_decode(priv_key_compress,
                                     sizeof(priv_key_compress), out_key));
  EXPECT_FALSE(memcmp(out_key, key, sizeof(key)));
  EXPECT_TRUE(fingera_btc_key_decode(priv_key, sizeof(priv_key), out_key));
  EXPECT_FALSE(memcmp(out_key, key, sizeof(key)));

  EXPECT_TRUE(fingera_btc_pubkey_encode(pubkey, pub_key_compress,
                                        sizeof(pub_key_compress)));
  EXPECT_TRUE(fingera_btc_pubkey_encode(pubkey, pub_key, sizeof(pub_key)));
  EXPECT_TRUE(fingera_btc_pubkey_decode(pub_key_compress,
                                        sizeof(pub_key_compress), out_pub_key));
  EXPECT_FALSE(memcmp(out_pub_key, pubkey, sizeof(pubkey)));
  EXPECT_TRUE(fingera_btc_pubkey_decode(pub_key, sizeof(pub_key), out_pub_key));
  EXPECT_FALSE(memcmp(out_pub_key, pubkey, sizeof(pubkey)));

  size_t enc_len = fingera_btc_signature_encode(signature, signature_enc);
  EXPECT_TRUE(enc_len > 0);
  EXPECT_TRUE(
      fingera_btc_signature_decode(signature_enc, enc_len, out_signature));
  EXPECT_FALSE(memcmp(out_signature, signature, sizeof(signature)));

  memset(signature, 0, sizeof(signature));
  EXPECT_TRUE(!fingera_btc_key_verify(pubkey, msg, signature));

  fingera_btc_key_uninit();
}