#include <fingera_libc/btc/address.h>
#include <fingera_libc/btc/hash.h>
#include <fingera_libc/btc/key.h>
#include <fingera_libc/hex.h>
#include <fingera_libc/random.h>

#include <gtest/gtest.h>
#include <stdint.h>
#include <stdio.h>
#include <string>

static void test_key(const std::string &encoded, const std::string &hex,
                     const chain_parameters *param, bool compressed = false) {
  EXPECT_TRUE(hex.size() % 2 == 0);
  std::vector<uint8_t> data;
  data.resize(hex.size() / 2);
  EXPECT_EQ(fingera_from_hex(hex.c_str(), hex.size(), data.data()),
            data.size());

  std::vector<uint8_t> decoded;
  int is_compressed;
  decoded.resize(32);
  EXPECT_TRUE(fingera_btc_key_from_string(
      encoded.c_str(), encoded.size(), decoded.data(), &is_compressed, param));
  EXPECT_EQ(data.size(), decoded.size());
  EXPECT_TRUE(memcmp(data.data(), decoded.data(), data.size()) == 0);
  EXPECT_EQ(!compressed, !is_compressed);

  std::string new_encoded;
  new_encoded.resize(fingera_key_string_max_length());
  size_t new_size = fingera_btc_key_to_string(
      data.data(), (char *)new_encoded.c_str(), is_compressed, param);
  EXPECT_EQ(new_size, encoded.size());
  new_encoded.resize(new_size);
  EXPECT_EQ(new_encoded, encoded);
}

TEST(key, string) {
  fingera_btc_key_init();

  test_key("5Kd3NBUAdUnhyzenEwVLy9pBKxSwXvE9FMPyR4UKZvpe6E3AgLr",
           "eddbdc1168f1daeadbd3e44c1e3f8f5a284c2029f78ad26af98583a499de5b19",
           &g_mainnet_chain_parameters);

  test_key("Kz6UJmQACJmLtaQj5A3JAge4kVTNQ8gbvXuwbmCj7bsaabudb3RD",
           "55c9bccb9ed68446d1b75273bbce89d7fe013a8acd1625514420fb2aca1a21c4",
           &g_mainnet_chain_parameters, true);

  test_key("9213qJab2HNEpMpYNBa7wHGFKKbkDn24jpANDs2huN3yi4J11ko",
           "36cb93b9ab1bdabf7fb9f2c04f1b9cc879933530ae7842398eef5a63a56800c2",
           &g_testnet_chain_parameters);

  test_key("9213qJab2HNEpMpYNBa7wHGFKKbkDn24jpANDs2huN3yi4J11ko",
           "36cb93b9ab1bdabf7fb9f2c04f1b9cc879933530ae7842398eef5a63a56800c2",
           &g_regnet_chain_parameters);

  test_key("cTpB4YiyKiBcPxnefsDpbnDxFDffjqJob8wGCEDXxgQ7zQoMXJdH",
           "b9f4892c9e8282028fea1d2667c4dc5213564d41fc5783896a0d843fc15089f3",
           &g_testnet_chain_parameters, true);

  test_key("cTpB4YiyKiBcPxnefsDpbnDxFDffjqJob8wGCEDXxgQ7zQoMXJdH",
           "b9f4892c9e8282028fea1d2667c4dc5213564d41fc5783896a0d843fc15089f3",
           &g_regnet_chain_parameters, true);

  test_key("5K494XZwps2bGyeL71pWid4noiSNA2cfCibrvRWqcHSptoFn7rc",
           "a326b95ebae30164217d7a7f57d72ab2b54e3be64928a19da0210b9568d4015e",
           &g_mainnet_chain_parameters);

  test_key("L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi",
           "7d998b45c219a1e38e99e7cbd312ef67f77a455a9b50c730c27f02c6f730dfb4",
           &g_mainnet_chain_parameters, true);

  test_key("93DVKyFYwSN6wEo3E2fCrFPUp17FtrtNi2Lf7n4G3garFb16CRj",
           "d6bca256b5abc5602ec2e1c121a08b0da2556587430bcf7e1898af2224885203",
           &g_testnet_chain_parameters);

  test_key("5KaBW9vNtWNhc3ZEDyNCiXLPdVPHCikRxSBWwV9NrpLLa4LsXi9",
           "e75d936d56377f432f404aabb406601f892fd49da90eb6ac558a733c93b47252",
           &g_mainnet_chain_parameters);

  test_key("L1axzbSyynNYA8mCAhzxkipKkfHtAXYF4YQnhSKcLV8YXA874fgT",
           "8248bd0375f2f75d7e274ae544fb920f51784480866b102384190b1addfbaa5c",
           &g_mainnet_chain_parameters, true);

  test_key("927CnUkUbasYtDwYwVn2j8GdTuACNnKkjZ1rpZd2yBB1CLcnXpo",
           "44c4f6a096eac5238291a94cc24c01e3b19b8d8cef72874a079e00a242237a52",
           &g_testnet_chain_parameters);

  test_key("cUcfCMRjiQf85YMzzQEk9d1s5A4K7xL5SmBCLrezqXFuTVefyhY7",
           "d1de707020a9059d6d3abaf85e17967c6555151143db13dbb06db78df0f15c69",
           &g_testnet_chain_parameters, true);

  test_key("5HtH6GdcwCJA4ggWEL1B3jzBBUB8HPiBi9SBc5h9i4Wk4PSeApR",
           "091035445ef105fa1bb125eccfb1882f3fe69592265956ade751fd095033d8d0",
           &g_mainnet_chain_parameters);

  test_key("L2xSYmMeVo3Zek3ZTsv9xUrXVAmrWxJ8Ua4cw8pkfbQhcEFhkXT8",
           "ab2b4bcdfc91d34dee0ae2a8c6b6668dadaeb3a88b9859743156f462325187af",
           &g_mainnet_chain_parameters, true);

  test_key("92xFEve1Z9N8Z641KQQS7ByCSb8kGjsDzw6fAmjHN1LZGKQXyMq",
           "b4204389cef18bbe2b353623cbf93e8678fbc92a475b664ae98ed594e6cf0856",
           &g_testnet_chain_parameters);

  test_key("92xFEve1Z9N8Z641KQQS7ByCSb8kGjsDzw6fAmjHN1LZGKQXyMq",
           "b4204389cef18bbe2b353623cbf93e8678fbc92a475b664ae98ed594e6cf0856",
           &g_regnet_chain_parameters);

  test_key("cVM65tdYu1YK37tNoAyGoJTR13VBYFva1vg9FLuPAsJijGvG6NEA",
           "e7b230133f1b5489843260236b06edca25f66adb1be455fbd38d4010d48faeef",
           &g_testnet_chain_parameters, true);

  test_key("5KQmDryMNDcisTzRp3zEq9e4awRmJrEVU1j5vFRTKpRNYPqYrMg",
           "d1fab7ab7385ad26872237f1eb9789aa25cc986bacc695e07ac571d6cdac8bc0",
           &g_mainnet_chain_parameters);

  test_key("L39Fy7AC2Hhj95gh3Yb2AU5YHh1mQSAHgpNixvm27poizcJyLtUi",
           "b0bbede33ef254e8376aceb1510253fc3550efd0fcf84dcd0c9998b288f166b3",
           &g_mainnet_chain_parameters, true);

  test_key("91cTVUcgydqyZLgaANpf1fvL55FH53QMm4BsnCADVNYuWuqdVys",
           "037f4192c630f399d9271e26c575269b1d15be553ea1a7217f0cb8513cef41cb",
           &g_testnet_chain_parameters, false);

  test_key("cQspfSzsgLeiJGB2u8vrAiWpCU4MxUT6JseWo2SjXy4Qbzn2fwDw",
           "6251e205e8ad508bab5596bee086ef16cd4b239e0cc0c5d7c4e6035441e7d5de",
           &g_testnet_chain_parameters, true);

  test_key("5KL6zEaMtPRXZKo1bbMq7JDjjo1bJuQcsgL33je3oY8uSJCR5b4",
           "c7666842503db6dc6ea061f092cfb9c388448629a6fe868d068c42a488b478ae",
           &g_mainnet_chain_parameters);

  test_key("KwV9KAfwbwt51veZWNscRTeZs9CKpojyu1MsPnaKTF5kz69H1UN2",
           "07f0803fc5399e773555ab1e8939907e9badacc17ca129e67a2f5f2ff84351dd",
           &g_mainnet_chain_parameters, true);

  test_key("93N87D6uxSBzwXvpokpzg8FFmfQPmvX4xHoWQe3pLdYpbiwT5YV",
           "ea577acfb5d1d14d3b7b195c321566f12f87d2b77ea3a53f68df7ebf8604a801",
           &g_testnet_chain_parameters);

  test_key("cMxXusSihaX58wpJ3tNuuUcZEQGt6DKJ1wEpxys88FFaQCYjku9h",
           "0b3b34f0958d8a268193a9814da92c3e8b58b4a4378a542863e34ac289cd830c",
           &g_testnet_chain_parameters, true);

  test_key("cTDVKtMGVYWTHCb1AFjmVbEbWjvKpKqKgMaR3QJxToMSQAhmCeTN",
           "a81ca4e8f90181ec4b61b6a7eb998af17b2cb04de8a03b504b9e34c4c61db7d9",
           &g_testnet_chain_parameters, true);
  fingera_btc_key_uninit();
}

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

static const std::string strSecret1 =
    "5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj";
static const std::string strSecret2 =
    "5KC4ejrDjv152FGwP386VD1i2NYc5KkfSMyv1nGy1VGDxGHqVY3";
static const std::string strSecret1C =
    "Kwr371tjA9u2rFSMZjTNun2PXXP3WPZu2afRHTcta6KxEUdm1vEw";
static const std::string strSecret2C =
    "L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g";
static const std::string addr1 = "1QFqqMUD55ZV3PJEJZtaKCsQmjLT6JkjvJ";
static const std::string addr2 = "1F5y5E5FMc5YzdJtB9hLaUe43GDxEKXENJ";
static const std::string addr1C = "1NoJrossxPBKfCHuJXT4HadJrXRE9Fxiqs";
static const std::string addr2C = "1CRj2HyM1CXWzHAXLQtiGLyggNT9WQqsDs";

static const std::string strAddressBad = "1HV9Lc3sNHZxwj4Zk6fB38tEmBryq2cBiF";

// bitcoin/src/key_tests.cpp
static void assert_is_valid(const std::string &key, bool is_valid,
                            bool compressed) {
  uint8_t key32[32];
  int is_compressed;
  int r =
      fingera_btc_key_from_string(key.c_str(), key.size(), key32,
                                  &is_compressed, &g_mainnet_chain_parameters);
  if (!is_valid) {
    EXPECT_FALSE(r);
    return;
  }
  EXPECT_TRUE(r);
  EXPECT_EQ(!is_compressed, !compressed);
}

static void verify_pub_key(const std::string &key,
                           const std::string &compressed_key) {
  uint8_t key32[32], compressed_key32[32];
  int is_compressed;
  EXPECT_TRUE(fingera_btc_key_from_string(key.c_str(), key.size(), key32,
                                          &is_compressed,
                                          &g_mainnet_chain_parameters));
  EXPECT_FALSE(is_compressed);
  EXPECT_TRUE(fingera_btc_key_from_string(
      compressed_key.c_str(), compressed_key.size(), compressed_key32,
      &is_compressed, &g_mainnet_chain_parameters));
  EXPECT_TRUE(is_compressed);
  EXPECT_FALSE(memcmp(key32, compressed_key32, 32));

  uint8_t pubkey[64];
  fingera_btc_key_get_pub(key32, pubkey);

  unsigned char rnd[128];
  fingera_os_rand_bytes(rnd, sizeof(rnd));
  uint8_t hash32[32];
  fingera_btc_hash256(rnd, sizeof(rnd), hash32);

  uint8_t signatures[64];
  fingera_btc_key_sign(key32, hash32, signatures);
  EXPECT_TRUE(fingera_btc_key_verify(pubkey, hash32, signatures));
}

static void verify_address(const std::string &addr, const std::string &key,
                           bool compress) {
  uint8_t key32[32];
  int is_compressed;
  int r =
      fingera_btc_key_from_string(key.c_str(), key.size(), key32,
                                  &is_compressed, &g_mainnet_chain_parameters);
  EXPECT_TRUE(r);
  EXPECT_EQ(!is_compressed, !compress);

  uint8_t buf[64];
  size_t buf_size = sizeof(buf);
  EXPECT_EQ(fingera_btc_address_decode(addr.c_str(), addr.size(), buf,
                                       &buf_size, &g_mainnet_chain_parameters),
            BTC_PUBKEY_ADDRESS);
  EXPECT_EQ(buf_size, 20);

  uint8_t keyid[20];
  fingera_btc_key_keyid(key32, compress ? 1 : 0, keyid);
  EXPECT_FALSE(memcmp(keyid, buf, sizeof(keyid)));
}

TEST(key, key_test1) {
  fingera_btc_key_init();
  assert_is_valid(strSecret1, true, false);
  assert_is_valid(strSecret2, true, false);
  assert_is_valid(strSecret1C, true, true);
  assert_is_valid(strSecret2C, true, true);
  assert_is_valid(strAddressBad, false, true);
  verify_pub_key(strSecret1, strSecret1C);
  verify_pub_key(strSecret2, strSecret2C);

  verify_address(addr1, strSecret1, false);
  verify_address(addr1C, strSecret1C, true);
  verify_address(addr2, strSecret2, false);
  verify_address(addr2C, strSecret2C, true);

  fingera_btc_key_uninit();
}