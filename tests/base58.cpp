#include <fingera_libc/base58.h>
#include <fingera_libc/hex.h>

#include <gtest/gtest.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <vector>

#define EXPECT_ZERO(x) EXPECT_EQ((x), 0)

static void encdec_test(const std::string& hex, const std::string& encoded) {
  std::vector<uint8_t> data;
  data.resize(hex.size() / 2);
  EXPECT_EQ(fingera_from_hex(hex.c_str(), hex.size(), data.data()),
            data.size());
  char out_char[4096];
  EXPECT_TRUE(fingera_to_base58_length(data.size()) < sizeof(out_char));
  if (fingera_to_base58_length(data.size()) < sizeof(out_char)) {
    size_t out_size = fingera_to_base58(data.data(), data.size(), out_char);
    EXPECT_TRUE(out_size < sizeof(out_char));
    out_char[out_size] = '\0';
    EXPECT_EQ(encoded, out_char);
    EXPECT_EQ(encoded.size(), out_size);

    uint8_t out_data[4096];
    EXPECT_TRUE(fingera_from_base58_length(out_size) < sizeof(out_data));
    if (fingera_from_base58_length(out_size) < sizeof(out_data)) {
      size_t data_size = fingera_from_base58(out_char, out_size, out_data);
      EXPECT_EQ(data_size, data.size());
      if (data.data()) {
        EXPECT_ZERO(memcmp(out_data, data.data(), data_size));
      }
    }
  }
}

TEST(base58, custom) {
  const static uint8_t buffer[] = {
      0x03, 0x1b, 0xab, 0x84, 0xe6, 0x87, 0xe3, 0x65, 0x14, 0xee, 0xaf,
      0x5a, 0x01, 0x7c, 0x30, 0xd3, 0x2c, 0x1f, 0x59, 0xdd, 0x4e, 0xa6,
      0x62, 0x9d, 0xa7, 0x97, 0x0c, 0xa3, 0x74, 0x51, 0x3d, 0xd0, 0x06};
  std::string result = "vYxp6yFC7qiVtK1RcGQQt3L6EqTc8YhEDLnSMLqDvp8D";
  char out_char[256];
  memset(out_char, 0, sizeof(out_char));
  EXPECT_EQ(fingera_to_base58(buffer, sizeof(buffer), out_char), result.size());
  EXPECT_EQ(result, out_char);
  size_t out_char_size =
      fingera_from_base58(result.c_str(), result.size(), out_char);
  EXPECT_EQ(out_char_size, sizeof(buffer));
  EXPECT_ZERO(memcmp(out_char, buffer, sizeof(buffer)));

  encdec_test("", "");
  encdec_test("61", "2g");
  encdec_test("626262", "a3gV");
  encdec_test("636363", "aPEr");
  encdec_test("73696d706c792061206c6f6e6720737472696e67",
              "2cFupjhnEsSn59qHXstmK2ffpLv2");
  encdec_test("00eb15231dfceb60925886b67d065299925915aeb172c06647",
              "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L");
  encdec_test("516b6fcd0f", "ABnLTmg");
  encdec_test("bf4f89001e670274dd", "3SEo3LWLoPntC");
  encdec_test("572e4794", "3EFU7m");
  encdec_test("ecac89cad93923c02321", "EJDM8drfXA6uyA");
  encdec_test("10c8511e", "Rt5zm");
  encdec_test("00000000000000000000", "1111111111");
  encdec_test(
      "000111d38e5fc9071ffcd20b4a763cc9ae4f252bb4e48fd66a835e252ada93ff480d6dd4"
      "3dc62a641155a5",
      "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
  encdec_test(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223"
      "2425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647"
      "48494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b"
      "6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"
      "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3"
      "b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7"
      "d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafb"
      "fcfdfeff",
      "1cWB5HCBdLjAuqGGReWE3R3CguuwSjw6RHn39s2yuDRTS5NsBgNiFpWgAnEx6VQi8csexkgY"
      "w3mdYrMHr8x9i7aEwP8kZ7vccXWqKDvGv3u1GxFKPuAkn8JCPPGDMf3vMMnbzm6Nh9zh1gcN"
      "sMvH3ZNLmP5fSG6DGbbi2tuwMWPthr4boWwCxf7ewSgNQeacyozhKDDQQ1qL5fQFUW52QKUZ"
      "DZ5fw3KXNQJMcNTcaB723LchjeKun7MuGW5qyCBZYzA1KjofN1gYBV3NqyhQJ3Ns746GNuf9"
      "N2pQPmHz4xpnSrrfCvy6TVVz5d4PdrjeshsWQwpZsZGzvbdAdN8MKV5QsBDY");
}