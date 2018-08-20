#include <fingera_libc/hex.h>

#include <gtest/gtest.h>
#include <stdint.h>
#include <string>

#define EXPECT_ZERO(x) EXPECT_EQ((x), 0)

TEST(hex, exhaustive) {
  uint8_t buf[256];
  std::string result =
      "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223"
      "2425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F4041424344454647"
      "48494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B"
      "6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F"
      "909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3"
      "B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7"
      "D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFB"
      "FCFDFEFF";
  std::string result_lower =
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223"
      "2425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647"
      "48494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b"
      "6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"
      "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3"
      "b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7"
      "d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafb"
      "fcfdfeff";
  for (size_t i = 0; i < 256; i++) {
    buf[i] = static_cast<uint8_t>(i);
  }

  uint8_t out_buf[256];
  char out_result[513];
  char out_result_zero[513] = {0};
  uint8_t out_buf_zero[256] = {0};

  for (size_t i = 0; i < 256; i++) {
    memset(out_result, 0, sizeof(out_result));
    memset(out_buf, 0, sizeof(out_buf));

    fingera_to_hex(buf, i, out_result, 1);
    EXPECT_ZERO(memcmp(out_result, result.c_str(), i * 2));
    EXPECT_ZERO(memcmp(out_result + i * 2, out_result_zero,
                       sizeof(out_result) - i * 2));

    EXPECT_EQ(fingera_from_hex(out_result, i * 2, out_buf), i);
    EXPECT_ZERO(memcmp(out_buf, buf, i));
    EXPECT_ZERO(memcmp(out_buf + i, out_result_zero, sizeof(out_buf) - i));

    memset(out_result, 0, sizeof(out_result));
    memset(out_buf, 0, sizeof(out_buf));

    fingera_to_hex(buf, i, out_result, 0);
    EXPECT_ZERO(memcmp(out_result, result_lower.c_str(), i * 2));
    EXPECT_ZERO(memcmp(out_result + i * 2, out_result_zero,
                       sizeof(out_result) - i * 2));

    EXPECT_EQ(fingera_from_hex(out_result, i * 2, out_buf), i);
    EXPECT_ZERO(memcmp(out_buf, buf, i));
    EXPECT_ZERO(memcmp(out_buf + i, out_result_zero, sizeof(out_buf) - i));
  }
}

TEST(hex, custom) {
  uint8_t buf[256];

  EXPECT_EQ(fingera_from_hex("00112233", 6, buf), 3);
  EXPECT_EQ(fingera_from_hex("00112233", 7, buf), 3);
  EXPECT_EQ(fingera_from_hex("00112233", 8, buf), 4);

  EXPECT_EQ(fingera_from_hex("001122T3", 8, buf), 3);
  EXPECT_EQ(fingera_from_hex("0011223T", 8, buf), 3);
}
