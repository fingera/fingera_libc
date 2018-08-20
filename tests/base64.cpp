#include <fingera_libc/base64.h>

#include <gtest/gtest.h>
#include <stdint.h>
#include <string>

#define EXPECT_ZERO(x) EXPECT_EQ((x), 0)

const static std::string standard_base64[] = {
#include "data/base64_standard.data"
};
const static std::string urlsafe_base64[] = {
#include "data/base64_urlsafe.data"
};

TEST(base64, exhaustive) {
  uint8_t buf[256];
  uint8_t out_buf[256];
  uint8_t out_buf_zero[256] = {0};
  char str[256 * 2];
  for (size_t i = 0; i < 256; i++) {
    buf[i] = static_cast<uint8_t>(i);
  }

  for (size_t i = 0; i < 256; i++) {
    memset(str, 0, sizeof(str));
    memset(out_buf, 0, sizeof(out_buf));
    fingera_to_base64(buf, i, str);
    size_t str_len = strlen(str);
    EXPECT_EQ(fingera_to_base64_length(i), str_len);
    EXPECT_EQ(standard_base64[i], str);
    EXPECT_EQ(fingera_from_base64(str, str_len, out_buf), i);
    EXPECT_EQ(fingera_from_base64_length(str, str_len), i);
    EXPECT_ZERO(memcmp(buf, out_buf, i));
    EXPECT_ZERO(memcmp(out_buf + i, out_buf_zero, 256 - i));

    memset(str, 0, sizeof(str));
    memset(out_buf, 0, sizeof(out_buf));
    fingera_to_base64_urlsafe(buf, i, str);
    str_len = strlen(str);
    EXPECT_EQ(fingera_to_base64_urlsafe_length(i), str_len);
    EXPECT_EQ(urlsafe_base64[i], str);
    EXPECT_EQ(fingera_from_base64_urlsafe(str, str_len, out_buf), i);
    EXPECT_EQ(fingera_from_base64_urlsafe_length(str_len), i);
    EXPECT_ZERO(memcmp(buf, out_buf, i));
    EXPECT_ZERO(memcmp(out_buf + i, out_buf_zero, 256 - i));
  }
}
