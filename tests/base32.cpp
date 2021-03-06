#include <fingera_libc/base32.h>
#include <fingera_libc/hex.h>

#include <gtest/gtest.h>
#include <stdint.h>
#include <stdio.h>
#include <string>

#define EXPECT_ZERO(x) EXPECT_EQ((x), 0)

TEST(base32, custom) {
  static const std::string vstrIn[] = {
      "", "f", "fo", "foo", "foob", "fooba", "foobar", "abcdefghijklmn"};
  static const std::string vstrOut[] = {
      "",         "my======", "mzxq====",         "mzxw6===",
      "mzxw6yq=", "mzxw6ytb", "mzxw6ytboi======", "mfrggzdfmztwq2lknnwg23q="};
  char out_char[256];
  size_t out_size;
  for (unsigned int i = 0; i < sizeof(vstrIn) / sizeof(vstrIn[0]); i++) {
    memset(out_char, 0, sizeof(out_char));
    fingera_to_base32(vstrIn[i].c_str(), vstrIn[i].size(), out_char);
    EXPECT_EQ(vstrOut[i], out_char);
    EXPECT_EQ(fingera_to_base32_length(vstrIn[i].size()), vstrOut[i].size());
    EXPECT_EQ(fingera_from_base32_length(vstrOut[i].c_str(), vstrOut[i].size()),
              vstrIn[i].size());
    memset(out_char, 0, sizeof(out_char));
    EXPECT_EQ(
        fingera_from_base32(vstrOut[i].c_str(), vstrOut[i].size(), out_char),
        vstrIn[i].size());
    EXPECT_EQ(vstrIn[i], out_char);

    memset(out_char, 0, sizeof(out_char));
    out_size =
        fingera_to_base32_raw(vstrIn[i].c_str(), vstrIn[i].size(), out_char);
    char values[256];
    size_t size_of_values = fingera_from_base32_raw(out_char, out_size, values);
    EXPECT_EQ(size_of_values, vstrIn[i].size());
    values[size_of_values] = '\0';
    EXPECT_EQ(vstrIn[i], values);
  }

  EXPECT_EQ(fingera_from_base32("mzxw6ytb#mzxw6ytb", 17, out_char), 5);
}