#include <fingera_libc/btc/bech32.h>
#include <fingera_libc/hex.h>

#include <assert.h>
#include <ctype.h>
#include <string.h>

static const char *BECH32_ENCODE = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static const int8_t BECH32_DECODE[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 15, -1, 10, 17, 21, 20, 26, 30, 7,
    5,  -1, -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9,  8,  23, -1, 18, 22,
    31, 27, 19, -1, 1,  0,  3,  16, 11, 28, 12, 14, 6,  4,  2,  -1, -1, -1, -1,
    -1, -1, 29, -1, 24, 13, 25, 9,  8,  23, -1, 18, 22, 31, 27, 19, -1, 1,  0,
    3,  16, 11, 28, 12, 14, 6,  4,  2,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1,
};
static const uint32_t BECH32_POLY_TABLE[32] = {
    0x00000000, 0x3b6a57b2, 0x26508e6d, 0x1d3ad9df, 0x1ea119fa, 0x25cb4e48,
    0x38f19797, 0x039bc025, 0x3d4233dd, 0x0628646f, 0x1b12bdb0, 0x2078ea02,
    0x23e32a27, 0x18897d95, 0x05b3a44a, 0x3ed9f3f8, 0x2a1462b3, 0x117e3501,
    0x0c44ecde, 0x372ebb6c, 0x34b57b49, 0x0fdf2cfb, 0x12e5f524, 0x298fa296,
    0x1756516e, 0x2c3c06dc, 0x3106df03, 0x0a6c88b1, 0x09f74894, 0x329d1f26,
    0x2fa7c6f9, 0x14cd914b,
};

static inline uint32_t poly_mod(uint8_t value, uint32_t c) {
  return ((c & 0x1ffffff) << 5) ^ BECH32_POLY_TABLE[c >> 25] ^ value;
}

static void create_checksum(const char *hrp, size_t hrp_len, const uint8_t *b32,
                            size_t b32_size, uint8_t checksum[6]) {
  uint32_t mod = 1;
  for (size_t i = 0; i < hrp_len; i++) {
    mod = poly_mod((uint8_t)hrp[i] >> 5, mod);
  }
  mod = poly_mod(0, mod);
  for (size_t i = 0; i < hrp_len; i++) {
    mod = poly_mod((uint8_t)hrp[i] & 0x1F, mod);
  }
  // values
  for (size_t i = 0; i < b32_size; i++) {
    mod = poly_mod(b32[i], mod);
  }
  // 6 zero
  for (size_t i = 0; i < 6; i++) {
    mod = poly_mod(0, mod);
  }
  mod ^= 1;
  for (size_t i = 0; i < 6; i++) {
    checksum[i] = (mod >> (5 * (5 - i))) & 31;
  }
}

static int verify_checksum(const char *hrp, size_t hrp_len, const uint8_t *b32,
                           size_t b32_size, uint8_t checksum[6]) {
  uint32_t mod = 1;
  for (size_t i = 0; i < hrp_len; i++) {
    mod = poly_mod((uint8_t)hrp[i] >> 5, mod);
  }
  mod = poly_mod(0, mod);
  for (size_t i = 0; i < hrp_len; i++) {
    mod = poly_mod((uint8_t)hrp[i] & 0x1F, mod);
  }
  // values
  for (size_t i = 0; i < b32_size; i++) {
    mod = poly_mod(b32[i], mod);
  }
  for (size_t i = 0; i < 6; i++) {
    mod = poly_mod(checksum[i], mod);
  }
  return mod == 1 ? 1 : 0;
}

void fingera_bech32_encode(const char *hrp, size_t hrp_len, const uint8_t *b32,
                           size_t b32_size, char *result) {
  uint8_t checksum[6];

  create_checksum(hrp, hrp_len, b32, b32_size, checksum);

  memcpy(result, hrp, hrp_len);
  result[hrp_len++] = '1';
  for (size_t i = 0; i < b32_size; i++) {
    assert(b32[i] < 32 && "bad b32 value");
    result[hrp_len++] = BECH32_ENCODE[b32[i]];
  }
  for (size_t i = 0; i < 6; i++) {
    result[hrp_len++] = BECH32_ENCODE[checksum[i]];
  }
}

static inline int is_illegal(const char *str, size_t size) {
  int lower = 0, upper = 0;
  for (size_t i = 0; i < size; i++) {
      unsigned char c = (unsigned char )str[i];
      if (c >= 'a' && c <= 'z') lower = 1;
      else if (c >= 'A' && c <= 'Z') upper = 1;
      else if (c < 33 || c > 126) return 1;
  }
  if (lower && upper) return 1;
  return 0;
}

int fingera_bech32_decode(const char *str, size_t str_len, char *hrp,
                          size_t *hrp_size, void *b32) {
  if (is_illegal(str, str_len)) return -1;

  const char *pos = strrchr(str, '1');
  if (!pos || str_len > 90 || pos == str || pos + 7 > str + str_len ||
      str_len <= 7) {
    return -2;
  }
  if (*hrp_size < (size_t)(pos - str)) return -3;
  *hrp_size = pos - str;
  for (size_t i = 0; i < *hrp_size; i++) {
    hrp[i] = isupper(str[i]) ? tolower(str[i]) : str[i];
  }
  pos++;
  int8_t *out = (int8_t *)b32;
  while (pos != (str + (str_len - 6))) {
    int8_t rev = BECH32_DECODE[(uint8_t)*pos++];
    if (rev == -1) return -4;
    *out++ = rev;
  }
  uint8_t checksum[6];
  for (size_t i = 0; i < 6; i++) {
    int8_t rev = BECH32_DECODE[(uint8_t)*pos++];
    if (rev == -1) return -4;
    checksum[i] = (uint8_t)rev;
  }
  size_t r = out - (int8_t *)b32;
  if (!verify_checksum(hrp, *hrp_size, (uint8_t *)b32, r, checksum)) return -5;
  return (int)r;
}