#include <assert.h>
#include <ctype.h>
#include <fingera_libc/base58.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const char *BASE58_ENCODE =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const int8_t BASE58_DECODE[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,
    8,  -1, -1, -1, -1, -1, -1, -1, 9,  10, 11, 12, 13, 14, 15, 16, -1, 17, 18,
    19, 20, 21, -1, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1,
    -1, -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46, 47, 48,
    49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

#define DEFAULT_STACK_ALLOC 1024

size_t fingera_to_base58(const void *buf, size_t buf_size, char *str) {
  uint8_t _stack_buffer_[DEFAULT_STACK_ALLOC];
  // Skip & count leading zeroes.
  const uint8_t *begin = (const uint8_t *)buf;
  const uint8_t *end = begin + buf_size;
  size_t zeroes = 0;
  while (begin != end && *begin == 0) {
    begin++;
    zeroes++;
  }
  // Allocate enough space in big-endian base58 representation.
  size_t size = (end - begin) * 138 / 100 + 1;
  uint8_t *b58;
  if (size <= sizeof(_stack_buffer_))
    b58 = _stack_buffer_;
  else
    b58 = (uint8_t *)malloc(size);
  memset(b58, 0, size);

  // Process the bytes.
  int length = 0;
  while (begin != end) {
    int carry = *begin;
    int i = 0;
    for (int it = size - 1; (carry != 0 || i < length) && it >= 0; it--, i++) {
      carry += 256 * b58[it];
      b58[it] = carry % 58;
      carry /= 58;
    }
    assert(carry == 0 && "base58 overflow");
    length = i;
    begin++;
  }

  // Skip leading zeroes in base58 result.
  const uint8_t *iter = b58 + (size - length);
  while (iter != b58 + size && *iter == 0) iter++;

  // Translate the result into a string.
  memset(str, '1', zeroes);
  while (iter != b58 + size) str[zeroes++] = BASE58_ENCODE[*iter++];

  if (size > sizeof(_stack_buffer_)) free(b58);

  return zeroes;
}

size_t fingera_from_base58(const char *str, size_t str_len, void *buf) {
  uint8_t _stack_buffer_[DEFAULT_STACK_ALLOC];
  const char *str_end = str + str_len;
  // Skip leading spaces.
  while (*str && isspace(*str)) {
    str++;
  }
  int zeroes = 0;
  int length = 0;
  while (*str == '1') {
    zeroes++;
    str++;
  }

  int size = (str_end - str) * 733 / 1000 + 1;
  uint8_t *b256;
  if (size <= sizeof(_stack_buffer_))
    b256 = _stack_buffer_;
  else
    b256 = (uint8_t *)malloc(size);
  memset(b256, 0, size);

  while (*str && !isspace(*str)) {
    // Decode base58 character
    int carry = BASE58_DECODE[(uint8_t)*str];
    if (carry == -1) {
      if (size > sizeof(_stack_buffer_)) free(b256);
      return 0;
    }
    int i = 0;
    for (int it = size - 1; (carry != 0 || i < length) && (it >= 0);
         --it, ++i) {
      carry += 58 * b256[it];
      b256[it] = carry % 256;
      carry /= 256;
    }
    assert(carry == 0);
    length = i;
    str++;
  }
  // Skip trailing spaces.
  while (isspace(*str)) str++;
  if (*str != 0) {
    if (size > sizeof(_stack_buffer_)) free(b256);
    return 0;
  }
  const uint8_t *it = b256 + (size - length);
  while (it != b256 + size && *it == 0) it++;
  uint8_t *out = (uint8_t *)buf;
  memset(out, 0, zeroes);
  while (it != b256 + size) {
    out[zeroes++] = *it++;
  }
  if (size > sizeof(_stack_buffer_)) free(b256);
  return zeroes;
}
