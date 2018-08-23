#include <fingera_libc/base32.h>
#include <stdint.h>
#include <string.h>

static const char BASE32_ENCODE[33] = "abcdefghijklmnopqrstuvwxyz234567";
static const uint8_t BASE32_DECODE[256] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 26,   27,   28,   29,   30,   31,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    6,
    7,    8,    9,    10,   11,   12,   13,   14,   15,   16,   17,   18,
    19,   20,   21,   22,   23,   24,   25,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0,    1,    2,    3,    4,    5,    6,    7,    8,    9,    10,
    11,   12,   13,   14,   15,   16,   17,   18,   19,   20,   21,   22,
    23,   24,   25,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF};

/*
  1 个字节 编码成2个字节 最后一个字节3位 需要增加6个padding
  2 个字节 编码成4个字节 最后一个字节1位 需要增加4个padding
  3 个字节 编码成5个字节 最后一个字节4位 需要增加3个padding
  4 个字节 编码成7个字节 最后一个字节2位 需要增加1个padding
  5 个字节 编码成8个字节
*/
static const int TAIL_TO_BYTES[8] = {0, 0, 1, 0, 2, 3, 0, 4};

void fingera_to_base32(const void *buf, size_t buf_size, char *out) {
  size_t tail_len = buf_size % 5;
  size_t loop_size = buf_size - tail_len;
  const uint8_t *input = (const uint8_t *)buf;
  const char *encode_str = BASE32_ENCODE;
  uint8_t byte1, byte2, byte3, byte4, byte5, byte6, byte7, byte8;

  for (size_t i = 0; i < loop_size; i += 5) {
    byte1 = input[0] >> 3;
    byte2 = ((input[0] & 7) << 2) | (input[1] >> 6);
    byte3 = (input[1] >> 1) & 0x1F;
    byte4 = ((input[1] & 1) << 4) | (input[2] >> 4);
    byte5 = ((input[2] & 0xF) << 1) | (input[3] >> 7);
    byte6 = (input[3] >> 2) & 0x1F;
    byte7 = ((input[3] & 3) << 3) | ((input[4] >> 5) & 7);
    byte8 = input[4] & 0x1F;
    out[0] = encode_str[byte1];
    out[1] = encode_str[byte2];
    out[2] = encode_str[byte3];
    out[3] = encode_str[byte4];
    out[4] = encode_str[byte5];
    out[5] = encode_str[byte6];
    out[6] = encode_str[byte7];
    out[7] = encode_str[byte8];
    out += 8;
    input += 5;
  }
  switch (tail_len) {
    case 1:
      byte1 = input[0] >> 3;
      byte2 = ((input[0] & 7) << 2);
      out[0] = encode_str[byte1];
      out[1] = encode_str[byte2];
      out[2] = '=';
      out[3] = '=';
      out[4] = '=';
      out[5] = '=';
      out[6] = '=';
      out[7] = '=';
      break;
    case 2:
      byte1 = input[0] >> 3;
      byte2 = ((input[0] & 7) << 2) | (input[1] >> 6);
      byte3 = (input[1] >> 1) & 0x1F;
      byte4 = ((input[1] & 1) << 4);
      out[0] = encode_str[byte1];
      out[1] = encode_str[byte2];
      out[2] = encode_str[byte3];
      out[3] = encode_str[byte4];
      out[4] = '=';
      out[5] = '=';
      out[6] = '=';
      out[7] = '=';
      break;
    case 3:
      byte1 = input[0] >> 3;
      byte2 = ((input[0] & 7) << 2) | (input[1] >> 6);
      byte3 = (input[1] >> 1) & 0x1F;
      byte4 = ((input[1] & 1) << 4) | (input[2] >> 4);
      byte5 = ((input[2] & 0xF) << 1);
      out[0] = encode_str[byte1];
      out[1] = encode_str[byte2];
      out[2] = encode_str[byte3];
      out[3] = encode_str[byte4];
      out[4] = encode_str[byte5];
      out[5] = '=';
      out[6] = '=';
      out[7] = '=';
      break;
    case 4:
      byte1 = input[0] >> 3;
      byte2 = ((input[0] & 7) << 2) | (input[1] >> 6);
      byte3 = (input[1] >> 1) & 0x1F;
      byte4 = ((input[1] & 1) << 4) | (input[2] >> 4);
      byte5 = ((input[2] & 0xF) << 1) | (input[3] >> 7);
      byte6 = (input[3] >> 2) & 0x1F;
      byte7 = ((input[3] & 3) << 3);
      out[0] = encode_str[byte1];
      out[1] = encode_str[byte2];
      out[2] = encode_str[byte3];
      out[3] = encode_str[byte4];
      out[4] = encode_str[byte5];
      out[5] = encode_str[byte6];
      out[6] = encode_str[byte7];
      out[7] = '=';
      break;
    default:
      break;
  }
}

static inline size_t base32_strlen(const char *str, size_t str_len) {
  const char *str_end = strchr(str, '=');
  if (!str_end) return str_len;
  return str_end - str;
}

size_t fingera_from_base32_length(const char *str, size_t str_len) {
  size_t new_len = base32_strlen(str, str_len);
  size_t size = (new_len / 8) * 5;
  return size + TAIL_TO_BYTES[new_len % 8];
}

size_t fingera_from_base32(const char *str, size_t str_len, void *buf) {
  size_t new_len = base32_strlen(str, str_len);
  size_t tail = new_len % 8;
  size_t blocks = new_len / 8;
  const char *tail_str = str + blocks * 8;
  uint8_t *out = (uint8_t *)buf;
  for (size_t i = 0; i < blocks; i++) {
    uint8_t byte1 = BASE32_DECODE[str[i * 8 + 0]];
    uint8_t byte2 = BASE32_DECODE[str[i * 8 + 1]];
    uint8_t byte3 = BASE32_DECODE[str[i * 8 + 2]];
    uint8_t byte4 = BASE32_DECODE[str[i * 8 + 3]];
    uint8_t byte5 = BASE32_DECODE[str[i * 8 + 4]];
    uint8_t byte6 = BASE32_DECODE[str[i * 8 + 5]];
    uint8_t byte7 = BASE32_DECODE[str[i * 8 + 6]];
    uint8_t byte8 = BASE32_DECODE[str[i * 8 + 7]];
    if (byte1 == 0xFF || byte2 == 0xFF || byte3 == 0xFF || byte4 == 0xFF ||
        byte5 == 0xFF || byte6 == 0xFF || byte7 == 0xFF || byte8 == 0xFF)
      return out - (uint8_t *)buf;
    // 11111111 11111111 11111111 11111111 11111111
    // 11111222 22333334 44445555 56666677 77788888
    out[0] = (byte1 << 3) | (byte2 >> 2);
    out[1] = (byte2 << 6) | (byte3 << 1) | (byte4 >> 4);
    out[2] = (byte4 << 4) | (byte5 >> 1);
    out[3] = (byte5 << 7) | (byte6 << 2) | (byte7 >> 3);
    out[4] = (byte7 << 5) | byte8;
    out += 5;
  }
  uint8_t tail_bytes = TAIL_TO_BYTES[tail];
  if (tail_bytes > 0) {
    uint8_t byte1 = BASE32_DECODE[tail_str[0]];
    uint8_t byte2 = BASE32_DECODE[tail_str[1]];
    *out++ = (byte1 << 3) | (byte2 >> 2);
    if (tail_bytes > 1) {
      uint8_t byte3 = BASE32_DECODE[tail_str[2]];
      uint8_t byte4 = BASE32_DECODE[tail_str[3]];
      *out++ = (byte2 << 6) | (byte3 << 1) | (byte4 >> 4);
      if (tail_bytes > 2) {
        uint8_t byte5 = BASE32_DECODE[tail_str[4]];
        *out++ = (byte4 << 4) | (byte5 >> 1);
        if (tail_bytes > 3) {
          uint8_t byte6 = BASE32_DECODE[tail_str[5]];
          uint8_t byte7 = BASE32_DECODE[tail_str[6]];
          *out++ = (byte5 << 7) | (byte6 << 2) | (byte7 >> 3);
        }
      }
    }
  }
  return out - (uint8_t *)buf;
}