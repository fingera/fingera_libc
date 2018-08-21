#include <fingera_libc/compress_integer.h>

#include <stdlib.h>

size_t fingera_encode_varint(uint64_t value, void *buf) {
  uint8_t tmp[10];
  uint8_t *out = (uint8_t *)buf;
  int len = 0;

  for (;;) {
    tmp[len] = (value & 0x7F) | (len ? 0x80 : 0x00);
    if (value <= 0x7F) break;
    value = (value >> 7) - 1;
    len++;
  }

  do {
    *out++ = tmp[len];
  } while (len--);

  return out - (uint8_t *)buf;
}

size_t fingera_decode_varint(const void *buf, size_t size, uint64_t *out) {
  *out = 0;
  const uint8_t *in = (const uint8_t *)buf;
  if (size > 10) size = 10;
  for (size_t i = 0; i < size; i++) {
    uint8_t byte = *in++;
    *out = (*out << 7) | (byte & 0x7F);
    if (byte & 0x80) {
      (*out)++;
    } else {
      return in - (uint8_t *)buf;
    }
  }
  return 0;
}

size_t fingera_encode_zigzag(int64_t value, void *buf) {
  uint64_t uvalue = (uint64_t)llabs(value);
  uint64_t sign = value < 0 ? 1 : 0;
  uvalue <<= 1;
  uvalue |= sign;
  return fingera_encode_varint(uvalue, buf);
}

size_t fingera_decode_zigzag(const void *buf, size_t size, int64_t *out) {
  uint64_t uvalue;
  uint64_t sign;
  size_t len = fingera_decode_varint(buf, size, &uvalue);
  if (len > 0) {
    sign = uvalue & 1;
    uvalue >>= 1;
    if (sign) {
      *out = -(int64_t)uvalue;
    } else {
      *out = (int64_t)uvalue;
    }
  }
  return len;
}