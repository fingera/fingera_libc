#include <fingera_libc/btc/base58_check.h>
#include <fingera_libc/btc/hash.h>
#include <fingera_libc/hex.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_STACK_ALLOC 128

size_t fingera_to_base58_check(const void *buf, size_t buf_size,
                               const void *prefix, size_t prefix_size,
                               char *str) {
  char _stack_buffer_[DEFAULT_STACK_ALLOC];
  char hash[32];

  size_t size_of_data = buf_size + prefix_size;
  size_t size_of_all = size_of_data + 4;

  char *buffer;
  if (size_of_all <= sizeof(buffer))
    buffer = _stack_buffer_;
  else
    buffer = (char *)malloc(size_of_all);

  memcpy(buffer, prefix, prefix_size);
  memcpy(buffer + prefix_size, buf, buf_size);
  fingera_btc_hash256(buffer, size_of_data, hash);
  memcpy(buffer + size_of_data, hash, 4);

  size_t r = fingera_to_base58(buffer, size_of_all, str);

  if (size_of_all > sizeof(buffer)) free(buffer);

  return r;
}

size_t fingera_from_base58_check(const char *str, size_t str_len, void *buf) {
  uint8_t hash[32];
  size_t buf_size = fingera_from_base58(str, str_len, buf);
  if (buf_size < 4) return 0;
  fingera_btc_hash256(buf, buf_size - 4, hash);
  if (memcmp(hash, (uint8_t *)buf + buf_size - 4, 4) != 0) return 0;
  return buf_size - 4;
}
