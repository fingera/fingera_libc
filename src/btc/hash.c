#include <fingera_libc/btc/hash.h>
#include <fingera_libc/cleanse.h>
#include <fingera_libc/endian.h>
#include <fingera_libc/hash/ripemd160.h>
#include <fingera_libc/hash/sha2.h>
#include <string.h>

void fingera_btc_hash160(const void *msg, size_t msg_len, void *hash) {
  char sha2_digest[32];
  fingera_sha2_256(msg, msg_len, sha2_digest);
  fingera_ripemd160(sha2_digest, sizeof(sha2_digest), hash);
}

void fingera_btc_hash256(const void *msg, size_t msg_len, void *hash) {
  char sha2_digest[32];
  fingera_sha2_256(msg, msg_len, sha2_digest);
  fingera_sha2_256(sha2_digest, sizeof(sha2_digest), hash);
}

// 在 hash/sha2.c 中实现
void _hash256_d64_transform(void *out, const void *in);

void fingera_btc_hash256_d64(void *out, const void *in, size_t blocks) {
  char *_out = (char *)out;
  const char *_in = (const char *)in;
  while (blocks--) {
    _hash256_d64_transform(_out, _in);
    _out += 32;
    _in += 64;
  }
}

/**
 * @brief 比特币bip32 HASH
 *
 * @param chain_code 32字节
 * @param child 4字节
 * @param header 1字节
 * @param data32 32字节
 * @param out64 输出64字节HASH值
 */
void fingera_btc_bip32_hash(const void *chain_code, uint32_t child,
                            uint8_t header, const void *data32, void *out64) {
  char buffer[1 + 32 + 4];
  char *ptr = buffer;
  memcpy(ptr, &header, 1);
  ptr++;
  memcpy(ptr, data32, 32);
  ptr += 32;
  write_little_32(ptr, child);
  fingera_hmac_sha512(chain_code, 32, buffer, sizeof(buffer), out64);
  fingera_cleanse(buffer, sizeof(buffer));
}
