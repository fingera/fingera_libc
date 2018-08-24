#include <fingera_libc/btc/hash.h>
#include <fingera_libc/hash/ripemd160.h>
#include <fingera_libc/hash/sha2.h>

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
