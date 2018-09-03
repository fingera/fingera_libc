#include <assert.h>
#include <fingera_libc/btc/exkey.h>
#include <fingera_libc/btc/key.h>
#include <fingera_libc/cleanse.h>
#include <fingera_libc/endian.h>
#include <fingera_libc/hash/sha2.h>
#include <fingera_libc/sl/buffer.h>
#include <string.h>

void fingera_exkey_init(fingera_ex_key *key, const void *seed, size_t len) {
  static const unsigned char hashkey[] = {'B', 'i', 't', 'c', 'o', 'i',
                                          'n', ' ', 's', 'e', 'e', 'd'};
  uint8_t out[64];
  fingera_hmac_sha512(hashkey, sizeof(hashkey), seed, len, out);

  key->ext.depth = 0;
  key->ext.child = 0;
  key->ext.fingerprint = 0;
  memcpy(key->key, out, 32);
  memcpy(key->ext.chain_code, out + 32, 32);
  fingera_cleanse(out, sizeof(out));
}

int fingera_exkey_derive(const fingera_ex_key *key, fingera_ex_key *derived,
                         uint32_t child, uint32_t fingerprint) {
  int r = fingera_btc_key_derive(key->key, key->ext.chain_code, derived->key,
                                 derived->ext.chain_code, child);
  if (r) {
    derived->ext.fingerprint = fingerprint;
    derived->ext.depth = key->ext.depth + 1;
    derived->ext.child = child;
  }
  return r;
}

int fingera_expubkey_derive(const fingera_ex_pubkey *pubkey,
                            fingera_ex_pubkey *derived, uint32_t child,
                            uint32_t fingerprint) {
  if (!fingera_btc_pubkey_derive(pubkey->c_pubkey, pubkey->ext.chain_code,
                                 derived->c_pubkey, derived->ext.chain_code,
                                 child))
    return 0;
  derived->ext.depth = pubkey->ext.depth + 1;
  derived->ext.child = child;
  derived->ext.fingerprint = fingerprint;
  return 1;
}

void fingera_exkey_get_pub(const fingera_ex_key *key,
                           fingera_ex_pubkey *pubkey) {
  memcpy(&pubkey->ext, &key->ext, sizeof(key->ext));
  uint8_t pub[64];
  fingera_btc_key_get_pub(key->key, pub);
  int r = fingera_btc_pubkey_encode(pub, pubkey->c_pubkey,
                                    sizeof(pubkey->c_pubkey));
  assert(r);
}

static void write_key_extension(const fingera_ex_extension *ext,
                                void *extkey74) {
  uint8_t *code = (uint8_t *)extkey74;
  code[0] = ext->depth;
  write_little_32(code + 1, ext->fingerprint);
  write_big_32(code + 5, ext->child);
  memcpy(code + 9, ext->chain_code, 32);
}

static void read_key_extension(const void *extkey74,
                               fingera_ex_extension *ext) {
  const uint8_t *code = (const uint8_t *)extkey74;
  ext->depth = code[0];
  ext->fingerprint = read_little_32(code + 1);
  ext->child = read_big_32(code + 5);
  memcpy(ext->chain_code, code + 9, 32);
}

void fingera_exkey_encode(const fingera_ex_key *key, void *extkey74) {
  uint8_t *code = (uint8_t *)extkey74;
  write_key_extension(&key->ext, extkey74);
  code[41] = 0;
  memcpy(code + 42, key->key, 32);
}

void fingera_exkey_decode(const void *extkey74, fingera_ex_key *key) {
  const uint8_t *code = (const uint8_t *)extkey74;
  read_key_extension(extkey74, &key->ext);
  memcpy(key->key, code + 42, 32);
}

size_t fingera_exkey_to_string(const fingera_ex_key *key, char *str,
                               const chain_parameters *param) {
  uint8_t extkey[BIP32_EXTKEY_SIZE];
  fingera_exkey_encode(key, extkey);
  size_t size = fingera_to_base58_check(extkey, sizeof(extkey),
                                        param->prefix_ext_secret_key,
                                        param->prefix_ext_secret_key_size, str);
  fingera_cleanse(extkey, sizeof(extkey));
  return size;
}

int fingera_exkey_from_string(const char *str, size_t str_len,
                              fingera_ex_key *key,
                              const chain_parameters *param) {
  uint8_t extkey[BIP32_EXTKEY_SIZE + 8];
  assert(param->prefix_ext_secret_key_size <= 8);
  size_t size = fingera_from_base58_check(str, str_len, extkey);
  assert(size <= sizeof(extkey));
  if (size <= BIP32_EXTKEY_SIZE || size > sizeof(extkey))
    return 0;  // no prefix or Overflow
  size_t prefix_size = size - BIP32_EXTKEY_SIZE;
  if (prefix_size != param->prefix_ext_secret_key_size) return 0;
  if (memcmp(extkey, param->prefix_ext_secret_key, prefix_size) != 0) return 0;
  fingera_exkey_decode(extkey + prefix_size, key);
  fingera_cleanse(extkey, sizeof(extkey));
  return 1;
}

void fingera_expubkey_encode(const fingera_ex_pubkey *pubkey, void *extkey74) {
  uint8_t *code = (uint8_t *)extkey74;
  write_key_extension(&pubkey->ext, extkey74);
  memcpy(code + 41, pubkey->c_pubkey, 33);
}

void fingera_expubkey_decode(const void *extkey74, fingera_ex_pubkey *pubkey) {
  uint8_t *code = (uint8_t *)extkey74;
  read_key_extension(extkey74, &pubkey->ext);
  memcpy(pubkey->c_pubkey, code + 41, 33);
}

size_t fingera_expubkey_to_string(const fingera_ex_pubkey *pubkey, char *str,
                                  const chain_parameters *param) {
  uint8_t extkey[BIP32_EXTKEY_SIZE];
  fingera_expubkey_encode(pubkey, extkey);
  size_t size = fingera_to_base58_check(extkey, sizeof(extkey),
                                        param->prefix_ext_public_key,
                                        param->prefix_ext_public_key_size, str);
  return size;
}
int fingera_expubkey_from_string(const char *str, size_t str_len,
                                 fingera_ex_pubkey *pub,
                                 const chain_parameters *param) {
  uint8_t extkey[BIP32_EXTKEY_SIZE + 8];
  assert(param->prefix_ext_public_key_size <= 8);
  size_t size = fingera_from_base58_check(str, str_len, extkey);
  assert(size <= sizeof(extkey));
  if (size <= BIP32_EXTKEY_SIZE || size > sizeof(extkey))
    return 0;  // no prefix or Overflow
  size_t prefix_size = size - BIP32_EXTKEY_SIZE;
  if (prefix_size != param->prefix_ext_public_key_size) return 0;
  if (memcmp(extkey, param->prefix_ext_public_key, prefix_size) != 0) return 0;
  fingera_expubkey_decode(extkey + prefix_size, pub);
  return 1;
}