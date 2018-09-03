#include <fingera_libc/btc/exkey.h>
#include <fingera_libc/btc/key.h>
#include <fingera_libc/cleanse.h>
#include <fingera_libc/hash/sha2.h>
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
  uint8_t compressed_pubkey[BTC_COMPRESSED_PUBLIC_KEY_SIZE];
  if (!fingera_btc_pubkey_encode(pubkey->pubkey, compressed_pubkey,
                                 sizeof(compressed_pubkey)))
    return 0;
  memcpy(derived->pubkey, pubkey->pubkey, sizeof(pubkey->pubkey));
  if (!fingera_btc_pubkey_derive(compressed_pubkey, pubkey->ext.chain_code,
                                 derived->pubkey, derived->ext.chain_code,
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
  fingera_btc_key_get_pub(key->key, pubkey->pubkey);
}
