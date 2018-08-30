#include <assert.h>
#include <fingera_libc/btc/key.h>
#include <fingera_libc/endian.h>
#include <fingera_libc/random.h>
#include <secp256k1.h>
#include <stdint.h>
#include <string.h>

static secp256k1_context* secp256k1_context_sign = NULL;
static secp256k1_context* secp256k1_context_verify = NULL;

void fingera_btc_key_init() {
  assert(secp256k1_context_verify == NULL);
  secp256k1_context_verify = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
  assert(secp256k1_context_sign == NULL);
  secp256k1_context_sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
}

void fingera_btc_key_uninit() {
  assert(secp256k1_context_sign != NULL);
  secp256k1_context_destroy(secp256k1_context_sign);
  secp256k1_context_sign = NULL;
  assert(secp256k1_context_verify != NULL);
  secp256k1_context_destroy(secp256k1_context_verify);
  secp256k1_context_verify = NULL;
}

void fingera_btc_key_new(void* key32) {
  do {
    fingera_os_rand_bytes(key32, 32);
  } while (!secp256k1_ec_seckey_verify(secp256k1_context_sign, key32));
}

void fingera_btc_key_get_pub(const void* key32, void* pubkey64) {
  assert(sizeof(secp256k1_pubkey) == 64);
  secp256k1_pubkey* pubkey = (secp256k1_pubkey*)pubkey64;
  int r = secp256k1_ec_pubkey_create(secp256k1_context_sign, pubkey,
                                     (const unsigned char*)key32);
  assert(r);
  (void)r;
}

// Check that the sig has a low R value and will be less than 71 bytes
int SigHasLowR(const secp256k1_ecdsa_signature* sig) {
  unsigned char compact_sig[64];
  secp256k1_ecdsa_signature_serialize_compact(secp256k1_context_sign,
                                              compact_sig, sig);

  // In DER serialization, all values are interpreted as big-endian, signed
  // integers. The highest bit in the integer indicates
  // its signed-ness; 0 is positive, 1 is negative. When the value is
  // interpreted as a negative integer, it must be converted
  // to a positive value by prepending a 0x00 byte so that the highest bit is 0.
  // We can avoid this prepending by ensuring that
  // our highest bit is always 0, and thus we must check that the first byte is
  // less than 0x80.
  return compact_sig[0] < 0x80;
}

void fingera_btc_key_sign(const void* key32, const void* hash32,
                          void* signatures64) {
  assert(sizeof(secp256k1_ecdsa_signature) == 64);
  secp256k1_ecdsa_signature* sig = (secp256k1_ecdsa_signature*)signatures64;
  int ret = secp256k1_ecdsa_sign(
      secp256k1_context_sign, sig, (const unsigned char*)hash32,
      (const unsigned char*)key32, secp256k1_nonce_function_rfc6979, NULL);

  unsigned char extra_entropy[32] = {0};
  uint32_t counter = 0;

  // Grind for low R
  while (ret && !SigHasLowR(sig)) {
    write_little_32(extra_entropy, ++counter);
    ret = secp256k1_ecdsa_sign(secp256k1_context_sign, sig,
                               (const unsigned char*)hash32,
                               (const unsigned char*)key32,
                               secp256k1_nonce_function_rfc6979, extra_entropy);
  }
  assert(ret);
}

int fingera_btc_key_verify(const void* pubkey64, const void* hash32,
                           const void* signatures64) {
  assert(sizeof(secp256k1_pubkey) == 64);
  assert(sizeof(secp256k1_ecdsa_signature) == 64);
  const secp256k1_pubkey* pubkey = (const secp256k1_pubkey*)pubkey64;
  const secp256k1_ecdsa_signature* sig =
      (const secp256k1_ecdsa_signature*)signatures64;
  secp256k1_ecdsa_signature sig_normalized;
  memcpy(&sig_normalized, signatures64, sizeof(secp256k1_ecdsa_signature));

  /* libsecp256k1's ECDSA verification requires lower-S signatures, which have
   * not historically been enforced in Bitcoin, so normalize them first. */
  secp256k1_ecdsa_signature_normalize(secp256k1_context_verify, &sig_normalized,
                                      sig);
  return secp256k1_ecdsa_verify(secp256k1_context_verify, &sig_normalized,
                                (const unsigned char*)hash32, pubkey);
}
