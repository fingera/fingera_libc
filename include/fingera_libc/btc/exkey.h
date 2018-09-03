/**
 * @brief 派生密钥的实现 bip32?
 *
 * @file exkey.h
 * @author liuyujun@fingera.cn
 * @date 2018-09-03
 */
#ifndef _FINGERA_LIBC_BTC_EXKEY_H_
#define _FINGERA_LIBC_BTC_EXKEY_H_

#if defined(__cplusplus)
extern "C" {
#endif

#include <fingera_libc/btc/base58_check.h>
#include <fingera_libc/btc/chain_parameters.h>
#include <stddef.h>
#include <stdint.h>

#define BIP32_EXTKEY_SIZE 74u

typedef struct _fingera_ex_extension {
  uint8_t depth;
  uint32_t fingerprint;
  uint32_t child;
  uint8_t chain_code[32];
} fingera_ex_extension;

typedef struct _fingera_ex_pubkey {
  fingera_ex_extension ext;
  uint8_t c_pubkey[33];
} fingera_ex_pubkey;

typedef struct _fingera_ex_key {
  fingera_ex_extension ext;
  uint8_t key[32];
} fingera_ex_key;

void fingera_exkey_init(fingera_ex_key *key, const void *seed, size_t len);

int fingera_exkey_derive(const fingera_ex_key *key, fingera_ex_key *derived,
                         uint32_t child, uint32_t fingerprint);

void fingera_exkey_get_pub(const fingera_ex_key *key,
                           fingera_ex_pubkey *pubkey);

int fingera_expubkey_derive(const fingera_ex_pubkey *pubkey,
                            fingera_ex_pubkey *derived, uint32_t child,
                            uint32_t fingerprint);

void fingera_exkey_encode(const fingera_ex_key *key, void *extkey74);
void fingera_exkey_decode(const void *extkey74, fingera_ex_key *key);

static inline size_t fingera_exkey_string_max_length() {
  return fingera_to_base58_check_length(BIP32_EXTKEY_SIZE, 8);
}

size_t fingera_exkey_to_string(const fingera_ex_key *key, char *str,
                               const chain_parameters *param);
int fingera_exkey_from_string(const char *str, size_t str_len,
                              fingera_ex_key *key,
                              const chain_parameters *param);

void fingera_expubkey_encode(const fingera_ex_pubkey *pubkey, void *extkey74);
void fingera_expubkey_decode(const void *extkey74, fingera_ex_pubkey *pubkey);

size_t fingera_expubkey_to_string(const fingera_ex_pubkey *pubkey, char *str,
                                  const chain_parameters *param);
int fingera_expubkey_from_string(const char *str, size_t str_len,
                                 fingera_ex_pubkey *pub,
                                 const chain_parameters *param);

#if defined(__cplusplus)
}
#endif

#endif  // _FINGERA_LIBC_BTC_EXKEY_H_