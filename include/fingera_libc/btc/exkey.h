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

#include <stddef.h>
#include <stdint.h>

typedef struct _fingera_ex_extension {
  uint8_t depth;
  uint32_t fingerprint;
  uint32_t child;
  uint8_t chain_code[32];
} fingera_ex_extension;

typedef struct _fingera_ex_pubkey {
  fingera_ex_extension ext;
  uint8_t pubkey[64];
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

#if defined(__cplusplus)
}
#endif

#endif  // _FINGERA_LIBC_BTC_EXKEY_H_