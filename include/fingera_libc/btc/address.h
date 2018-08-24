/**
 * @brief 比特比地址编码解码
 *
 * @file address.h
 * @author liuyujun@fingera.cn
 * @date 2018-08-24
 */
#ifndef _FINGERA_LIBC_BTC_ADDRESS_H_
#define _FINGERA_LIBC_BTC_ADDRESS_H_

#if defined(__cplusplus)
extern "C" {
#endif

#include <fingera_libc/btc/chain_parameters.h>
#include <stddef.h>

typedef enum _fingera_btc_address {
  BTC_BAD_ADDRESS,                   // 错误地址
  BTC_PUBKEY_ADDRESS,                // 公钥地址
  BTC_SCRIPT_ADDRESS,                // 脚本地址
  BTC_WITNESSV0_KEYHASH_ADDRESS,     // 隔离见证公钥地址
  BTC_WITNESSV0_SCRIPTHASH_ADDRESS,  // 隔离见证脚本地址
  BTC_WITNESS_UNKNOWN_ADDRESS,       // 隔离见证其他地址
} fingera_btc_address;

static const size_t BTC_WITNESSV0_KEYID_SIZE = 20;
static const size_t BTC_WITNESSV0_SCRIPTID_SIZE = 32;

size_t fingera_to_address_pubkey(const void *key_id, size_t key_id_size,
                                 char *out, size_t out_size,
                                 const chain_parameters *param);

size_t fingera_to_address_script(const void *script_id, size_t script_id_size,
                                 char *out, size_t out_size,
                                 const chain_parameters *param);

size_t fingera_to_address_witnessv0_keyhash(const void *key_hash,
                                            size_t key_hash_size, char *out,
                                            size_t out_size,
                                            const chain_parameters *param);

size_t fingera_to_address_witnessv0_scripthash(const void *script_hash,
                                               size_t script_hash_size,
                                               char *out, size_t out_size,
                                               const chain_parameters *param);

size_t fingera_to_address_witness_unknown(const void *version_and_program,
                                          size_t version_and_program_size,
                                          char *out, size_t out_size,
                                          const chain_parameters *param);

fingera_btc_address fingera_btc_address_decode(const char *str, size_t str_len,
                                               void *out, size_t *out_size,
                                               const chain_parameters *param);

#if defined(__cplusplus)
}
#endif

#endif  // _FINGERA_LIBC_BTC_ADDRESS_H_