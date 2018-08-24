/**
 * @brief 比特币网络配置参数
 *
 * @file chain_parameters.h
 * @author liuyujun@fingera.cn
 * @date 2018-08-24
 */
#ifndef _FINGERA_LIBC_BTC_CHAIN_PARAMETERS_H_
#define _FINGERA_LIBC_BTC_CHAIN_PARAMETERS_H_

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct _chain_parameters {
  const char *prefix_pubkey_address;
  unsigned int prefix_pubkey_address_size;

  const char *prefix_script_address;
  unsigned int prefix_script_address_size;

  const char *prefix_secret_key;
  unsigned int prefix_secret_key_size;

  const char *prefix_ext_public_key;
  unsigned int prefix_ext_public_key_size;

  const char *prefix_ext_secret_key;
  unsigned int prefix_ext_secret_key_size;

  const char *bech32_hrp;
  unsigned int bech32_hrp_size;
} chain_parameters;

extern chain_parameters g_mainnet_chain_parameters;
extern chain_parameters g_testnet_chain_parameters;
extern chain_parameters g_regnet_chain_parameters;

#if defined(__cplusplus)
}
#endif

#endif  // _FINGERA_LIBC_BTC_CHAIN_PARAMETERS_H_