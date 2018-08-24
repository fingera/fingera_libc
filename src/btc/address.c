#include <assert.h>
#include <fingera_libc/base32.h>
#include <fingera_libc/btc/address.h>
#include <fingera_libc/btc/base58_check.h>
#include <fingera_libc/btc/bech32.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_STACK_ALLOC 128

size_t fingera_to_address_pubkey(const void *key_id, size_t key_id_size,
                                 char *out, size_t out_size,
                                 const chain_parameters *param) {
  if (out_size < fingera_to_base58_check_length(
                     key_id_size, param->prefix_pubkey_address_size)) {
    return 0;  // 内存可能会不足
  }
  return fingera_to_base58_check(key_id, key_id_size,
                                 param->prefix_pubkey_address,
                                 param->prefix_pubkey_address_size, out);
}

size_t fingera_to_address_script(const void *script_id, size_t script_id_size,
                                 char *out, size_t out_size,
                                 const chain_parameters *param) {
  if (out_size < fingera_to_base58_check_length(
                     script_id_size, param->prefix_script_address_size)) {
    return 0;  // 内存可能会不足
  }
  return fingera_to_base58_check(script_id, script_id_size,
                                 param->prefix_script_address,
                                 param->prefix_script_address_size, out);
}

size_t fingera_to_address_witnessv0_keyhash(const void *key_hash,
                                            size_t key_hash_size, char *out,
                                            size_t out_size,
                                            const chain_parameters *param) {
  char buffer[64];
  assert(key_hash_size == BTC_WITNESSV0_KEYID_SIZE);
  if (key_hash_size != BTC_WITNESSV0_KEYID_SIZE) return 0;
  buffer[0] = 0;
  size_t buf_size =
      fingera_to_base32_raw(key_hash, key_hash_size, buffer + 1) + 1;
  size_t result_size =
      fingera_bech32_encode_length(param->bech32_hrp_size, buf_size);
  if (out_size < result_size) return 0;

  fingera_bech32_encode(param->bech32_hrp, param->bech32_hrp_size, buffer,
                        buf_size, out);
  return result_size;
}

size_t fingera_to_address_witnessv0_scripthash(const void *script_hash,
                                               size_t script_hash_size,
                                               char *out, size_t out_size,
                                               const chain_parameters *param) {
  char buffer[64];
  assert(script_hash_size == BTC_WITNESSV0_SCRIPTID_SIZE);
  if (script_hash_size != BTC_WITNESSV0_SCRIPTID_SIZE) return 0;
  buffer[0] = 0;
  size_t buf_size =
      fingera_to_base32_raw(script_hash, script_hash_size, buffer + 1) + 1;
  size_t result_size =
      fingera_bech32_encode_length(param->bech32_hrp_size, buf_size);
  if (out_size < result_size) return 0;

  fingera_bech32_encode(param->bech32_hrp, param->bech32_hrp_size, buffer,
                        buf_size, out);
  return result_size;
}

size_t fingera_to_address_witness_unknown(const void *version_and_program,
                                          size_t version_and_program_size,
                                          char *out, size_t out_size,
                                          const chain_parameters *param) {
  if (version_and_program_size < 3 || version_and_program_size > 41) return 0;
  int version = *(uint8_t *)version_and_program;
  if (version < 1 || version > 16) return 0;

  char buffer[128];
  buffer[0] = version;
  size_t buf_size =
      fingera_to_base32_raw((char *)version_and_program + 1,
                            version_and_program_size - 1, buffer + 1) +
      1;
  size_t result_size =
      fingera_bech32_encode_length(param->bech32_hrp_size, buf_size);
  if (out_size < result_size) return 0;

  fingera_bech32_encode(param->bech32_hrp, param->bech32_hrp_size, buffer,
                        buf_size, out);
  return result_size;
}

static fingera_btc_address decode_bech32(const char *str, size_t str_len,
                                         void *out, size_t *out_size,
                                         const chain_parameters *param) {
  char _stack_buffer_[DEFAULT_STACK_ALLOC];

  char *buffer;
  if (str_len - 7 <= sizeof(_stack_buffer_)) {
    buffer = _stack_buffer_;
  } else {
    buffer = (char *)malloc(str_len - 7);
  }

  char bech32_hrp[16];
  size_t hrp_size = sizeof(bech32_hrp);
  int bech32_size =
      fingera_bech32_decode(str, str_len, bech32_hrp, &hrp_size, buffer);

  if (bech32_size < 1 || hrp_size != param->bech32_hrp_size ||
      memcmp(bech32_hrp, param->bech32_hrp, hrp_size) != 0) {
    if (str_len - 7 > sizeof(_stack_buffer_)) {
      free(buffer);
    }
    return BTC_BAD_ADDRESS;
  }

  if (*out_size >= fingera_from_base32_raw_length(bech32_size - 1)) {
    int version = buffer[0];
    if (version == 0) {
      *out_size = fingera_from_base32_raw(buffer + 1, bech32_size - 1, out);
      if (*out_size == BTC_WITNESSV0_KEYID_SIZE) {
        return BTC_WITNESSV0_KEYHASH_ADDRESS;
      } else if (*out_size == BTC_WITNESSV0_SCRIPTID_SIZE) {
        return BTC_WITNESSV0_SCRIPTHASH_ADDRESS;
      } else {
        return BTC_BAD_ADDRESS;
      }
    }
    *(int8_t *)out = version;
    *out_size =
        fingera_from_base32_raw(buffer + 1, bech32_size - 1, (char *)out + 1);
    (*out_size)++;
    if (version > 16 || *out_size < 3 || *out_size > 41) {
      return BTC_BAD_ADDRESS;
    }
    return BTC_WITNESS_UNKNOWN_ADDRESS;
  }

  if (str_len - 7 > sizeof(_stack_buffer_)) {
    free(buffer);
  }
  return BTC_BAD_ADDRESS;
}

fingera_btc_address fingera_btc_address_decode(const char *str, size_t str_len,
                                               void *out, size_t *out_size,
                                               const chain_parameters *param) {
  if (*out_size < fingera_from_base58_check_length(str_len)) {
    return BTC_BAD_ADDRESS;
  }
  size_t size = fingera_from_base58_check(str, str_len, out);
  if (size) {
    if (size >= param->prefix_pubkey_address_size &&
        memcmp(out, param->prefix_pubkey_address,
               param->prefix_pubkey_address_size) == 0) {
      *out_size = size - param->prefix_pubkey_address_size;
      memmove(out, (char *)out + param->prefix_pubkey_address_size, *out_size);
      return BTC_PUBKEY_ADDRESS;
    } else if (size >= param->prefix_script_address_size &&
               memcmp(out, param->prefix_script_address,
                      param->prefix_script_address_size) == 0) {
      *out_size = size - param->prefix_script_address_size;
      memmove(out, (char *)out + param->prefix_script_address_size, *out_size);
      return BTC_SCRIPT_ADDRESS;
    }
  }
  return decode_bech32(str, str_len, out, out_size, param);
}