/**
 * @brief 公钥私钥处理
 *
 * @file key.h
 * @author liuyujun@fingera.cn
 * @date 2018-08-29
 */
#ifndef _FINGERA_LIBC_BTC_KEY_H_
#define _FINGERA_LIBC_BTC_KEY_H_

#if defined(__cplusplus)
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#define BTC_PRIVATE_KEY_SIZE 279u
#define BTC_COMPRESSED_PRIVATE_KEY_SIZE 214u
#define BTC_PUBLIC_KEY_SIZE 65u
#define BTC_COMPRESSED_PUBLIC_KEY_SIZE 33u
#define BTC_SIGNATURE_SIZE 72u

/**
 * @brief 初始化
 *
 */
void fingera_btc_key_init();
/**
 * @brief 销毁
 *
 */
void fingera_btc_key_uninit();

/**
 * @brief 生成私钥(32字节)
 *
 * @param key 32字节的内存存储私钥
 */
void fingera_btc_key_new(void *key32);

/**
 * @brief 派生私钥(32字节) 和chain_code(32字节)
 *
 * @param key32 32字节私钥
 * @param chain32 32字节chain_code
 * @param out_key32 32字节输出私钥
 * @param out_chain32 32字节输出chain_code
 * @param child 派生时传入的一个32位整数
 * @return int 非0成功 0失败
 */
int fingera_btc_key_derive(const void *key32, const void *chain32,
                           void *out_key32, void *out_chain32, uint32_t child);

/**
 * @brief 比特币私钥格式编码
 *
 * @param key32 32字节的私钥
 * @param encoded_key 编码后的私钥缓存
 * @param encoded_key_len 编码后私钥长度(279 非压缩格式 214压缩格式)
 * @return int 非0成功 0失败
 */
int fingera_btc_key_encode(const void *key32, void *encoded_key,
                           size_t encoded_key_len);

/**
 * @brief 比特币私钥格式解码
 *
 * @param encoded_key 编码后的私钥
 * @param encoded_key_len 编码后的私钥长度(279 非压缩格式 214压缩格式)
 * @param key32 32字节的私钥
 * @return int 非0成功 0失败
 */
int fingera_btc_key_decode(const void *encoded_key, size_t encoded_key_len,
                           void *key32);

/**
 * @brief 通过私钥获取公钥(64字节)
 *
 * @param key 私钥
 * @param pubkey 公钥64字节的内存
 */
void fingera_btc_key_get_pub(const void *key32, void *pubkey64);

/**
 * @brief 派生公钥(64字节) 和chain_code(32字节)
 *
 * @param encoded_pubkey33 输入公钥的压缩格式
 * @param chain32 输入的chain code
 * @param in_out_pubkey64 输入时是公钥的未压缩 输出派生后的公钥
 * @param out_chain32 输出派生后的chain code
 * @param child
 * @return int 非0成功 0失败
 */
int fingera_btc_pubkey_derive(const void *encoded_pubkey33, const void *chain32,
                              void *in_out_pubkey64, void *out_chain32,
                              uint32_t child);

/**
 * @brief 比特币公钥编码
 *
 * @param pubkey64 64字节公钥
 * @param encoded_pubkey 编码后的公钥
 * @param encoded_pubkey_len 编码后的公钥长度(65未压缩 33压缩)
 * @return int 非0成功 0失败
 */
int fingera_btc_pubkey_encode(const void *pubkey64, void *encoded_pubkey,
                              size_t encoded_pubkey_len);

/**
 * @brief 比特币公钥解码
 *
 * @param encoded_pubkey 编码后的公钥
 * @param encoded_pubkey_len 编码后的公钥长度(65未压缩 33压缩)
 * @param pubkey64 64字节公钥
 * @return int 非0成功 0失败
 */
int fingera_btc_pubkey_decode(const void *encoded_pubkey,
                              size_t encoded_pubkey_len, void *pubkey64);

/**
 * @brief 对32字节的HASH生成签名
 *
 * @param key 32字节的私钥
 * @param hash 32字节的HASH
 * @param signatures 64字节的签名信息
 */
void fingera_btc_key_sign(const void *key32, const void *hash32,
                          void *signatures64);

/**
 * @brief 比特币签名格式编码 注意encoded_sig必须不小于72字节
 *
 * @param signatures64 64字节的签名信息
 * @param encoded_sig 编码后的签名信息(长度不小于72字节)
 * @return size_t 编码后的签名信息长度 0 表示失败
 */
size_t fingera_btc_signature_encode(const void *signatures64,
                                    void *encoded_sig);

/**
 * @brief 比特币签名格式解码
 *
 * @param encoded_sig 编码后的签名
 * @param encoded_sig_len 编码后的签名长度
 * @param signatures64 64字节的签名信息
 * @return int 非0表示成功 0表示失败
 */
int fingera_btc_signature_decode(const void *encoded_sig,
                                 size_t encoded_sig_len, void *signatures64);

/**
 * @brief 校验签名信息
 *
 * @param pubkey64 64字节公钥
 * @param hash32 32字节的HASH
 * @param signatures64 64字节的签名信息
 * @return int 非0表示正确 0表示错误
 */
int fingera_btc_key_verify(const void *pubkey64, const void *hash32,
                           const void *signatures64);

void fingera_btc_key_keyid(const void *key32, int compress, void *keyid20);
void fingera_btc_pubkey_keyid(const void *pubkey64, int compress,
                              void *keyid20);

uint32_t fingera_btc_key_fingerprint(const void *key32, int compress);
uint32_t fingera_btc_pubkey_fingerprint(const void *pubkey64, int compress);

#if defined(__cplusplus)
}
#endif

#endif  // _FINGERA_LIBC_BTC_KEY_H_