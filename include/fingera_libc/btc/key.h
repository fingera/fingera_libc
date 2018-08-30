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
 * @brief 通过私钥获取公钥(64字节)
 *
 * @param key 私钥
 * @param pubkey 公钥64字节的内存
 */
void fingera_btc_key_get_pub(const void *key32, void *pubkey64);

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
 * @brief 校验签名信息
 *
 * @param pubkey64 64字节公钥
 * @param hash32 32字节的HASH
 * @param signatures64 64字节的签名信息
 * @return int 非0表示正确 0表示错误
 */
int fingera_btc_key_verify(const void *pubkey64, const void *hash32,
                           const void *signatures64);

#if defined(__cplusplus)
}
#endif

#endif  // _FINGERA_LIBC_BTC_KEY_H_