/**
 * @brief 比特币的hash算法
 * 1. hash256(x) = sha256(sha256(x))
 * 2. hash160(x) = ripemd160(sha256(x))
 *
 * @file btc_hash.h
 * @author liuyujun@fingera.cn
 * @date 2018-08-22
 */
#ifndef _FINGERA_LIBC_BTC_HASH_H_
#define _FINGERA_LIBC_BTC_HASH_H_

#if defined(__cplusplus)
extern "C" {
#endif

#include <stddef.h>

/**
 * @brief 计算hash160 ripemd160(sha256(x))
 *
 * @param msg 输入数据
 * @param msg_len 数据长度
 * @param hash 输出HASH 长度必须为20个字节
 */
void fingera_btc_hash160(const void *msg, size_t msg_len, void *hash);

/**
 * @brief 计算hash256 sha256(sha256(x))
 *
 * @param msg 输入数据
 * @param msg_len 数据长度
 * @param hash 输出HASH 长度必须为32个字节
 */
void fingera_btc_hash256(const void *msg, size_t msg_len, void *hash);

void fingera_btc_hash256_d64(void *out, const void *in, size_t blocks);

#if defined(__cplusplus)
}
#endif

#endif  // _FINGERA_LIBC_BTC_HASH_H_