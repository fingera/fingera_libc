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
#include <stdint.h>

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

/**
 * @brief 计算merkle树时需要用到
 * 计算出上一层的merkle树
 *
 * @param out 输出hash 32*blocks
 * @param in 输入数据 64*blocks
 * @param blocks 输出输入数量
 */
void fingera_btc_hash256_d64(void *out, const void *in, size_t blocks);

/**
 * @brief 比特币bip32 HASH
 *
 * @param chain_code 32字节
 * @param child 4字节
 * @param header 1字节
 * @param data32 32字节
 * @param out64 输出64字节HASH值
 */
void fingera_btc_bip32_hash(const void *chain_code, uint32_t child,
                            uint8_t header, const void *data32, void *out64);

#if defined(__cplusplus)
}
#endif

#endif  // _FINGERA_LIBC_BTC_HASH_H_