/**
 * @brief sha256 sha512 hmac_sha256 hmac_sha512
 *
 * @file sha2.h
 * @author liuyujun@fingera.cn
 * @date 2018-08-22
 */
#ifndef _FINGERA_LIBC_SHA2_H_
#define _FINGERA_LIBC_SHA2_H_

#if defined(__cplusplus)
extern "C" {
#endif

#include <stddef.h>

/**
 * @brief sha256 hash 算法(sha2)
 *
 * @param msg 输入数据
 * @param msg_len 输入数据长度
 * @param hash 输出HASH 长度必须为32个字节
 */
void fingera_sha2_256(const void* msg, size_t msg_len, void* hash);

/**
 * @brief sha512 hash 算法(sha2)
 *
 * @param msg 输入数据
 * @param msg_len 输入数据长度
 * @param hash 输出HASH 长度必须为64个字节
 */
void fingera_sha2_512(const void* msg, size_t msg_len, void* hash);

/**
 * @brief hmac_sha256 hash 算法
 *
 * @param key 输入key
 * @param key_len key长度
 * @param msg 输入数据
 * @param msg_len 数据长度
 * @param hmac 输出HASH 长度必须为32字节
 */
void fingera_hmac_sha256(const void* key, size_t key_len, const void* msg,
                         size_t msg_len, void* hmac);

/**
 * @brief hmac_sha512 hash 算法
 *
 * @param key 输入key
 * @param key_len key长度
 * @param msg 输入数据
 * @param msg_len 数据长度
 * @param hmac 输出HASH 长度必须为64字节
 */
void fingera_hmac_sha512(const void* key, size_t key_len, const void* msg,
                         size_t msg_len, void* hmac);

#if defined(__cplusplus)
}
#endif

#endif  // _FINGERA_LIBC_SHA2_H_