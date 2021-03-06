/**
 * @brief ripemd160
 *
 * @file ripemd160.h
 * @author liuyujun@fingera.cn
 * @date 2018-08-22
 */
#ifndef _FINGERA_LIBC_RIPEMD160_H_
#define _FINGERA_LIBC_RIPEMD160_H_

#if defined(__cplusplus)
extern "C" {
#endif

#include <stddef.h>

/**
 * @brief ripemd160算法
 *
 * @param msg 输入数据
 * @param msg_len 数据长度
 * @param hash 输出HASH 长度必须为20字节
 */
void fingera_ripemd160(const void *msg, size_t msg_len, void *hash);

#if defined(__cplusplus)
}
#endif

#endif  // _FINGERA_LIBC_RIPEMD160_H_