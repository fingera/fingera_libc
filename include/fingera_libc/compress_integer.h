/**
 * @brief 整数的压缩算法
 * 1. varint 针对无符号整数
 * 2. zigzag 针对有符号整数
 *
 * @file hex.h
 * @author liuyujun@fingera.cn
 * @date 2018-08-17
 */
#ifndef _FINGERA_LIBC_COMPRESS_INTEGER_H_
#define _FINGERA_LIBC_COMPRESS_INTEGER_H_

#if defined(__cplusplus)
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/**
 * @brief 无符号整数编码
 *
 * @param value 需要压缩的整数
 * @param buf 放入缓冲区（缓冲区大小确保10个字节以上）
 * @return size_t 使用字节数(如果为0则表示失败)
 */
size_t fingera_encode_varint(uint64_t value, void *buf);

/**
 * @brief 无符号整数解码
 *
 * @param buf 读取缓冲区
 * @param size 大小
 * @param out 输出的无符号整数
 * @return size_t 读取的大小(如果为0则表示失败)
 */
size_t fingera_decode_varint(const void *buf, size_t size, uint64_t *out);

/**
 * @brief 带符号整数编码
 *
 * @param value 需要压缩的整数
 * @param buf 放入缓冲区（缓冲区大小确保10个字节以上）
 * @return size_t 使用字节数(如果为0则表示失败)
 */
size_t fingera_encode_zigzag(int64_t value, void *buf);

/**
 * @brief 带符号整数解码
 *
 * @param buf 读取缓冲区
 * @param size 大小
 * @param out 输出的带符号整数
 * @return size_t 读取的大小(如果为0则表示失败)
 */
size_t fingera_decode_zigzag(const void *buf, size_t size, int64_t *out);

#if defined(__cplusplus)
}
#endif

#endif  //_FINGERA_LIBC_COMPRESS_INTEGER_H_