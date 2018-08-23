/**
 * @brief Base58
 * 1. 在编码解码时需要一个缓存，默认1K以下在栈上分配
 *
 * @file base58.h
 * @author liuyujun@fingera.cn
 * @date 2018-08-23
 */
#ifndef _FINGERA_LIBC_BASE58_H_
#define _FINGERA_LIBC_BASE58_H_

#if defined(__cplusplus)
extern "C" {
#endif

#include <stddef.h>

/**
 * @brief 获取BASE58编码的最大长度
 * 1. 请确保编码时输出缓存必须大于等于
 *
 * @param buf_size 需要编码的数据长度
 * @return size_t 最大长度
 */
static inline size_t fingera_to_base58_length(size_t buf_size) {
  return buf_size * 138 / 100 + 2;
}

/**
 * @brief 获取BASE58解码的最大长度
 * 1. 请确保解码时输出缓存必须大于等于
 *
 * @param str_len 需要解码的数据长度
 * @return size_t 最大长度
 */
static inline size_t fingera_from_base58_length(size_t str_len) {
  return str_len * 733 / 1000 + 2;
}

/**
 * @brief BASE58编码
 *
 * @param buf 需要编码的数据
 * @param buf_size 数据长度
 * @param str 输出缓存
 * @return size_t 输出长度
 */
size_t fingera_to_base58(const void *buf, size_t buf_size, char *str);

/**
 * @brief BASE58解码
 *
 * @param str 需要解码的数据
 * @param str_len 数据长度
 * @param buf 输出缓存
 * @return size_t 输出长度
 */
size_t fingera_from_base58(const char *str, size_t str_len, void *buf);

#if defined(__cplusplus)
}
#endif

#endif  // _FINGERA_LIBC_BASE58_H_