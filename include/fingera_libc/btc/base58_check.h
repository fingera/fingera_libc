/**
 * @brief Base58Check
 *
 * @file base58_check.h
 * @author liuyujun@fingera.cn
 * @date 2018-08-24
 */
#ifndef _FINGERA_LIBC_BTC_BASE58_CHECK_H_
#define _FINGERA_LIBC_BTC_BASE58_CHECK_H_

#if defined(__cplusplus)
extern "C" {
#endif

#include <fingera_libc/base58.h>

/**
 * @brief 获取BASE58Check编码的最大长度
 * 1. 请确保编码时输出缓存必须大于等于
 *
 * @param buf_size 需要编码的数据长度
 * @param prefix_size 需要编码的前缀长度
 * @return size_t 最大长度
 */
static inline size_t fingera_to_base58_check_length(size_t buf_size,
                                                    size_t prefix_size) {
  return fingera_to_base58_length(buf_size + 4 +
                                  prefix_size);  // checksum 4 byte
}

/**
 * @brief 获取BASE58Check解码的最大长度
 * 1. 请确保解码时输出缓存必须大于等于
 *
 * @param str_len 需要解码的数据长度
 * @return size_t 最大长度
 */
static inline size_t fingera_from_base58_check_length(size_t str_len) {
  // 解码的时候会吧checksum也解到传入的buf中校验并返回结果-4
  return fingera_from_base58_length(str_len);
}

/**
 * @brief BASE58Check编码
 *
 * @param buf 需要编码的数据
 * @param buf_size 数据长度
 * @param str 输出缓存
 * @return size_t 输出长度
 */
size_t fingera_to_base58_check(const void *buf, size_t buf_size,
                               const void *prefix, size_t prefix_size,
                               char *str);

/**
 * @brief BASE58Check解码
 *
 * @param str 需要解码的数据
 * @param str_len 数据长度
 * @param buf 输出缓存
 * @return size_t 输出长度
 */
size_t fingera_from_base58_check(const char *str, size_t str_len, void *buf);

#if defined(__cplusplus)
}
#endif

#endif  // _FINGERA_LIBC_BTC_BASE58_CHECK_H_