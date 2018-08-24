/**
 * @brief Base32
 *
 * @file base32.h
 * @author liuyujun@fingera.cn
 * @date 2018-08-23
 */
#ifndef _FINGERA_LIBC_BASE32_H_
#define _FINGERA_LIBC_BASE32_H_

#if defined(__cplusplus)
extern "C" {
#endif

#include <stddef.h>

/**
 * @brief 获取编码后的长度
 *
 * @param buf_size 需要编码的数据大小
 * @return size_t 编码后的长度
 */
static inline size_t fingera_to_base32_length(size_t buf_size) {
  return ((buf_size + 4) / 5) * 8;
}

/**
 * @brief BASE32编码
 * 1. 编码后的输出str必须大于fingera_to_base32_length
 * 2. 编码函数不追加字符串终结符'\0'
 *
 * @param buf 输入数据
 * @param buf_size 数据大小
 * @param str 编码后的输出
 */
void fingera_to_base32(const void *buf, size_t buf_size, char *str);

/**
 * @brief 不强加字符串，仅仅进行位的转换
 *
 * @param buf 输入数据
 * @param buf_size 数据大小
 * @param str 编码后的输出
 * @return size_t 输出的大小
 */
size_t fingera_to_base32_raw(const void *buf, size_t buf_size, void *out);

/**
 * @brief 获得BASE32解码后的长度
 * 1. 假定数据是合法的，如果部分不合法可能不需要这么长
 *
 * @param str 输入数据
 * @param str_len 数据大小
 * @return size_t 解码后的长度
 */
size_t fingera_from_base32_length(const char *str, size_t str_len);
size_t fingera_from_base32_raw_length(size_t str_len);

/**
 * @brief BASE32解码
 * 1. 解码输出的大小必须为fingera_from_base32_length
 * 2. 解码大小如果不为fingera_from_base32_length则表示没有全部解码成功
 *
 * @param str 输入数据
 * @param str_len 数据长度
 * @param buf 解码输出
 * @return size_t 解码大小
 */
size_t fingera_from_base32(const char *str, size_t str_len, void *buf);

/**
 * @brief 仅仅进行位的转换其他参考 from_base32
 *
 * @param str 输入数据
 * @param str_len 数据长度
 * @param buf 解码输出
 * @return size_t 解码大小
 */
size_t fingera_from_base32_raw(const void *buf, size_t buf_size, void *out);

#if defined(__cplusplus)
}
#endif

#endif  // _FINGERA_LIBC_BASE32_H_