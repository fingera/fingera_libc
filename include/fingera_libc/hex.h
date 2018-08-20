/**
 * @brief HEX的编码和解码
 *
 * @file hex.h
 * @author liuyujun@fingera.cn
 * @date 2018-08-17
 */
#ifndef _FINGERA_LIBC_HEX_H_
#define _FINGERA_LIBC_HEX_H_

#if defined(__cplusplus)
extern "C" {
#endif

#include <stddef.h>

/**
 * @brief 计算数据编码为HEX的长度
 *
 * @param buf_size 数据长度
 * @return size_t HEX编码需要的长度
 */
inline size_t fingera_to_hex_length(size_t buf_size) { return buf_size * 2; }
/**
 * @brief 将数据编码为HEX
 * 1. str的长度必须为fingera_to_hex_length(buf_size)
 * 2. 没有在str的后面增加字符串结束符'\0'
 *
 * @param buf 数据
 * @param buf_size 数据长度
 * @param str HEX编码后的数据
 * @param upper 是否为大写
 */
void fingera_to_hex(const void *buf, size_t buf_size, char *str, int upper);

/**
 * @brief 计算HEX解码后的数据长度
 *
 * @param str_length HEX数据长度
 * @return size_t 解码后的数据长度
 */
inline size_t fingera_from_hex_length(size_t str_length) {
  return (str_length + 1) / 2;
}

/**
 * @brief 将HEX数据解码
 * 1. buf的长度至少为fingera_from_hex_length(str_len)
 * 2. 不一定能全部解码成功 成功多少需要看返回值
 *
 * @param str HEX数据
 * @param str_len HEX数据的长度
 * @param buf 解码后的数据
 * @return size_t 解码成功的数据长度
 */
size_t fingera_from_hex(const char *str, size_t str_len, void *buf);

/**
 * @brief hex_dump到标准输出中
 *
 * @param buf 数据
 * @param buf_size 数据长度
 * @param upper 是否为大写
 */
void fingera_hex_dump(const void *buf, size_t buf_size, int upper);

#if defined(__cplusplus)
}
#endif

#endif  // _FINGERA_LIBC_HEX_H_