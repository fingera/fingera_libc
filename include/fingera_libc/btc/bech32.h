/**
 * @brief bech32 比特币新地址编码
 *
 * @file bech32.h
 * @author liuyujun@fingera.cn
 * @date 2018-08-24
 */
#ifndef _FINGERA_LIBC_BECH32_H_
#define _FINGERA_LIBC_BECH32_H_

#if defined(__cplusplus)
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/**
 * @brief 获取编码后的长度
 *
 * @param hrp_len 头部长度
 * @param b32_size 数据长度
 * @return size_t 编码后的长度
 */
static inline size_t fingera_bech32_encode_length(size_t hrp_len,
                                                  size_t b32_size) {
  return hrp_len + b32_size + 7;
}

/**
 * @brief 执行bech32编码
 * 1. 返回结果的长度和fingera_bech32_encode_length一致
 *
 * @param hrp 头部数据
 * @param hrp_len 头部长度
 * @param b32 数据
 * @param b32_size 数据长度
 * @param result 返回编码结果
 */
void fingera_bech32_encode(const char *hrp, size_t hrp_len, const uint8_t *b32,
                           size_t b32_size, char *result);

/**
 * @brief bech32解码
 * 1. hrp_size传入时指出头部长度，如果长度不足会造成编码失败返回0
 * 2. hrp_size传出时会指出hrp中的长度
 * 3. 返回值大于等于0表示编码成功代表b32的长度 小于0表示失败
 * 4. 关于b32的长度确定为'1'的位置到'\0'的位置减去6 简单点就str_len-7
 *
 * @param str 编码的数据
 * @param str_len 编码数据长度
 * @param hrp 解码的头部数据
 * @param hrp_size 传入传出解码头部数据的长度
 * @param b32 解码的基础数据
 * @return int 返回基础数据的长度
 */
int fingera_bech32_decode(const char *str, size_t str_len, char *hrp,
                          size_t *hrp_size, void *b32);

#if defined(__cplusplus)
}
#endif

#endif  // _FINGERA_LIBC_BECH32_H_