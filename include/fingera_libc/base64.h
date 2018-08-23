/**
 * @brief BASE64编码和解码 支持 标准编码 和 URL安全编码
 * 1. URL安全编码没有包含pad(=)
 *
 * @file base64.h
 * @author liuyujun@fingera.cn
 * @date 2018-08-17
 */
#ifndef _FINGERA_LIBC_BASE64_H_
#define _FINGERA_LIBC_BASE64_H_

#if defined(__cplusplus)
extern "C" {
#endif

#include <stddef.h>

/**
 * @brief 获取标准BASE64编码后的长度
 *
 * @param buf_size 数据长度
 * @return size_t 编码后的长度
 */
static inline size_t fingera_to_base64_length(size_t buf_size) {
  return ((buf_size + 2) / 3) * 4;
}

/**
 * @brief 获取URL安全BASE64编码后的长度
 * 1. URL安全编码没有要求在后面追加'='
 *
 * @param buf_size 数据长度
 * @return size_t 编码后的长度
 */
static inline size_t fingera_to_base64_urlsafe_length(size_t buf_size) {
  size_t tail = buf_size % 3;
  size_t len = (buf_size / 3) * 4;
  if (tail == 1)
    len += 2;
  else if (tail == 2)
    len += 3;
  return len;
}

/**
 * @brief 标准BASE64编码
 * 1. 输出的字符串请保留 fingera_to_base64_length() 获取的长度
 * 2. 输出的字符串不会在后面追加终结符'\0'
 *
 * @param buf 数据
 * @param buf_size 数据长度
 * @param str 编码输出的字符串
 */
void fingera_to_base64(const void *buf, size_t buf_size, char *str);

/**
 * @brief URL安全的BASE64编码
 * 1. 输出的字符串请保留 fingera_to_base64_urlsafe_length() 获取的长度
 * 2. 不会在后面追加终结符'\0'
 * 3. 不会追加'='让编码数据保持4字节对齐
 *
 * @param buf 数据
 * @param buf_size 数据长度
 * @param str 编码输出的字符串
 */
void fingera_to_base64_urlsafe(const void *buf, size_t buf_size, char *str);

/**
 * @brief 获得URL安全的BASE64解码长度
 * 1. 假定是合法的BASE64字符串
 *
 * @param str_len 编码长度
 * @return size_t 解码长度
 */
static inline size_t fingera_from_base64_urlsafe_length(size_t str_len) {
  size_t tail = str_len % 4;
  size_t len = (str_len / 4) * 3;
  if (tail == 2)
    len++;
  else if (tail == 3)
    len += 2;
  return len;
}
/**
 * @brief 标准BASE64解码长度
 * 1. 假定数据是合法的BASE64数据
 *
 * @param str_len 编码的长度
 * @return size_t 解码后的长度
 */
static inline size_t fingera_from_base64_length(const char *str,
                                                size_t str_len) {
  if (str_len > 0 && str[str_len - 1] == '=') {
    str_len--;
    if (str_len > 0 && str[str_len - 1] == '=') str_len--;
  }
  return fingera_from_base64_urlsafe_length(str_len);
}

/**
 * @brief 标准BASE64解码
 *
 * @param str 编码数据
 * @param str_len 编码数据长度
 * @param buf 解码数据
 * @return size_t 解码后数据长度
 */
size_t fingera_from_base64(const char *str, size_t str_len, void *buf);

/**
 * @brief URL安全BASE64解码
 *
 * @param str 编码数据
 * @param str_len 编码数据长度
 * @param buf 解码数据
 * @return size_t 解码后数据长度
 */
size_t fingera_from_base64_urlsafe(const char *str, size_t str_len, void *buf);

#if defined(__cplusplus)
}
#endif

#endif  // _FINGERA_LIBC_BASE64_H_