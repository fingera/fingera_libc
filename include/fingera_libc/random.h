/**
 * @brief 随机数获取
 *
 * @file random.h
 * @author liuyujun@fingera.cn
 * @date 2018-08-28
 */
#ifndef _FINGERA_LIBC_RANDOM_H_
#define _FINGERA_LIBC_RANDOM_H_

#if defined(__cplusplus)
extern "C" {
#endif

#include <stddef.h>

void fingera_os_rand_bytes(void *buf, size_t buf_size);

#if defined(__cplusplus)
}
#endif

#endif  // _FINGERA_LIBC_RANDOM_H_