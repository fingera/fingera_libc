/**
 * @brief 将关键数据在生命周期结束时在内存中完全清除
 *
 * @file cleanse.h
 * @author liuyujun@fingera.cn
 * @date 2018-08-31
 */
#ifndef _FINGERA_LIBC_CLEANSE_H_
#define _FINGERA_LIBC_CLEANSE_H_

#if defined(__cplusplus)
extern "C" {
#endif

#include <stddef.h>

void fingera_cleanse(void *mem, size_t size);

#if defined(__cplusplus)
}
#endif

#endif  // _FINGERA_LIBC_CLEANSE_H_