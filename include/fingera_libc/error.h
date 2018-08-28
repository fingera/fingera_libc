/**
 * @brief 系统错误
 *
 * @file error.h
 * @author liuyujun@fingera.cn
 * @date 2018-08-28
 */
#ifndef _FINGERA_LIBC_ERROR_H_
#define _FINGERA_LIBC_ERROR_H_

#if defined(__cplusplus)
extern "C" {
#endif

void fingera_fatal(const char *func, const char *file, long line,
                   const char *msg, ...);

#define FINGERA_FATAL(msg, ...) \
  fingera_fatal(__func__, __FILE__, __LINE__, msg, ##__VA_ARGS__)

#if defined(__cplusplus)
}
#endif

#endif  // _FINGERA_LIBC_ERROR_H_