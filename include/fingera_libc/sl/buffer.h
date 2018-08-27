/**
 * @brief 在一定大小以内的申请内存直接放在栈上，因为99%的时候会小于这个值
 *
 * @file buffer.h
 * @author liuyujun@fingera.cn
 * @date 2018-08-27
 */
#ifndef _FINGERA_LIBC_SL_BUFFER_H_
#define _FINGERA_LIBC_SL_BUFFER_H_

#define DEFAULT_STACK_BUFFER 128

#define DECLARE_BUFFER(type, name, real_size)      \
  char name##_stack_buffer_[DEFAULT_STACK_BUFFER]; \
  type *name;                                      \
  int name##_in_heap;                              \
  if (real_size > sizeof(name##_stack_buffer_)) {  \
    name = (type *)malloc(real_size);              \
    name##_in_heap = 1;                            \
  } else {                                         \
    name = (type *)name##_stack_buffer_;           \
    name##_in_heap = 0;                            \
  }

#define FREE_BUFFER(name) \
  if (name##_in_heap) free(name);

#endif  // _FINGERA_LIBC_SL_BUFFER_H_