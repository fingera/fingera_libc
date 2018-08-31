#include <fingera_libc/cleanse.h>

#include <string.h>
#if defined(_MSC_VER)
#include <Windows.h>
#endif

void fingera_cleanse(void *mem, size_t size) {
  memset(mem, 0xCC, size);
#if defined(_MSC_VER)
  SecureZeroMemory(mem, size);
#else
  __asm__ __volatile__("" : : "r"(mem) : "memory");
#endif
}