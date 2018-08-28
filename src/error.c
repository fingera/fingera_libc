#ifdef WIN32
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <errno.h>
#include <fingera_libc/error.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#include <Windows.h>
#endif

void fingera_fatal(const char *func, const char *file, long line,
                   const char *msg, ...) {
  int err = errno;
#ifdef WIN32
  DWORD win_err = GetLastError();
#endif

  fprintf(stderr, "FATAL ");

  va_list args;
  va_start(args, msg);
  vfprintf(stderr, msg, args);
  va_end(args);

  fprintf(stderr, " (%s)(%s:%ld)\n", func, file, line);
  if (err != 0) {
    fprintf(stderr, "\t%s(%d)\n", strerror(err), err);
  }
#ifdef WIN32
  if (win_err != ERROR_SUCCESS) {
    LPVOID msg_buffer;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, win_err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   (char *)&msg_buffer, 0, NULL);
    fprintf(stderr, "\t%s ErrorCode(%08lx)\n", (char *)msg_buffer, win_err);
    LocalFree(msg_buffer);
  }
#endif

  fflush(stderr);
  exit(-1);
}