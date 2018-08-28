#include <fingera_libc/error.h>
#include <fingera_libc/random.h>

#ifdef WIN32

#include <Windows.h>
#include <wincrypt.h>
#pragma comment(lib, "Advapi32.lib")

void fingera_os_rand_bytes(void *buf, size_t buf_size) {
  HCRYPTPROV hProvider;
  if (!CryptAcquireContextW(&hProvider, NULL, NULL, PROV_RSA_FULL,
                            CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
    FINGERA_FATAL("CryptAcquireContextW");
  }
  if (!CryptGenRandom(hProvider, (DWORD)buf_size, buf)) {
    FINGERA_FATAL("CryptGenRandom");
  }
  CryptReleaseContext(hProvider, 0);
}
#else

#include <fcntl.h>
#include <unistd.h>

void fingera_os_rand_bytes(void *buf, size_t buf_size) {
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    FINGERA_FATAL("open /dev/urandom");
  }
  while (buf_size > 0) {
    int r = read(fd, buf, buf_size);
    if (r <= 0) {
      FINGERA_FATAL("read /dev/urandom %d", r);
    }
    buf_size -= (size_t)r;
  }
}

#endif