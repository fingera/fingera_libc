#include <fingera_libc/error.h>
#include <fingera_libc/random.h>

#ifdef WIN32

#include <windows.h>

///////////////////////////>=Win Vista/////////////////////////////////////////
#if defined(_MSC_VER) && defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0600
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

void fingera_os_rand_bytes(void *buf, size_t buf_size) {
  BCRYPT_ALG_HANDLE hProvider;
  NTSTATUS ret =
      BCryptOpenAlgorithmProvider(&hProvider, BCRYPT_RNG_ALGORITHM, NULL, 0);
  if (ret != STATUS_SUCCESS) {
    FINGERA_FATAL("BCryptOpenAlgorithmProvider %lu", (unsigned int)ret);
  }
  ret = BCryptGenRandom(hProvider, buf, buf_size, 0);
  if (ret != STATUS_SUCCESS) {
    FINGERA_FATAL("BCryptGenRandom %lu", (unsigned int)ret);
  }
  BCryptCloseAlgorithmProvider(hProvider, 0);
}

#else

////////////////////////////<Win Vista/////////////////////////////////////////
#include <wincrypt.h>
#pragma comment(lib, "Advapi32.lib")
void fingera_os_rand_bytes(void *buf, size_t buf_size) {
  HCRYPTPROV hProvider;
  if (!CryptAcquireContextW(&hProvider, NULL, NULL, PROV_RSA_FULL,
                            CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
    FINGERA_FATAL("CryptAcquireContextW");
  }
  if (!CryptGenRandom(hProvider, (DWORD)buf_size, (BYTE *)buf)) {
    FINGERA_FATAL("CryptGenRandom");
  }
  CryptReleaseContext(hProvider, 0);
}

#endif

#else

/////////////////////////////Unix//////////////////////////////////////////////
#include <fcntl.h>
#include <unistd.h>
void fingera_os_rand_bytes(void *buf, size_t buf_size) {
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    FINGERA_FATAL("open /dev/urandom");
  }
  while (buf_size != 0) {
    int r = read(fd, buf, buf_size);
    if (r <= 0) {
      FINGERA_FATAL("read /dev/urandom %d", r);
    }
    buf_size -= (size_t)r;
  }
  close(fd);
}

#endif