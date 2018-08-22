
#include <fingera_libc/endian.h>
#include <fingera_libc/hash/ripemd160.h>
#include <stdint.h>
#include <string.h>

/********************************************************************/
/* ROL(x, n) cyclically rotates x over n bits to the left */
/* x must be of an unsigned 32 bits type and 0 <= n < 32. */
#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* the five basic functions F(), G() and H() */
#define F(x, y, z) ((x) ^ (y) ^ (z))
#define G(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define H(x, y, z) (((x) | ~(y)) ^ (z))
#define I(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define J(x, y, z) ((x) ^ ((y) | ~(z)))

/* the ten basic operations FF() through III() */
#define FF(a, b, c, d, e, x, s)    \
  {                                \
    (a) += F((b), (c), (d)) + (x); \
    (a) = ROL((a), (s)) + (e);     \
    (c) = ROL((c), 10);            \
  }
#define GG(a, b, c, d, e, x, s)                   \
  {                                               \
    (a) += G((b), (c), (d)) + (x) + 0x5a827999UL; \
    (a) = ROL((a), (s)) + (e);                    \
    (c) = ROL((c), 10);                           \
  }
#define HH(a, b, c, d, e, x, s)                   \
  {                                               \
    (a) += H((b), (c), (d)) + (x) + 0x6ed9eba1UL; \
    (a) = ROL((a), (s)) + (e);                    \
    (c) = ROL((c), 10);                           \
  }
#define II(a, b, c, d, e, x, s)                   \
  {                                               \
    (a) += I((b), (c), (d)) + (x) + 0x8f1bbcdcUL; \
    (a) = ROL((a), (s)) + (e);                    \
    (c) = ROL((c), 10);                           \
  }
#define JJ(a, b, c, d, e, x, s)                   \
  {                                               \
    (a) += J((b), (c), (d)) + (x) + 0xa953fd4eUL; \
    (a) = ROL((a), (s)) + (e);                    \
    (c) = ROL((c), 10);                           \
  }
#define FFF(a, b, c, d, e, x, s)   \
  {                                \
    (a) += F((b), (c), (d)) + (x); \
    (a) = ROL((a), (s)) + (e);     \
    (c) = ROL((c), 10);            \
  }
#define GGG(a, b, c, d, e, x, s)                  \
  {                                               \
    (a) += G((b), (c), (d)) + (x) + 0x7a6d76e9UL; \
    (a) = ROL((a), (s)) + (e);                    \
    (c) = ROL((c), 10);                           \
  }
#define HHH(a, b, c, d, e, x, s)                  \
  {                                               \
    (a) += H((b), (c), (d)) + (x) + 0x6d703ef3UL; \
    (a) = ROL((a), (s)) + (e);                    \
    (c) = ROL((c), 10);                           \
  }
#define III(a, b, c, d, e, x, s)                  \
  {                                               \
    (a) += I((b), (c), (d)) + (x) + 0x5c4dd124UL; \
    (a) = ROL((a), (s)) + (e);                    \
    (c) = ROL((c), 10);                           \
  }
#define JJJ(a, b, c, d, e, x, s)                  \
  {                                               \
    (a) += J((b), (c), (d)) + (x) + 0x50a28be6UL; \
    (a) = ROL((a), (s)) + (e);                    \
    (c) = ROL((c), 10);                           \
  }

/********************************************************************/

static void ripemd160_transform(uint32_t *s, const void *chunk) {
  uint32_t aa = s[0], bb = s[1], cc = s[2], dd = s[3], ee = s[4];
  uint32_t aaa = s[0], bbb = s[1], ccc = s[2], ddd = s[3], eee = s[4];

  uint32_t X0 = le32(chunk, 0 * 4), X1 = le32(chunk, 1 * 4);
  uint32_t X2 = le32(chunk, 2 * 4), X3 = le32(chunk, 3 * 4);
  uint32_t X4 = le32(chunk, 4 * 4), X5 = le32(chunk, 5 * 4);
  uint32_t X6 = le32(chunk, 6 * 4), X7 = le32(chunk, 7 * 4);
  uint32_t X8 = le32(chunk, 8 * 4), X9 = le32(chunk, 9 * 4);
  uint32_t X10 = le32(chunk, 10 * 4), X11 = le32(chunk, 11 * 4);
  uint32_t X12 = le32(chunk, 12 * 4), X13 = le32(chunk, 13 * 4);
  uint32_t X14 = le32(chunk, 14 * 4), X15 = le32(chunk, 15 * 4);

  /* round 1 */
  FF(aa, bb, cc, dd, ee, X0, 11);
  FF(ee, aa, bb, cc, dd, X1, 14);
  FF(dd, ee, aa, bb, cc, X2, 15);
  FF(cc, dd, ee, aa, bb, X3, 12);
  FF(bb, cc, dd, ee, aa, X4, 5);
  FF(aa, bb, cc, dd, ee, X5, 8);
  FF(ee, aa, bb, cc, dd, X6, 7);
  FF(dd, ee, aa, bb, cc, X7, 9);
  FF(cc, dd, ee, aa, bb, X8, 11);
  FF(bb, cc, dd, ee, aa, X9, 13);
  FF(aa, bb, cc, dd, ee, X10, 14);
  FF(ee, aa, bb, cc, dd, X11, 15);
  FF(dd, ee, aa, bb, cc, X12, 6);
  FF(cc, dd, ee, aa, bb, X13, 7);
  FF(bb, cc, dd, ee, aa, X14, 9);
  FF(aa, bb, cc, dd, ee, X15, 8);

  /* round 2 */
  GG(ee, aa, bb, cc, dd, X7, 7);
  GG(dd, ee, aa, bb, cc, X4, 6);
  GG(cc, dd, ee, aa, bb, X13, 8);
  GG(bb, cc, dd, ee, aa, X1, 13);
  GG(aa, bb, cc, dd, ee, X10, 11);
  GG(ee, aa, bb, cc, dd, X6, 9);
  GG(dd, ee, aa, bb, cc, X15, 7);
  GG(cc, dd, ee, aa, bb, X3, 15);
  GG(bb, cc, dd, ee, aa, X12, 7);
  GG(aa, bb, cc, dd, ee, X0, 12);
  GG(ee, aa, bb, cc, dd, X9, 15);
  GG(dd, ee, aa, bb, cc, X5, 9);
  GG(cc, dd, ee, aa, bb, X2, 11);
  GG(bb, cc, dd, ee, aa, X14, 7);
  GG(aa, bb, cc, dd, ee, X11, 13);
  GG(ee, aa, bb, cc, dd, X8, 12);

  /* round 3 */
  HH(dd, ee, aa, bb, cc, X3, 11);
  HH(cc, dd, ee, aa, bb, X10, 13);
  HH(bb, cc, dd, ee, aa, X14, 6);
  HH(aa, bb, cc, dd, ee, X4, 7);
  HH(ee, aa, bb, cc, dd, X9, 14);
  HH(dd, ee, aa, bb, cc, X15, 9);
  HH(cc, dd, ee, aa, bb, X8, 13);
  HH(bb, cc, dd, ee, aa, X1, 15);
  HH(aa, bb, cc, dd, ee, X2, 14);
  HH(ee, aa, bb, cc, dd, X7, 8);
  HH(dd, ee, aa, bb, cc, X0, 13);
  HH(cc, dd, ee, aa, bb, X6, 6);
  HH(bb, cc, dd, ee, aa, X13, 5);
  HH(aa, bb, cc, dd, ee, X11, 12);
  HH(ee, aa, bb, cc, dd, X5, 7);
  HH(dd, ee, aa, bb, cc, X12, 5);

  /* round 4 */
  II(cc, dd, ee, aa, bb, X1, 11);
  II(bb, cc, dd, ee, aa, X9, 12);
  II(aa, bb, cc, dd, ee, X11, 14);
  II(ee, aa, bb, cc, dd, X10, 15);
  II(dd, ee, aa, bb, cc, X0, 14);
  II(cc, dd, ee, aa, bb, X8, 15);
  II(bb, cc, dd, ee, aa, X12, 9);
  II(aa, bb, cc, dd, ee, X4, 8);
  II(ee, aa, bb, cc, dd, X13, 9);
  II(dd, ee, aa, bb, cc, X3, 14);
  II(cc, dd, ee, aa, bb, X7, 5);
  II(bb, cc, dd, ee, aa, X15, 6);
  II(aa, bb, cc, dd, ee, X14, 8);
  II(ee, aa, bb, cc, dd, X5, 6);
  II(dd, ee, aa, bb, cc, X6, 5);
  II(cc, dd, ee, aa, bb, X2, 12);

  /* round 5 */
  JJ(bb, cc, dd, ee, aa, X4, 9);
  JJ(aa, bb, cc, dd, ee, X0, 15);
  JJ(ee, aa, bb, cc, dd, X5, 5);
  JJ(dd, ee, aa, bb, cc, X9, 11);
  JJ(cc, dd, ee, aa, bb, X7, 6);
  JJ(bb, cc, dd, ee, aa, X12, 8);
  JJ(aa, bb, cc, dd, ee, X2, 13);
  JJ(ee, aa, bb, cc, dd, X10, 12);
  JJ(dd, ee, aa, bb, cc, X14, 5);
  JJ(cc, dd, ee, aa, bb, X1, 12);
  JJ(bb, cc, dd, ee, aa, X3, 13);
  JJ(aa, bb, cc, dd, ee, X8, 14);
  JJ(ee, aa, bb, cc, dd, X11, 11);
  JJ(dd, ee, aa, bb, cc, X6, 8);
  JJ(cc, dd, ee, aa, bb, X15, 5);
  JJ(bb, cc, dd, ee, aa, X13, 6);

  /* parallel round 1 */
  JJJ(aaa, bbb, ccc, ddd, eee, X5, 8);
  JJJ(eee, aaa, bbb, ccc, ddd, X14, 9);
  JJJ(ddd, eee, aaa, bbb, ccc, X7, 9);
  JJJ(ccc, ddd, eee, aaa, bbb, X0, 11);
  JJJ(bbb, ccc, ddd, eee, aaa, X9, 13);
  JJJ(aaa, bbb, ccc, ddd, eee, X2, 15);
  JJJ(eee, aaa, bbb, ccc, ddd, X11, 15);
  JJJ(ddd, eee, aaa, bbb, ccc, X4, 5);
  JJJ(ccc, ddd, eee, aaa, bbb, X13, 7);
  JJJ(bbb, ccc, ddd, eee, aaa, X6, 7);
  JJJ(aaa, bbb, ccc, ddd, eee, X15, 8);
  JJJ(eee, aaa, bbb, ccc, ddd, X8, 11);
  JJJ(ddd, eee, aaa, bbb, ccc, X1, 14);
  JJJ(ccc, ddd, eee, aaa, bbb, X10, 14);
  JJJ(bbb, ccc, ddd, eee, aaa, X3, 12);
  JJJ(aaa, bbb, ccc, ddd, eee, X12, 6);

  /* parallel round 2 */
  III(eee, aaa, bbb, ccc, ddd, X6, 9);
  III(ddd, eee, aaa, bbb, ccc, X11, 13);
  III(ccc, ddd, eee, aaa, bbb, X3, 15);
  III(bbb, ccc, ddd, eee, aaa, X7, 7);
  III(aaa, bbb, ccc, ddd, eee, X0, 12);
  III(eee, aaa, bbb, ccc, ddd, X13, 8);
  III(ddd, eee, aaa, bbb, ccc, X5, 9);
  III(ccc, ddd, eee, aaa, bbb, X10, 11);
  III(bbb, ccc, ddd, eee, aaa, X14, 7);
  III(aaa, bbb, ccc, ddd, eee, X15, 7);
  III(eee, aaa, bbb, ccc, ddd, X8, 12);
  III(ddd, eee, aaa, bbb, ccc, X12, 7);
  III(ccc, ddd, eee, aaa, bbb, X4, 6);
  III(bbb, ccc, ddd, eee, aaa, X9, 15);
  III(aaa, bbb, ccc, ddd, eee, X1, 13);
  III(eee, aaa, bbb, ccc, ddd, X2, 11);

  /* parallel round 3 */
  HHH(ddd, eee, aaa, bbb, ccc, X15, 9);
  HHH(ccc, ddd, eee, aaa, bbb, X5, 7);
  HHH(bbb, ccc, ddd, eee, aaa, X1, 15);
  HHH(aaa, bbb, ccc, ddd, eee, X3, 11);
  HHH(eee, aaa, bbb, ccc, ddd, X7, 8);
  HHH(ddd, eee, aaa, bbb, ccc, X14, 6);
  HHH(ccc, ddd, eee, aaa, bbb, X6, 6);
  HHH(bbb, ccc, ddd, eee, aaa, X9, 14);
  HHH(aaa, bbb, ccc, ddd, eee, X11, 12);
  HHH(eee, aaa, bbb, ccc, ddd, X8, 13);
  HHH(ddd, eee, aaa, bbb, ccc, X12, 5);
  HHH(ccc, ddd, eee, aaa, bbb, X2, 14);
  HHH(bbb, ccc, ddd, eee, aaa, X10, 13);
  HHH(aaa, bbb, ccc, ddd, eee, X0, 13);
  HHH(eee, aaa, bbb, ccc, ddd, X4, 7);
  HHH(ddd, eee, aaa, bbb, ccc, X13, 5);

  /* parallel round 4 */
  GGG(ccc, ddd, eee, aaa, bbb, X8, 15);
  GGG(bbb, ccc, ddd, eee, aaa, X6, 5);
  GGG(aaa, bbb, ccc, ddd, eee, X4, 8);
  GGG(eee, aaa, bbb, ccc, ddd, X1, 11);
  GGG(ddd, eee, aaa, bbb, ccc, X3, 14);
  GGG(ccc, ddd, eee, aaa, bbb, X11, 14);
  GGG(bbb, ccc, ddd, eee, aaa, X15, 6);
  GGG(aaa, bbb, ccc, ddd, eee, X0, 14);
  GGG(eee, aaa, bbb, ccc, ddd, X5, 6);
  GGG(ddd, eee, aaa, bbb, ccc, X12, 9);
  GGG(ccc, ddd, eee, aaa, bbb, X2, 12);
  GGG(bbb, ccc, ddd, eee, aaa, X13, 9);
  GGG(aaa, bbb, ccc, ddd, eee, X9, 12);
  GGG(eee, aaa, bbb, ccc, ddd, X7, 5);
  GGG(ddd, eee, aaa, bbb, ccc, X10, 15);
  GGG(ccc, ddd, eee, aaa, bbb, X14, 8);

  /* parallel round 5 */
  FFF(bbb, ccc, ddd, eee, aaa, X12, 8);
  FFF(aaa, bbb, ccc, ddd, eee, X15, 5);
  FFF(eee, aaa, bbb, ccc, ddd, X10, 12);
  FFF(ddd, eee, aaa, bbb, ccc, X4, 9);
  FFF(ccc, ddd, eee, aaa, bbb, X1, 12);
  FFF(bbb, ccc, ddd, eee, aaa, X5, 5);
  FFF(aaa, bbb, ccc, ddd, eee, X8, 14);
  FFF(eee, aaa, bbb, ccc, ddd, X7, 6);
  FFF(ddd, eee, aaa, bbb, ccc, X6, 8);
  FFF(ccc, ddd, eee, aaa, bbb, X2, 13);
  FFF(bbb, ccc, ddd, eee, aaa, X13, 6);
  FFF(aaa, bbb, ccc, ddd, eee, X14, 5);
  FFF(eee, aaa, bbb, ccc, ddd, X0, 15);
  FFF(ddd, eee, aaa, bbb, ccc, X3, 13);
  FFF(ccc, ddd, eee, aaa, bbb, X9, 11);
  FFF(bbb, ccc, ddd, eee, aaa, X11, 11);

  /* combine results */
  ddd += cc + s[1]; /* final result for s[0] */
  s[1] = s[2] + dd + eee;
  s[2] = s[3] + ee + aaa;
  s[3] = s[4] + aa + bbb;
  s[4] = s[0] + bb + ccc;
  s[0] = ddd;
}

void fingera_ripemd160(const void *msg, size_t msg_len, void *hash) {
  uint8_t last_chunk[64];
  uint32_t digest[5] = {0x67452301UL, 0xEFCDAB89UL, 0x98BADCFEUL, 0x10325476UL,
                        0xC3D2E1F0UL};
  const uint8_t *msg_buf = (const uint8_t *)msg;
  uint32_t *out = (uint32_t *)hash;
  uint64_t chunk_end = htole64((uint64_t)msg_len << 3);
  while (msg_len >= 64) {
    ripemd160_transform(digest, msg_buf);
    msg_len -= 64;
    msg_buf += 64;
  }
  memset(last_chunk, 0, sizeof(last_chunk));
  memcpy(last_chunk, msg_buf, msg_len);
  last_chunk[msg_len] = 0x80;

  if (msg_len > 55) {
    ripemd160_transform(digest, last_chunk);
    memset(last_chunk, 0, 64);
  }

  *(uint64_t *)&last_chunk[56] = chunk_end;
  ripemd160_transform(digest, last_chunk);

  out[0] = htole32(digest[0]);
  out[1] = htole32(digest[1]);
  out[2] = htole32(digest[2]);
  out[3] = htole32(digest[3]);
  out[4] = htole32(digest[4]);
}