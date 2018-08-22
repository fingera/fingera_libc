#include <fingera_libc/endian.h>
#include <fingera_libc/hash/sha1.h>
#include <stdint.h>
#include <string.h>

/********************************************************************/
#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

#define Ch(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define Maj(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))
#define Sigma032(x) (ROL(x, 30) ^ ROL(x, 19) ^ ROL(x, 10))
#define Sigma132(x) (ROL(x, 26) ^ ROL(x, 21) ^ ROL(x, 7))
#define sigma032(x) (ROL(x, 25) ^ ROL(x, 14) ^ ((x) >> 3))
#define sigma132(x) (ROL(x, 15) ^ ROL(x, 13) ^ ((x) >> 10))
#define Sigma064(x) (ROL64(x, 36) ^ ROL64(x, 30) ^ ROL64(x, 25))
#define Sigma164(x) (ROL64(x, 50) ^ ROL64(x, 46) ^ ROL64(x, 23))
#define sigma064(x) (ROL64(x, 63) ^ ROL64(x, 56) ^ ((x) >> 7))
#define sigma164(x) (ROL64(x, 45) ^ ROL64(x, 3) ^ ((x) >> 6))

#define ROUND32(a, b, c, d, e, f, g, h, k)                       \
  {                                                              \
    uint32_t t1 = (h) + Sigma132((e)) + Ch((e), (f), (g)) + (k); \
    uint32_t t2 = Sigma032((a)) + Maj((a), (b), (c));            \
    (d) += t1;                                                   \
    (h) = t1 + t2;                                               \
  }
#define ROUND64(a, b, c, d, e, f, g, h, k, w)                          \
  {                                                                    \
    uint64_t t1 = (h) + Sigma164((e)) + Ch((e), (f), (g)) + (k) + (w); \
    uint64_t t2 = Sigma064((a)) + Maj((a), (b), (c));                  \
    (d) += t1;                                                         \
    (h) = t1 + t2;                                                     \
  }
/********************************************************************/

static void sha256_transform(uint32_t *s, const void *chunk) {
  uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6],
           h = s[7];
  uint32_t w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;

  ROUND32(a, b, c, d, e, f, g, h, 0x428a2f98 + (w0 = be32(chunk, 0)));
  ROUND32(h, a, b, c, d, e, f, g, 0x71374491 + (w1 = be32(chunk, 4)));
  ROUND32(g, h, a, b, c, d, e, f, 0xb5c0fbcf + (w2 = be32(chunk, 8)));
  ROUND32(f, g, h, a, b, c, d, e, 0xe9b5dba5 + (w3 = be32(chunk, 12)));
  ROUND32(e, f, g, h, a, b, c, d, 0x3956c25b + (w4 = be32(chunk, 16)));
  ROUND32(d, e, f, g, h, a, b, c, 0x59f111f1 + (w5 = be32(chunk, 20)));
  ROUND32(c, d, e, f, g, h, a, b, 0x923f82a4 + (w6 = be32(chunk, 24)));
  ROUND32(b, c, d, e, f, g, h, a, 0xab1c5ed5 + (w7 = be32(chunk, 28)));
  ROUND32(a, b, c, d, e, f, g, h, 0xd807aa98 + (w8 = be32(chunk, 32)));
  ROUND32(h, a, b, c, d, e, f, g, 0x12835b01 + (w9 = be32(chunk, 36)));
  ROUND32(g, h, a, b, c, d, e, f, 0x243185be + (w10 = be32(chunk, 40)));
  ROUND32(f, g, h, a, b, c, d, e, 0x550c7dc3 + (w11 = be32(chunk, 44)));
  ROUND32(e, f, g, h, a, b, c, d, 0x72be5d74 + (w12 = be32(chunk, 48)));
  ROUND32(d, e, f, g, h, a, b, c, 0x80deb1fe + (w13 = be32(chunk, 52)));
  ROUND32(c, d, e, f, g, h, a, b, 0x9bdc06a7 + (w14 = be32(chunk, 56)));
  ROUND32(b, c, d, e, f, g, h, a, 0xc19bf174 + (w15 = be32(chunk, 60)));
  ROUND32(a, b, c, d, e, f, g, h,
          0xe49b69c1 + (w0 += sigma132(w14) + w9 + sigma032(w1)));
  ROUND32(h, a, b, c, d, e, f, g,
          0xefbe4786 + (w1 += sigma132(w15) + w10 + sigma032(w2)));
  ROUND32(g, h, a, b, c, d, e, f,
          0x0fc19dc6 + (w2 += sigma132(w0) + w11 + sigma032(w3)));
  ROUND32(f, g, h, a, b, c, d, e,
          0x240ca1cc + (w3 += sigma132(w1) + w12 + sigma032(w4)));
  ROUND32(e, f, g, h, a, b, c, d,
          0x2de92c6f + (w4 += sigma132(w2) + w13 + sigma032(w5)));
  ROUND32(d, e, f, g, h, a, b, c,
          0x4a7484aa + (w5 += sigma132(w3) + w14 + sigma032(w6)));
  ROUND32(c, d, e, f, g, h, a, b,
          0x5cb0a9dc + (w6 += sigma132(w4) + w15 + sigma032(w7)));
  ROUND32(b, c, d, e, f, g, h, a,
          0x76f988da + (w7 += sigma132(w5) + w0 + sigma032(w8)));
  ROUND32(a, b, c, d, e, f, g, h,
          0x983e5152 + (w8 += sigma132(w6) + w1 + sigma032(w9)));
  ROUND32(h, a, b, c, d, e, f, g,
          0xa831c66d + (w9 += sigma132(w7) + w2 + sigma032(w10)));
  ROUND32(g, h, a, b, c, d, e, f,
          0xb00327c8 + (w10 += sigma132(w8) + w3 + sigma032(w11)));
  ROUND32(f, g, h, a, b, c, d, e,
          0xbf597fc7 + (w11 += sigma132(w9) + w4 + sigma032(w12)));
  ROUND32(e, f, g, h, a, b, c, d,
          0xc6e00bf3 + (w12 += sigma132(w10) + w5 + sigma032(w13)));
  ROUND32(d, e, f, g, h, a, b, c,
          0xd5a79147 + (w13 += sigma132(w11) + w6 + sigma032(w14)));
  ROUND32(c, d, e, f, g, h, a, b,
          0x06ca6351 + (w14 += sigma132(w12) + w7 + sigma032(w15)));
  ROUND32(b, c, d, e, f, g, h, a,
          0x14292967 + (w15 += sigma132(w13) + w8 + sigma032(w0)));
  ROUND32(a, b, c, d, e, f, g, h,
          0x27b70a85 + (w0 += sigma132(w14) + w9 + sigma032(w1)));
  ROUND32(h, a, b, c, d, e, f, g,
          0x2e1b2138 + (w1 += sigma132(w15) + w10 + sigma032(w2)));
  ROUND32(g, h, a, b, c, d, e, f,
          0x4d2c6dfc + (w2 += sigma132(w0) + w11 + sigma032(w3)));
  ROUND32(f, g, h, a, b, c, d, e,
          0x53380d13 + (w3 += sigma132(w1) + w12 + sigma032(w4)));
  ROUND32(e, f, g, h, a, b, c, d,
          0x650a7354 + (w4 += sigma132(w2) + w13 + sigma032(w5)));
  ROUND32(d, e, f, g, h, a, b, c,
          0x766a0abb + (w5 += sigma132(w3) + w14 + sigma032(w6)));
  ROUND32(c, d, e, f, g, h, a, b,
          0x81c2c92e + (w6 += sigma132(w4) + w15 + sigma032(w7)));
  ROUND32(b, c, d, e, f, g, h, a,
          0x92722c85 + (w7 += sigma132(w5) + w0 + sigma032(w8)));
  ROUND32(a, b, c, d, e, f, g, h,
          0xa2bfe8a1 + (w8 += sigma132(w6) + w1 + sigma032(w9)));
  ROUND32(h, a, b, c, d, e, f, g,
          0xa81a664b + (w9 += sigma132(w7) + w2 + sigma032(w10)));
  ROUND32(g, h, a, b, c, d, e, f,
          0xc24b8b70 + (w10 += sigma132(w8) + w3 + sigma032(w11)));
  ROUND32(f, g, h, a, b, c, d, e,
          0xc76c51a3 + (w11 += sigma132(w9) + w4 + sigma032(w12)));
  ROUND32(e, f, g, h, a, b, c, d,
          0xd192e819 + (w12 += sigma132(w10) + w5 + sigma032(w13)));
  ROUND32(d, e, f, g, h, a, b, c,
          0xd6990624 + (w13 += sigma132(w11) + w6 + sigma032(w14)));
  ROUND32(c, d, e, f, g, h, a, b,
          0xf40e3585 + (w14 += sigma132(w12) + w7 + sigma032(w15)));
  ROUND32(b, c, d, e, f, g, h, a,
          0x106aa070 + (w15 += sigma132(w13) + w8 + sigma032(w0)));
  ROUND32(a, b, c, d, e, f, g, h,
          0x19a4c116 + (w0 += sigma132(w14) + w9 + sigma032(w1)));
  ROUND32(h, a, b, c, d, e, f, g,
          0x1e376c08 + (w1 += sigma132(w15) + w10 + sigma032(w2)));
  ROUND32(g, h, a, b, c, d, e, f,
          0x2748774c + (w2 += sigma132(w0) + w11 + sigma032(w3)));
  ROUND32(f, g, h, a, b, c, d, e,
          0x34b0bcb5 + (w3 += sigma132(w1) + w12 + sigma032(w4)));
  ROUND32(e, f, g, h, a, b, c, d,
          0x391c0cb3 + (w4 += sigma132(w2) + w13 + sigma032(w5)));
  ROUND32(d, e, f, g, h, a, b, c,
          0x4ed8aa4a + (w5 += sigma132(w3) + w14 + sigma032(w6)));
  ROUND32(c, d, e, f, g, h, a, b,
          0x5b9cca4f + (w6 += sigma132(w4) + w15 + sigma032(w7)));
  ROUND32(b, c, d, e, f, g, h, a,
          0x682e6ff3 + (w7 += sigma132(w5) + w0 + sigma032(w8)));
  ROUND32(a, b, c, d, e, f, g, h,
          0x748f82ee + (w8 += sigma132(w6) + w1 + sigma032(w9)));
  ROUND32(h, a, b, c, d, e, f, g,
          0x78a5636f + (w9 += sigma132(w7) + w2 + sigma032(w10)));
  ROUND32(g, h, a, b, c, d, e, f,
          0x84c87814 + (w10 += sigma132(w8) + w3 + sigma032(w11)));
  ROUND32(f, g, h, a, b, c, d, e,
          0x8cc70208 + (w11 += sigma132(w9) + w4 + sigma032(w12)));
  ROUND32(e, f, g, h, a, b, c, d,
          0x90befffa + (w12 += sigma132(w10) + w5 + sigma032(w13)));
  ROUND32(d, e, f, g, h, a, b, c,
          0xa4506ceb + (w13 += sigma132(w11) + w6 + sigma032(w14)));
  ROUND32(c, d, e, f, g, h, a, b,
          0xbef9a3f7 + (w14 + sigma132(w12) + w7 + sigma032(w15)));
  ROUND32(b, c, d, e, f, g, h, a,
          0xc67178f2 + (w15 + sigma132(w13) + w8 + sigma032(w0)));

  s[0] += a;
  s[1] += b;
  s[2] += c;
  s[3] += d;
  s[4] += e;
  s[5] += f;
  s[6] += g;
  s[7] += h;
}

static void sha512_transform(uint64_t *s, const void *chunk) {
  uint64_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6],
           h = s[7];
  uint64_t w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;

  ROUND64(a, b, c, d, e, f, g, h, 0x428a2f98d728ae22ull, w0 = be64(chunk, 0));
  ROUND64(h, a, b, c, d, e, f, g, 0x7137449123ef65cdull, w1 = be64(chunk, 8));
  ROUND64(g, h, a, b, c, d, e, f, 0xb5c0fbcfec4d3b2full, w2 = be64(chunk, 16));
  ROUND64(f, g, h, a, b, c, d, e, 0xe9b5dba58189dbbcull, w3 = be64(chunk, 24));
  ROUND64(e, f, g, h, a, b, c, d, 0x3956c25bf348b538ull, w4 = be64(chunk, 32));
  ROUND64(d, e, f, g, h, a, b, c, 0x59f111f1b605d019ull, w5 = be64(chunk, 40));
  ROUND64(c, d, e, f, g, h, a, b, 0x923f82a4af194f9bull, w6 = be64(chunk, 48));
  ROUND64(b, c, d, e, f, g, h, a, 0xab1c5ed5da6d8118ull, w7 = be64(chunk, 56));
  ROUND64(a, b, c, d, e, f, g, h, 0xd807aa98a3030242ull, w8 = be64(chunk, 64));
  ROUND64(h, a, b, c, d, e, f, g, 0x12835b0145706fbeull, w9 = be64(chunk, 72));
  ROUND64(g, h, a, b, c, d, e, f, 0x243185be4ee4b28cull, w10 = be64(chunk, 80));
  ROUND64(f, g, h, a, b, c, d, e, 0x550c7dc3d5ffb4e2ull, w11 = be64(chunk, 88));
  ROUND64(e, f, g, h, a, b, c, d, 0x72be5d74f27b896full, w12 = be64(chunk, 96));
  ROUND64(d, e, f, g, h, a, b, c, 0x80deb1fe3b1696b1ull,
          w13 = be64(chunk, 104));
  ROUND64(c, d, e, f, g, h, a, b, 0x9bdc06a725c71235ull,
          w14 = be64(chunk, 112));
  ROUND64(b, c, d, e, f, g, h, a, 0xc19bf174cf692694ull,
          w15 = be64(chunk, 120));
  ROUND64(a, b, c, d, e, f, g, h, 0xe49b69c19ef14ad2ull,
          w0 += sigma164(w14) + w9 + sigma064(w1));
  ROUND64(h, a, b, c, d, e, f, g, 0xefbe4786384f25e3ull,
          w1 += sigma164(w15) + w10 + sigma064(w2));
  ROUND64(g, h, a, b, c, d, e, f, 0x0fc19dc68b8cd5b5ull,
          w2 += sigma164(w0) + w11 + sigma064(w3));
  ROUND64(f, g, h, a, b, c, d, e, 0x240ca1cc77ac9c65ull,
          w3 += sigma164(w1) + w12 + sigma064(w4));
  ROUND64(e, f, g, h, a, b, c, d, 0x2de92c6f592b0275ull,
          w4 += sigma164(w2) + w13 + sigma064(w5));
  ROUND64(d, e, f, g, h, a, b, c, 0x4a7484aa6ea6e483ull,
          w5 += sigma164(w3) + w14 + sigma064(w6));
  ROUND64(c, d, e, f, g, h, a, b, 0x5cb0a9dcbd41fbd4ull,
          w6 += sigma164(w4) + w15 + sigma064(w7));
  ROUND64(b, c, d, e, f, g, h, a, 0x76f988da831153b5ull,
          w7 += sigma164(w5) + w0 + sigma064(w8));
  ROUND64(a, b, c, d, e, f, g, h, 0x983e5152ee66dfabull,
          w8 += sigma164(w6) + w1 + sigma064(w9));
  ROUND64(h, a, b, c, d, e, f, g, 0xa831c66d2db43210ull,
          w9 += sigma164(w7) + w2 + sigma064(w10));
  ROUND64(g, h, a, b, c, d, e, f, 0xb00327c898fb213full,
          w10 += sigma164(w8) + w3 + sigma064(w11));
  ROUND64(f, g, h, a, b, c, d, e, 0xbf597fc7beef0ee4ull,
          w11 += sigma164(w9) + w4 + sigma064(w12));
  ROUND64(e, f, g, h, a, b, c, d, 0xc6e00bf33da88fc2ull,
          w12 += sigma164(w10) + w5 + sigma064(w13));
  ROUND64(d, e, f, g, h, a, b, c, 0xd5a79147930aa725ull,
          w13 += sigma164(w11) + w6 + sigma064(w14));
  ROUND64(c, d, e, f, g, h, a, b, 0x06ca6351e003826full,
          w14 += sigma164(w12) + w7 + sigma064(w15));
  ROUND64(b, c, d, e, f, g, h, a, 0x142929670a0e6e70ull,
          w15 += sigma164(w13) + w8 + sigma064(w0));
  ROUND64(a, b, c, d, e, f, g, h, 0x27b70a8546d22ffcull,
          w0 += sigma164(w14) + w9 + sigma064(w1));
  ROUND64(h, a, b, c, d, e, f, g, 0x2e1b21385c26c926ull,
          w1 += sigma164(w15) + w10 + sigma064(w2));
  ROUND64(g, h, a, b, c, d, e, f, 0x4d2c6dfc5ac42aedull,
          w2 += sigma164(w0) + w11 + sigma064(w3));
  ROUND64(f, g, h, a, b, c, d, e, 0x53380d139d95b3dfull,
          w3 += sigma164(w1) + w12 + sigma064(w4));
  ROUND64(e, f, g, h, a, b, c, d, 0x650a73548baf63deull,
          w4 += sigma164(w2) + w13 + sigma064(w5));
  ROUND64(d, e, f, g, h, a, b, c, 0x766a0abb3c77b2a8ull,
          w5 += sigma164(w3) + w14 + sigma064(w6));
  ROUND64(c, d, e, f, g, h, a, b, 0x81c2c92e47edaee6ull,
          w6 += sigma164(w4) + w15 + sigma064(w7));
  ROUND64(b, c, d, e, f, g, h, a, 0x92722c851482353bull,
          w7 += sigma164(w5) + w0 + sigma064(w8));
  ROUND64(a, b, c, d, e, f, g, h, 0xa2bfe8a14cf10364ull,
          w8 += sigma164(w6) + w1 + sigma064(w9));
  ROUND64(h, a, b, c, d, e, f, g, 0xa81a664bbc423001ull,
          w9 += sigma164(w7) + w2 + sigma064(w10));
  ROUND64(g, h, a, b, c, d, e, f, 0xc24b8b70d0f89791ull,
          w10 += sigma164(w8) + w3 + sigma064(w11));
  ROUND64(f, g, h, a, b, c, d, e, 0xc76c51a30654be30ull,
          w11 += sigma164(w9) + w4 + sigma064(w12));
  ROUND64(e, f, g, h, a, b, c, d, 0xd192e819d6ef5218ull,
          w12 += sigma164(w10) + w5 + sigma064(w13));
  ROUND64(d, e, f, g, h, a, b, c, 0xd69906245565a910ull,
          w13 += sigma164(w11) + w6 + sigma064(w14));
  ROUND64(c, d, e, f, g, h, a, b, 0xf40e35855771202aull,
          w14 += sigma164(w12) + w7 + sigma064(w15));
  ROUND64(b, c, d, e, f, g, h, a, 0x106aa07032bbd1b8ull,
          w15 += sigma164(w13) + w8 + sigma064(w0));
  ROUND64(a, b, c, d, e, f, g, h, 0x19a4c116b8d2d0c8ull,
          w0 += sigma164(w14) + w9 + sigma064(w1));
  ROUND64(h, a, b, c, d, e, f, g, 0x1e376c085141ab53ull,
          w1 += sigma164(w15) + w10 + sigma064(w2));
  ROUND64(g, h, a, b, c, d, e, f, 0x2748774cdf8eeb99ull,
          w2 += sigma164(w0) + w11 + sigma064(w3));
  ROUND64(f, g, h, a, b, c, d, e, 0x34b0bcb5e19b48a8ull,
          w3 += sigma164(w1) + w12 + sigma064(w4));
  ROUND64(e, f, g, h, a, b, c, d, 0x391c0cb3c5c95a63ull,
          w4 += sigma164(w2) + w13 + sigma064(w5));
  ROUND64(d, e, f, g, h, a, b, c, 0x4ed8aa4ae3418acbull,
          w5 += sigma164(w3) + w14 + sigma064(w6));
  ROUND64(c, d, e, f, g, h, a, b, 0x5b9cca4f7763e373ull,
          w6 += sigma164(w4) + w15 + sigma064(w7));
  ROUND64(b, c, d, e, f, g, h, a, 0x682e6ff3d6b2b8a3ull,
          w7 += sigma164(w5) + w0 + sigma064(w8));
  ROUND64(a, b, c, d, e, f, g, h, 0x748f82ee5defb2fcull,
          w8 += sigma164(w6) + w1 + sigma064(w9));
  ROUND64(h, a, b, c, d, e, f, g, 0x78a5636f43172f60ull,
          w9 += sigma164(w7) + w2 + sigma064(w10));
  ROUND64(g, h, a, b, c, d, e, f, 0x84c87814a1f0ab72ull,
          w10 += sigma164(w8) + w3 + sigma064(w11));
  ROUND64(f, g, h, a, b, c, d, e, 0x8cc702081a6439ecull,
          w11 += sigma164(w9) + w4 + sigma064(w12));
  ROUND64(e, f, g, h, a, b, c, d, 0x90befffa23631e28ull,
          w12 += sigma164(w10) + w5 + sigma064(w13));
  ROUND64(d, e, f, g, h, a, b, c, 0xa4506cebde82bde9ull,
          w13 += sigma164(w11) + w6 + sigma064(w14));
  ROUND64(c, d, e, f, g, h, a, b, 0xbef9a3f7b2c67915ull,
          w14 += sigma164(w12) + w7 + sigma064(w15));
  ROUND64(b, c, d, e, f, g, h, a, 0xc67178f2e372532bull,
          w15 += sigma164(w13) + w8 + sigma064(w0));
  ROUND64(a, b, c, d, e, f, g, h, 0xca273eceea26619cull,
          w0 += sigma164(w14) + w9 + sigma064(w1));
  ROUND64(h, a, b, c, d, e, f, g, 0xd186b8c721c0c207ull,
          w1 += sigma164(w15) + w10 + sigma064(w2));
  ROUND64(g, h, a, b, c, d, e, f, 0xeada7dd6cde0eb1eull,
          w2 += sigma164(w0) + w11 + sigma064(w3));
  ROUND64(f, g, h, a, b, c, d, e, 0xf57d4f7fee6ed178ull,
          w3 += sigma164(w1) + w12 + sigma064(w4));
  ROUND64(e, f, g, h, a, b, c, d, 0x06f067aa72176fbaull,
          w4 += sigma164(w2) + w13 + sigma064(w5));
  ROUND64(d, e, f, g, h, a, b, c, 0x0a637dc5a2c898a6ull,
          w5 += sigma164(w3) + w14 + sigma064(w6));
  ROUND64(c, d, e, f, g, h, a, b, 0x113f9804bef90daeull,
          w6 += sigma164(w4) + w15 + sigma064(w7));
  ROUND64(b, c, d, e, f, g, h, a, 0x1b710b35131c471bull,
          w7 += sigma164(w5) + w0 + sigma064(w8));
  ROUND64(a, b, c, d, e, f, g, h, 0x28db77f523047d84ull,
          w8 += sigma164(w6) + w1 + sigma064(w9));
  ROUND64(h, a, b, c, d, e, f, g, 0x32caab7b40c72493ull,
          w9 += sigma164(w7) + w2 + sigma064(w10));
  ROUND64(g, h, a, b, c, d, e, f, 0x3c9ebe0a15c9bebcull,
          w10 += sigma164(w8) + w3 + sigma064(w11));
  ROUND64(f, g, h, a, b, c, d, e, 0x431d67c49c100d4cull,
          w11 += sigma164(w9) + w4 + sigma064(w12));
  ROUND64(e, f, g, h, a, b, c, d, 0x4cc5d4becb3e42b6ull,
          w12 += sigma164(w10) + w5 + sigma064(w13));
  ROUND64(d, e, f, g, h, a, b, c, 0x597f299cfc657e2aull,
          w13 += sigma164(w11) + w6 + sigma064(w14));
  ROUND64(c, d, e, f, g, h, a, b, 0x5fcb6fab3ad6faecull,
          w14 + sigma164(w12) + w7 + sigma064(w15));
  ROUND64(b, c, d, e, f, g, h, a, 0x6c44198c4a475817ull,
          w15 + sigma164(w13) + w8 + sigma064(w0));

  s[0] += a;
  s[1] += b;
  s[2] += c;
  s[3] += d;
  s[4] += e;
  s[5] += f;
  s[6] += g;
  s[7] += h;
}

static void sha256_final(uint32_t *digest, const void *msg, size_t msg_len,
                         size_t append_size) {
  uint8_t last_chunk[64];
  const uint8_t *msg_buf = (const uint8_t *)msg;
  uint64_t chunk_end = htobe64((uint64_t)(msg_len + append_size) << 3);
  while (msg_len >= 64) {
    sha256_transform(digest, msg_buf);
    msg_len -= 64;
    msg_buf += 64;
  }
  memset(last_chunk, 0, sizeof(last_chunk));
  memcpy(last_chunk, msg_buf, msg_len);
  last_chunk[msg_len] = 0x80;

  if (msg_len > 55) {
    sha256_transform(digest, last_chunk);
    memset(last_chunk, 0, 64);
  }

  *(uint64_t *)&last_chunk[56] = chunk_end;
  sha256_transform(digest, last_chunk);
}

void fingera_sha2_256(const void *msg, size_t msg_len, void *hash) {
  uint32_t *out = (uint32_t *)hash;
  uint32_t digest[8] = {0x6a09e667ul, 0xbb67ae85ul, 0x3c6ef372ul, 0xa54ff53aul,
                        0x510e527ful, 0x9b05688cul, 0x1f83d9abul, 0x5be0cd19ul};

  sha256_final(digest, msg, msg_len, 0);

  out[0] = htobe32(digest[0]);
  out[1] = htobe32(digest[1]);
  out[2] = htobe32(digest[2]);
  out[3] = htobe32(digest[3]);
  out[4] = htobe32(digest[4]);
  out[5] = htobe32(digest[5]);
  out[6] = htobe32(digest[6]);
  out[7] = htobe32(digest[7]);
}

static void sha512_final(uint64_t *digest, const void *msg, size_t msg_len,
                         size_t append_size) {
  uint8_t last_chunk[128];
  const uint8_t *msg_buf = (const uint8_t *)msg;
  uint64_t chunk_end = htobe64((uint64_t)(msg_len + append_size) << 3);
  while (msg_len >= 128) {
    sha512_transform(digest, msg_buf);
    msg_len -= 128;
    msg_buf += 128;
  }
  memset(last_chunk, 0, sizeof(last_chunk));
  memcpy(last_chunk, msg_buf, msg_len);
  last_chunk[msg_len] = 0x80;

  if (msg_len > 111) {
    sha512_transform(digest, last_chunk);
    memset(last_chunk, 0, sizeof(last_chunk));
  }

  *(uint64_t *)&last_chunk[120] = chunk_end;
  sha512_transform(digest, last_chunk);
}

void fingera_sha2_512(const void *msg, size_t msg_len, void *hash) {
  uint64_t digest[8] = {0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull,
                        0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
                        0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
                        0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull};
  uint64_t *out = (uint64_t *)hash;
  sha512_final(digest, msg, msg_len, 0);

  out[1] = htobe64(digest[1]);
  out[0] = htobe64(digest[0]);
  out[2] = htobe64(digest[2]);
  out[3] = htobe64(digest[3]);
  out[4] = htobe64(digest[4]);
  out[5] = htobe64(digest[5]);
  out[6] = htobe64(digest[6]);
  out[7] = htobe64(digest[7]);
}

void fingera_hmac_sha256(const void *key, size_t key_len, const void *msg,
                         size_t msg_len, void *hmac) {
  const static uint64_t _36 = 0x3636363636363636ull;
  const static uint64_t _5C = 0x5C5C5C5C5C5C5C5Cull;
  uint32_t digest_inner[8] = {0x6a09e667ul, 0xbb67ae85ul, 0x3c6ef372ul,
                              0xa54ff53aul, 0x510e527ful, 0x9b05688cul,
                              0x1f83d9abul, 0x5be0cd19ul};
  uint32_t digest_outter[8] = {0x6a09e667ul, 0xbb67ae85ul, 0x3c6ef372ul,
                               0xa54ff53aul, 0x510e527ful, 0x9b05688cul,
                               0x1f83d9abul, 0x5be0cd19ul};
  uint64_t buffer[8];
  uint64_t key_inner[8];
  uint64_t key_outter[8];
  uint32_t *out = (uint32_t *)hmac;
  size_t i;
  if (key_len <= 64) {
    memcpy(buffer, key, key_len);
    memset((char *)buffer + key_len, 0, 64 - key_len);
  } else {
    fingera_sha2_256(key, key_len, buffer);
    memset((char *)buffer + 32, 0, 32);
  }
  for (i = 0; i < 8; i++) {
    key_inner[i] = buffer[i] ^ _36;
    key_outter[i] = buffer[i] ^ _5C;
  }

  sha256_transform(digest_inner, key_inner);
  sha256_final(digest_inner, msg, msg_len, 64);

  for (i = 0; i < 8; i++) {
    digest_inner[i] = htobe32(digest_inner[i]);
  }

  sha256_transform(digest_outter, key_outter);
  sha256_final(digest_outter, digest_inner, 32, 64);

  for (i = 0; i < 8; i++) {
    out[i] = htobe32(digest_outter[i]);
  }
}

void fingera_hmac_sha512(const void *key, size_t key_len, const void *msg,
                         size_t msg_len, void *hmac) {
  const static uint64_t _36 = 0x3636363636363636ull;
  const static uint64_t _5C = 0x5C5C5C5C5C5C5C5Cull;
  uint64_t digest_inner[8] = {0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull,
                              0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
                              0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
                              0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull};
  uint64_t digest_outter[8] = {0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull,
                               0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
                               0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
                               0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull};
  uint64_t buffer[16];
  uint64_t key_inner[16];
  uint64_t key_outter[16];
  uint64_t *out = (uint64_t *)hmac;
  size_t i;
  if (key_len <= 128) {
    memcpy(buffer, key, key_len);
    memset((char *)buffer + key_len, 0, 128 - key_len);
  } else {
    fingera_sha2_512(key, key_len, buffer);
    memset((char *)buffer + 64, 0, 64);
  }
  for (i = 0; i < 16; i++) {
    key_inner[i] = buffer[i] ^ _36;
    key_outter[i] = buffer[i] ^ _5C;
  }

  sha512_transform(digest_inner, key_inner);
  sha512_final(digest_inner, msg, msg_len, 128);

  for (i = 0; i < 8; i++) {
    digest_inner[i] = htobe64(digest_inner[i]);
  }

  sha512_transform(digest_outter, key_outter);
  sha512_final(digest_outter, digest_inner, 64, 128);

  for (i = 0; i < 8; i++) {
    out[i] = htobe64(digest_outter[i]);
  }
}
