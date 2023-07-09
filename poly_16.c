#include <stdint.h>
#include <immintrin.h>
#include <string.h>
#include "align.h"
#include "params.h"
#include "poly_16.h"
#include "ntt_16.h"
#include "consts_16.h"
#include "reduce.h"
#include "cbd.h"
#include "symmetric.h"
#include "clocks.h"

#if (KYBER_POLYCOMPRESSEDBYTES == 96)
void poly_compress(uint8_t r[96], const poly *restrict a)
{
  unsigned int i;
  __m256i f0, f1, f2, f3;
  __m128i t0, t1;
  const __m256i v = _mm256_load_si256(&qdata.vec[_16XV / 16]);
  const __m256i shift1 = _mm256_set1_epi16(1 << 8);
  const __m256i mask = _mm256_set1_epi16(7);
  const __m256i shift2 = _mm256_set1_epi16((8 << 8) + 1);
  const __m256i shift3 = _mm256_set1_epi32((64 << 16) + 1);
  const __m256i sllvdidx = _mm256_set1_epi64x(12LL << 32);
  const __m256i shufbidx = _mm256_set_epi8(8, 2, 1, 0, -1, -1, -1, -1, 14, 13, 12, 6, 5, 4, 10, 9,
                                           -1, -1, -1, -1, 14, 13, 12, 6, 5, 4, 10, 9, 8, 2, 1, 0);

  for (i = 0; i < KYBER_N / 64; i++)
  {
    f0 = _mm256_load_si256(&a->vec[4 * i + 0]);
    f1 = _mm256_load_si256(&a->vec[4 * i + 1]);
    f2 = _mm256_load_si256(&a->vec[4 * i + 2]);
    f3 = _mm256_load_si256(&a->vec[4 * i + 3]);
    f0 = _mm256_mulhi_epi16(f0, v);
    f1 = _mm256_mulhi_epi16(f1, v);
    f2 = _mm256_mulhi_epi16(f2, v);
    f3 = _mm256_mulhi_epi16(f3, v);
    f0 = _mm256_mulhrs_epi16(f0, shift1);
    f1 = _mm256_mulhrs_epi16(f1, shift1);
    f2 = _mm256_mulhrs_epi16(f2, shift1);
    f3 = _mm256_mulhrs_epi16(f3, shift1);
    f0 = _mm256_and_si256(f0, mask);
    f1 = _mm256_and_si256(f1, mask);
    f2 = _mm256_and_si256(f2, mask);
    f3 = _mm256_and_si256(f3, mask);
    f0 = _mm256_packus_epi16(f0, f1);
    f2 = _mm256_packus_epi16(f2, f3);
    f0 = _mm256_maddubs_epi16(f0, shift2); // a0 a1 a2 a3 b0 b1 b2 b3 a4 a5 a6 a7 b4 b5 b6 b7
    f2 = _mm256_maddubs_epi16(f2, shift2); // c0 c1 c2 c3 d0 d1 d2 d3 c4 c5 c6 c7 d4 d5 d6 d7
    f0 = _mm256_madd_epi16(f0, shift3);    // a0 a1 b0 b1 a2 a3 b2 b3
    f2 = _mm256_madd_epi16(f2, shift3);    // c0 c1 d0 d1 c2 c3 d2 d3
    f0 = _mm256_sllv_epi32(f0, sllvdidx);
    f2 = _mm256_sllv_epi32(f2, sllvdidx);
    f0 = _mm256_hadd_epi32(f0, f2);          // a0 c0 c0 d0 a1 b1 c1 d1
    f0 = _mm256_permute4x64_epi64(f0, 0xD8); // a0 b0 a1 b1 c0 d0 c1 d1
    f0 = _mm256_shuffle_epi8(f0, shufbidx);
    t0 = _mm256_castsi256_si128(f0);
    t1 = _mm256_extracti128_si256(f0, 1);
    t0 = _mm_blend_epi32(t0, t1, 0x08);
    _mm_storeu_si128((__m128i *)&r[24 * i + 0], t0);
    _mm_storel_epi64((__m128i *)&r[24 * i + 16], t1);
  }
}

void poly_decompress(poly *restrict r, const uint8_t a[96])
{
  unsigned int i;
  __m128i t;
  __m256i f;
  const __m256i q = _mm256_load_si256(&qdata.vec[_16XQ / 16]);
  const __m256i shufbidx = _mm256_set_epi8(5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3,
                                           2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0);
  const __m256i mask = _mm256_set_epi16(224, 28, 896, 112, 14, 448, 56, 7,
                                        224, 28, 896, 112, 14, 448, 56, 7);
  const __m256i shift = _mm256_set_epi16(128, 1024, 32, 256, 2048, 64, 512, 4096,
                                         128, 1024, 32, 256, 2048, 64, 512, 4096);

  for (i = 0; i < KYBER_N / 16; i++)
  {
    t = _mm_castps_si128(_mm_load_ss((float *)&a[6*i+0])));
    t = _mm_insert_epi16(t, *(int16_t *)&a[6 * i + 4], 2);
    f = _mm256_broadcastsi128_si256(t);
    f = _mm256_blend_epi16(f, g, 0x);
    f = _mm256_shuffle_epi8(f, shufbidx);
    f = _mm256_and_si256(f, mask);
    f = _mm256_mullo_epi16(f, shift);
    f = _mm256_mulhrs_epi16(f, q);
    _mm256_store_si256(&r->vec[i], f);
  }
}

#elif (KYBER_POLYCOMPRESSEDBYTES == 128 * 16)
void poly_compress(uint8_t r[128 * 16], const poly_16 *restrict a)
{
  unsigned int i;
  __m256i f0, f1, f2, f3;
  const __m256i v = _mm256_load_si256(&qdata_16.vec[_16XV_16 / 16]);
  const __m256i shift1 = _mm256_set1_epi16(1 << 9);
  const __m256i mask = _mm256_set1_epi16(15);

  for (i = 0; i < KYBER_N / 4; i++)
  {
    f0 = _mm256_load_si256(&a->vec[4 * i + 0]);
    f1 = _mm256_load_si256(&a->vec[4 * i + 1]);
    f2 = _mm256_load_si256(&a->vec[4 * i + 2]);
    f3 = _mm256_load_si256(&a->vec[4 * i + 3]);
    f0 = _mm256_mulhi_epi16(f0, v);
    f1 = _mm256_mulhi_epi16(f1, v);
    f2 = _mm256_mulhi_epi16(f2, v);
    f3 = _mm256_mulhi_epi16(f3, v);
    f0 = _mm256_mulhrs_epi16(f0, shift1);
    f1 = _mm256_mulhrs_epi16(f1, shift1);
    f2 = _mm256_mulhrs_epi16(f2, shift1);
    f3 = _mm256_mulhrs_epi16(f3, shift1);
    f0 = _mm256_and_si256(f0, mask);
    f1 = _mm256_and_si256(f1, mask);
    f2 = _mm256_and_si256(f2, mask);
    f3 = _mm256_and_si256(f3, mask);

    f1 = _mm256_slli_epi16(f1, 4);
    f0 = _mm256_add_epi16(f0, f1);
    f2 = _mm256_slli_epi16(f2, 8);
    f0 = _mm256_add_epi16(f0, f2);
    f3 = _mm256_slli_epi16(f3, 12);
    f0 = _mm256_add_epi16(f0, f3);
    _mm256_storeu_si256((__m256i *)&r[32 * i], f0);
  }
}

void poly_decompress(poly_16 *restrict r, const uint8_t a[128 * 16])
{
  unsigned int i;
  __m256i f, g;
  const __m256i q = _mm256_load_si256(&qdata_16.vec[_16XQ_16 / 16]);
  const __m256i mask = _mm256_set1_epi16(30720); //0b0111 1000 0000 0000

  for (i = 0; i < KYBER_N / 4; i++)
  {
    f = _mm256_loadu_si256((__m256i *)&a[32 * i]);
    g = _mm256_slli_epi16(f, 11);
    g = _mm256_and_si256(g, mask);
    g = _mm256_mulhrs_epi16(g, q);
    _mm256_storeu_si256((__m256i *)&r->vec[4 * i], g);
    g = _mm256_slli_epi16(f, 7);
    g = _mm256_and_si256(g, mask);
    g = _mm256_mulhrs_epi16(g, q);
    _mm256_storeu_si256((__m256i *)&r->vec[4 * i + 1], g);
    g = _mm256_slli_epi16(f, 3);
    g = _mm256_and_si256(g, mask);
    g = _mm256_mulhrs_epi16(g, q);
    _mm256_storeu_si256((__m256i *)&r->vec[4 * i + 2], g);
    g = _mm256_srli_epi16(f, 1);
    g = _mm256_and_si256(g, mask);
    g = _mm256_mulhrs_epi16(g, q);
    _mm256_storeu_si256((__m256i *)&r->vec[4 * i + 3], g);
  }
}

#elif (KYBER_POLYCOMPRESSEDBYTES == 160)
void poly_compress(uint8_t r[160], const poly *restrict a)
{
  unsigned int i;
  __m256i f0, f1;
  __m128i t0, t1;
  const __m256i v = _mm256_load_si256(&qdata.vec[_16XV / 16]);
  const __m256i shift1 = _mm256_set1_epi16(1 << 10);
  const __m256i mask = _mm256_set1_epi16(31);
  const __m256i shift2 = _mm256_set1_epi16((32 << 8) + 1);
  const __m256i shift3 = _mm256_set1_epi32((1024 << 16) + 1);
  const __m256i sllvdidx = _mm256_set1_epi64x(12);
  const __m256i shufbidx = _mm256_set_epi8(8, -1, -1, -1, -1, -1, 4, 3, 2, 1, 0, -1, 12, 11, 10, 9,
                                           -1, 12, 11, 10, 9, 8, -1, -1, -1, -1, -1, 4, 3, 2, 1, 0);

  for (i = 0; i < KYBER_N / 32; i++)
  {
    f0 = _mm256_load_si256(&a->vec[2 * i + 0]);
    f1 = _mm256_load_si256(&a->vec[2 * i + 1]);
    f0 = _mm256_mulhi_epi16(f0, v);
    f1 = _mm256_mulhi_epi16(f1, v);
    f0 = _mm256_mulhrs_epi16(f0, shift1);
    f1 = _mm256_mulhrs_epi16(f1, shift1);
    f0 = _mm256_and_si256(f0, mask);
    f1 = _mm256_and_si256(f1, mask);
    f0 = _mm256_packus_epi16(f0, f1);
    f0 = _mm256_maddubs_epi16(f0, shift2); // a0 a1 a2 a3 b0 b1 b2 b3 a4 a5 a6 a7 b4 b5 b6 b7
    f0 = _mm256_madd_epi16(f0, shift3);    // a0 a1 b0 b1 a2 a3 b2 b3
    f0 = _mm256_sllv_epi32(f0, sllvdidx);
    f0 = _mm256_srlv_epi64(f0, sllvdidx);
    f0 = _mm256_shuffle_epi8(f0, shufbidx);
    t0 = _mm256_castsi256_si128(f0);
    t1 = _mm256_extracti128_si256(f0, 1);
    t0 = _mm_blendv_epi8(t0, t1, _mm256_castsi256_si128(shufbidx));
    _mm_storeu_si128((__m128i *)&r[20 * i + 0], t0);
    memcpy(&r[20 * i + 16], &t1, 4);
  }
}

void poly_decompress(poly *restrict r, const uint8_t a[160])
{
  unsigned int i;
  __m128i t;
  __m256i f;
  int16_t ti;
  const __m256i q = _mm256_load_si256(&qdata.vec[_16XQ / 16]);
  const __m256i shufbidx = _mm256_set_epi8(9, 9, 9, 8, 8, 8, 8, 7, 7, 6, 6, 6, 6, 5, 5, 5,
                                           4, 4, 4, 3, 3, 3, 3, 2, 2, 1, 1, 1, 1, 0, 0, 0);
  const __m256i mask = _mm256_set_epi16(248, 1984, 62, 496, 3968, 124, 992, 31,
                                        248, 1984, 62, 496, 3968, 124, 992, 31);
  const __m256i shift = _mm256_set_epi16(128, 16, 512, 64, 8, 256, 32, 1024,
                                         128, 16, 512, 64, 8, 256, 32, 1024);

  for (i = 0; i < KYBER_N / 16; i++)
  {
    t = _mm_loadl_epi64((__m128i *)&a[10 * i + 0]);
    memcpy(&ti, &a[10 * i + 8], 2);
    t = _mm_insert_epi16(t, ti, 4);
    f = _mm256_broadcastsi128_si256(t);
    f = _mm256_shuffle_epi8(f, shufbidx);
    f = _mm256_and_si256(f, mask);
    f = _mm256_mullo_epi16(f, shift);
    f = _mm256_mulhrs_epi16(f, q);
    _mm256_store_si256(&r->vec[i], f);
  }
}

#endif

void poly_tobytes(uint8_t r[KYBER_POLYBYTES * 16], const poly_16 *a)
{
  ntttobytes_avx_16(r, a->vec, qdata_16.vec);
}

void poly_frombytes(poly_16 *r, const uint8_t a[KYBER_POLYBYTES * 16])
{
  nttfrombytes_avx_16(r->vec, a, qdata_16.vec);
}

void poly_frommsg_16(poly_16 *restrict r, const uint8_t msg[KYBER_INDCPA_MSGBYTES * 16])
{
#if (KYBER_INDCPA_MSGBYTES != 32)
#error "KYBER_INDCPA_MSGBYTES must be equal to 32!"
#endif
  __m256i f, g0, g1, g2, g3, h0, h1, h2, h3;
  // const __m256i shift = _mm256_broadcastsi128_si256(_mm_set_epi32(0,1,2,3));
  // const __m256i idx1 = _mm256_set_epi8(15,15,13,13,11,11,9,9,7,7,5,5,3,3,1,1,14,14,12,12,10,10,8,8,6,6,4,4,2,2,0,0);
  // const __m256i idx2 = _mm256_set_epi8(31,31,29,29,27,27,25,25,23,23,21,21,19,19,17,17,30,30,28,28,26,26,24,24,22,22,20,20,18,18,16,16);
  const __m256i idx1 = _mm256_set_epi8(15, 15, 14, 14, 13, 13, 12, 12, 11, 11, 10, 10, 9, 9, 8, 8, 7, 7, 6, 6, 5, 5, 4, 4, 3, 3, 2, 2, 1, 1, 0, 0);
  const __m256i idx2 = _mm256_set_epi8(31, 31, 30, 30, 29, 29, 28, 28, 27, 27, 26, 26, 25, 25, 24, 24, 23, 23, 22, 22, 21, 21, 20, 20, 19, 19, 18, 18, 17, 17, 16, 16);

  const __m256i hqs = _mm256_set1_epi16((KYBER_Q + 1) / 2);

#define FROMMSG64(i)                       \
  g0 = _mm256_permute4x64_epi64(f, 0x44);  \
  g1 = _mm256_permute4x64_epi64(f, 0xEE);  \
  g2 = _mm256_shuffle_epi8(g0, idx1);      \
  g3 = _mm256_shuffle_epi8(g1, idx2);      \
  g0 = _mm256_slli_epi16(g2, 15);          \
  g1 = _mm256_slli_epi16(g3, 15);          \
  g0 = _mm256_srai_epi16(g0, 15);          \
  g1 = _mm256_srai_epi16(g1, 15);          \
  g0 = _mm256_and_si256(g0, hqs);          \
  g1 = _mm256_and_si256(g1, hqs);          \
  _mm256_store_si256(&r->vec[i], g0);      \
  _mm256_store_si256(&r->vec[i + 8], g1);  \
  g0 = _mm256_slli_epi16(g2, 14);          \
  g1 = _mm256_slli_epi16(g3, 14);          \
  g0 = _mm256_srai_epi16(g0, 15);          \
  g1 = _mm256_srai_epi16(g1, 15);          \
  g0 = _mm256_and_si256(g0, hqs);          \
  g1 = _mm256_and_si256(g1, hqs);          \
  _mm256_store_si256(&r->vec[i + 1], g0);  \
  _mm256_store_si256(&r->vec[i + 9], g1);  \
  g0 = _mm256_slli_epi16(g2, 13);          \
  g1 = _mm256_slli_epi16(g3, 13);          \
  g0 = _mm256_srai_epi16(g0, 15);          \
  g1 = _mm256_srai_epi16(g1, 15);          \
  g0 = _mm256_and_si256(g0, hqs);          \
  g1 = _mm256_and_si256(g1, hqs);          \
  _mm256_store_si256(&r->vec[i + 2], g0);  \
  _mm256_store_si256(&r->vec[i + 10], g1); \
  g0 = _mm256_slli_epi16(g2, 12);          \
  g1 = _mm256_slli_epi16(g3, 12);          \
  g0 = _mm256_srai_epi16(g0, 15);          \
  g1 = _mm256_srai_epi16(g1, 15);          \
  g0 = _mm256_and_si256(g0, hqs);          \
  g1 = _mm256_and_si256(g1, hqs);          \
  _mm256_store_si256(&r->vec[i + 3], g0);  \
  _mm256_store_si256(&r->vec[i + 11], g1); \
  g0 = _mm256_slli_epi16(g2, 11);          \
  g1 = _mm256_slli_epi16(g3, 11);          \
  g0 = _mm256_srai_epi16(g0, 15);          \
  g1 = _mm256_srai_epi16(g1, 15);          \
  g0 = _mm256_and_si256(g0, hqs);          \
  g1 = _mm256_and_si256(g1, hqs);          \
  _mm256_store_si256(&r->vec[i + 4], g0);  \
  _mm256_store_si256(&r->vec[i + 12], g1); \
  g0 = _mm256_slli_epi16(g2, 10);          \
  g1 = _mm256_slli_epi16(g3, 10);          \
  g0 = _mm256_srai_epi16(g0, 15);          \
  g1 = _mm256_srai_epi16(g1, 15);          \
  g0 = _mm256_and_si256(g0, hqs);          \
  g1 = _mm256_and_si256(g1, hqs);          \
  _mm256_store_si256(&r->vec[i + 5], g0);  \
  _mm256_store_si256(&r->vec[i + 13], g1); \
  g0 = _mm256_slli_epi16(g2, 9);           \
  g1 = _mm256_slli_epi16(g3, 9);           \
  g0 = _mm256_srai_epi16(g0, 15);          \
  g1 = _mm256_srai_epi16(g1, 15);          \
  g0 = _mm256_and_si256(g0, hqs);          \
  g1 = _mm256_and_si256(g1, hqs);          \
  _mm256_store_si256(&r->vec[i + 6], g0);  \
  _mm256_store_si256(&r->vec[i + 14], g1); \
  g0 = _mm256_slli_epi16(g2, 8);           \
  g1 = _mm256_slli_epi16(g3, 8);           \
  g0 = _mm256_srai_epi16(g0, 15);          \
  g1 = _mm256_srai_epi16(g1, 15);          \
  g0 = _mm256_and_si256(g0, hqs);          \
  g1 = _mm256_and_si256(g1, hqs);          \
  _mm256_store_si256(&r->vec[i + 7], g0);  \
  _mm256_store_si256(&r->vec[i + 15], g1);

  f = _mm256_loadu_si256((__m256i *)msg); // 认为msg内部结构为a0-p0, a1-p1,...., a31-p31
// g2 = _mm256_shuffle_epi8(f, idx1);
// g0 = _mm256_slli_epi16(g2, 15);
// g0 = _mm256_srai_epi16(g0, 15);
// g0 = _mm256_and_si256(g0, hqs);
// _mm256_store_si256(&r->vec[0], g0);
  FROMMSG64(0);
  f = _mm256_loadu_si256((__m256i *)(msg + 32));
  FROMMSG64(16);
  f = _mm256_loadu_si256((__m256i *)(msg + 64));
  FROMMSG64(32);
  f = _mm256_loadu_si256((__m256i *)(msg + 96));
  FROMMSG64(48);
  f = _mm256_loadu_si256((__m256i *)(msg + 128));
  FROMMSG64(64);
  f = _mm256_loadu_si256((__m256i *)(msg + 160));
  FROMMSG64(80);
  f = _mm256_loadu_si256((__m256i *)(msg + 192));
  FROMMSG64(96);
  f = _mm256_loadu_si256((__m256i *)(msg + 224));
  FROMMSG64(112);
  f = _mm256_loadu_si256((__m256i *)(msg + 256));
  FROMMSG64(128);
  f = _mm256_loadu_si256((__m256i *)(msg + 288));
  FROMMSG64(144);
  f = _mm256_loadu_si256((__m256i *)(msg + 320));
  FROMMSG64(160);
  f = _mm256_loadu_si256((__m256i *)(msg + 352));
  FROMMSG64(176);
  f = _mm256_loadu_si256((__m256i *)(msg + 384));
  FROMMSG64(192);
  f = _mm256_loadu_si256((__m256i *)(msg + 416));
  FROMMSG64(208);
  f = _mm256_loadu_si256((__m256i *)(msg + 448));
  FROMMSG64(224);
  f = _mm256_loadu_si256((__m256i *)(msg + 480));
  FROMMSG64(240);
}

void poly_tomsg_16(uint8_t msg[KYBER_INDCPA_MSGBYTES * 16], const poly_16 *restrict a)
{
  unsigned int i;
  __m256i f0, f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, f15,
      g0, g1, g2, g3, g4, g5, g6, g7, g8, g9, g10, g11, g12, g13, g14, g15;
  const __m256i hq = _mm256_set1_epi16((KYBER_Q - 1) / 2);
  const __m256i hhq = _mm256_set1_epi16((KYBER_Q - 1) / 4);
  const __m256i mask = _mm256_set1_epi16(32896); // 0b1000 0000 1000 0000

  for (i = 0; i < KYBER_N/16; i++)
  {
    f0 = _mm256_load_si256(&a->vec[16 * i + 0]);
    f1 = _mm256_load_si256(&a->vec[16 * i + 1]);
    f2 = _mm256_load_si256(&a->vec[16 * i + 2]);
    f3 = _mm256_load_si256(&a->vec[16 * i + 3]);
    f4 = _mm256_load_si256(&a->vec[16 * i + 4]);
    f5 = _mm256_load_si256(&a->vec[16 * i + 5]);
    f6 = _mm256_load_si256(&a->vec[16 * i + 6]);
    f7 = _mm256_load_si256(&a->vec[16 * i + 7]);
    f8 = _mm256_load_si256(&a->vec[16 * i + 8]);
    f9 = _mm256_load_si256(&a->vec[16 * i + 9]);
    f10 = _mm256_load_si256(&a->vec[16 * i + 10]);
    f11 = _mm256_load_si256(&a->vec[16 * i + 11]);
    f12 = _mm256_load_si256(&a->vec[16 * i + 12]);
    f13 = _mm256_load_si256(&a->vec[16 * i + 13]);
    f14 = _mm256_load_si256(&a->vec[16 * i + 14]);
    f15 = _mm256_load_si256(&a->vec[16 * i + 15]);

    f0 = _mm256_sub_epi16(hq, f0);
    f1 = _mm256_sub_epi16(hq, f1);
    f2 = _mm256_sub_epi16(hq, f2);
    f3 = _mm256_sub_epi16(hq, f3);
    f4 = _mm256_sub_epi16(hq, f4);
    f5 = _mm256_sub_epi16(hq, f5);
    f6 = _mm256_sub_epi16(hq, f6);
    f7 = _mm256_sub_epi16(hq, f7);
    f8 = _mm256_sub_epi16(hq, f8);
    f9 = _mm256_sub_epi16(hq, f9);
    f10 = _mm256_sub_epi16(hq, f10);
    f11 = _mm256_sub_epi16(hq, f11);
    f12 = _mm256_sub_epi16(hq, f12);
    f13 = _mm256_sub_epi16(hq, f13);
    f14 = _mm256_sub_epi16(hq, f14);
    f15 = _mm256_sub_epi16(hq, f15);

    g0 = _mm256_srai_epi16(f0, 15);
    g1 = _mm256_srai_epi16(f1, 15);
    g2 = _mm256_srai_epi16(f2, 15);
    g3 = _mm256_srai_epi16(f3, 15);
    g4 = _mm256_srai_epi16(f4, 15);
    g5 = _mm256_srai_epi16(f5, 15);
    g6 = _mm256_srai_epi16(f6, 15);
    g7 = _mm256_srai_epi16(f7, 15);
    g8 = _mm256_srai_epi16(f8, 15);
    g9 = _mm256_srai_epi16(f9, 15);
    g10 = _mm256_srai_epi16(f10, 15);
    g11 = _mm256_srai_epi16(f11, 15);
    g12 = _mm256_srai_epi16(f12, 15);
    g13 = _mm256_srai_epi16(f13, 15);
    g14 = _mm256_srai_epi16(f14, 15);
    g15 = _mm256_srai_epi16(f15, 15);

    f0 = _mm256_xor_si256(f0, g0);
    f1 = _mm256_xor_si256(f1, g1);
    f2 = _mm256_xor_si256(f2, g2);
    f3 = _mm256_xor_si256(f3, g3);
    f4 = _mm256_xor_si256(f4, g4);
    f5 = _mm256_xor_si256(f5, g5);
    f6 = _mm256_xor_si256(f6, g6);
    f7 = _mm256_xor_si256(f7, g7);
    f8 = _mm256_xor_si256(f8, g8);
    f9 = _mm256_xor_si256(f9, g9);
    f10 = _mm256_xor_si256(f10, g10);
    f11 = _mm256_xor_si256(f11, g11);
    f12 = _mm256_xor_si256(f12, g12);
    f13 = _mm256_xor_si256(f13, g13);
    f14 = _mm256_xor_si256(f14, g14);
    f15 = _mm256_xor_si256(f15, g15);

    f0 = _mm256_sub_epi16(f0, hhq);
    f1 = _mm256_sub_epi16(f1, hhq);
    f2 = _mm256_sub_epi16(f2, hhq);
    f3 = _mm256_sub_epi16(f3, hhq);
    f4 = _mm256_sub_epi16(f4, hhq);
    f5 = _mm256_sub_epi16(f5, hhq);
    f6 = _mm256_sub_epi16(f6, hhq);
    f7 = _mm256_sub_epi16(f7, hhq);
    f8 = _mm256_sub_epi16(f8, hhq);
    f9 = _mm256_sub_epi16(f9, hhq);
    f10 = _mm256_sub_epi16(f10, hhq);
    f11 = _mm256_sub_epi16(f11, hhq);
    f12 = _mm256_sub_epi16(f12, hhq);
    f13 = _mm256_sub_epi16(f13, hhq);
    f14 = _mm256_sub_epi16(f14, hhq);
    f15 = _mm256_sub_epi16(f15, hhq);

    g0 = _mm256_packs_epi16(f0, f8);
    g1 = _mm256_packs_epi16(f1, f9);
    g2 = _mm256_packs_epi16(f2, f10);
    g3 = _mm256_packs_epi16(f3, f11);
    g4 = _mm256_packs_epi16(f4, f12);
    g5 = _mm256_packs_epi16(f5, f13);
    g6 = _mm256_packs_epi16(f6, f14);
    g7 = _mm256_packs_epi16(f7, f15);

    g0 = _mm256_permute4x64_epi64(g0, 0xD8);
    g1 = _mm256_permute4x64_epi64(g1, 0xD8);
    g2 = _mm256_permute4x64_epi64(g2, 0xD8);
    g3 = _mm256_permute4x64_epi64(g3, 0xD8);
    g4 = _mm256_permute4x64_epi64(g4, 0xD8);
    g5 = _mm256_permute4x64_epi64(g5, 0xD8);
    g6 = _mm256_permute4x64_epi64(g6, 0xD8);
    g7 = _mm256_permute4x64_epi64(g7, 0xD8);

    g0 = _mm256_and_si256(g0, mask);
    g1 = _mm256_and_si256(g1, mask);
    g2 = _mm256_and_si256(g2, mask);
    g3 = _mm256_and_si256(g3, mask);
    g4 = _mm256_and_si256(g4, mask);
    g5 = _mm256_and_si256(g5, mask);
    g6 = _mm256_and_si256(g6, mask);
    g7 = _mm256_and_si256(g7, mask);

    g0 = _mm256_srli_epi16(g0, 7);
    g1 = _mm256_srli_epi16(g1, 6);
    g2 = _mm256_srli_epi16(g2, 5);
    g3 = _mm256_srli_epi16(g3, 4);
    g4 = _mm256_srli_epi16(g4, 3);
    g5 = _mm256_srli_epi16(g5, 2);
    g6 = _mm256_srli_epi16(g6, 1);

    g0 = _mm256_add_epi16(g0, g1);
    g0 = _mm256_add_epi16(g0, g2);
    g0 = _mm256_add_epi16(g0, g3);
    g0 = _mm256_add_epi16(g0, g4);
    g0 = _mm256_add_epi16(g0, g5);
    g0 = _mm256_add_epi16(g0, g6);
    g0 = _mm256_add_epi16(g0, g7);

    memcpy(&msg[32 * i], &g0, 32);
  }
}

void poly_getnoise_eta1(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce)
{
  ALIGNED_UINT8(KYBER_ETA1 * KYBER_N / 4 + 32)
  buf; // +32 bytes as required by poly_cbd_eta1
  prf(buf.coeffs, KYBER_ETA1 * KYBER_N / 4, seed, nonce);
  poly_cbd_eta1(r, buf.vec);
}

void poly_getnoise_eta2(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce)
{
  ALIGNED_UINT8(KYBER_ETA2 * KYBER_N / 4)
  buf;
  prf(buf.coeffs, KYBER_ETA2 * KYBER_N / 4, seed, nonce);
  poly_cbd_eta2(r, buf.vec);
}

#ifndef KYBER_90S
#define NOISE_NBLOCKS ((KYBER_ETA1 * KYBER_N / 4 + SHAKE256_RATE - 1) / SHAKE256_RATE)
void poly_getnoise_eta1_4x(poly_16 *r0,
                           poly_16 *r1,
                           poly_16 *r2,
                           poly_16 *r3,
                           const uint8_t seed[32],
                           uint8_t nonce0,
                           uint8_t nonce1,
                           uint8_t nonce2,
                           uint8_t nonce3)
{
  ALIGNED_UINT8(NOISE_NBLOCKS * 16 * SHAKE256_RATE)
  buf[4]; // NOISE_NBLOCKS = 1
  __m256i f;
  keccakx4_state state;

  f = _mm256_loadu_si256((__m256i *)seed);
  _mm256_store_si256(buf[0].vec, f);
  _mm256_store_si256(buf[1].vec, f);
  _mm256_store_si256(buf[2].vec, f);
  _mm256_store_si256(buf[3].vec, f);

  buf[0].coeffs[32] = nonce0;
  buf[1].coeffs[32] = nonce1;
  buf[2].coeffs[32] = nonce2;
  buf[3].coeffs[32] = nonce3;

  shake256x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 33);
  shake256x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, NOISE_NBLOCKS * 16, &state);

  poly_cbd_eta1(r0, buf[0].vec); // buf.vec数组的个数似乎都对不上，每一层系数中的数组个数都比下一层多几个
  poly_cbd_eta1(r1, buf[1].vec);
  poly_cbd_eta1(r2, buf[2].vec);
  poly_cbd_eta1(r3, buf[3].vec);
}

#if KYBER_K == 2
void poly_getnoise_eta1122_4x(poly *r0,
                              poly *r1,
                              poly *r2,
                              poly *r3,
                              const uint8_t seed[32],
                              uint8_t nonce0,
                              uint8_t nonce1,
                              uint8_t nonce2,
                              uint8_t nonce3)
{
  ALIGNED_UINT8(NOISE_NBLOCKS * SHAKE256_RATE)
  buf[4];
  __m256i f;
  keccakx4_state state;

  f = _mm256_loadu_si256((__m256i *)seed);
  _mm256_store_si256(buf[0].vec, f);
  _mm256_store_si256(buf[1].vec, f);
  _mm256_store_si256(buf[2].vec, f);
  _mm256_store_si256(buf[3].vec, f);

  buf[0].coeffs[32] = nonce0;
  buf[1].coeffs[32] = nonce1;
  buf[2].coeffs[32] = nonce2;
  buf[3].coeffs[32] = nonce3;

  shake256x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 33);
  shake256x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, NOISE_NBLOCKS, &state);

  poly_cbd_eta1(r0, buf[0].vec);
  poly_cbd_eta1(r1, buf[1].vec);
  poly_cbd_eta2(r2, buf[2].vec);
  poly_cbd_eta2(r3, buf[3].vec);
}
#endif
#endif

void poly_ntt(poly_16 *r)
{
  ntt_avx_16(r->vec, qdata_16.vec);
}

void poly_invntt_tomont(poly_16 *r)
{
  invntt_avx_16(r->vec, qdata_16.vec);
}

// void poly_nttunpack(poly_16 *r)
// {
//   nttunpack_avx_16(r->vec);
// }

void poly_basemul_montgomery(poly_16 *r, const poly_16 *a, const poly_16 *b)
{
  basemul_avx_16(r->vec, a->vec, b->vec, qdata_16.vec);
}

void poly_tomont(poly_16 *r)
{
  tomont_avx_16(r->vec, qdata_16.vec);
}

void poly_reduce(poly_16 *r)
{
  reduce_avx_16(r->vec, qdata_16.vec);
}

void poly_add(poly_16 *r, const poly_16 *a, const poly_16 *b)
{
  unsigned int i = 0;
  __m256i f0, f1;

  uint64_t start, end, cost[KYBER_N];
  // _mm_prefetch(&a->vec[i + 2], _MM_HINT_T0);
  // _mm_prefetch(&b->vec[i + 2], _MM_HINT_T0);
  // f0 = _mm256_load_si256(&a->vec[i]);
  // f1 = _mm256_load_si256(&b->vec[i]);
  // f0 = _mm256_add_epi16(f0, f1);
  // _mm256_store_si256(&r->vec[i], f0);
  // i++;
  // f0 = _mm256_load_si256(&a->vec[i]);
  // f1 = _mm256_load_si256(&b->vec[i]);
  // f0 = _mm256_add_epi16(f0, f1);
  // _mm256_store_si256(&r->vec[i], f0);
  // i++;
  // printf("a: %p, b: %p, a_addr: %p, b_addr: %p\n", &a->vec[i], &b->vec[i], a_addr & mask, b_addr & mask);
  // _mm_prefetch(a_addr & mask, _MM_HINT_T0);
  // _mm_prefetch(b_addr & mask, _MM_HINT_T0);
  // _mm_prefetch((a_addr & mask) + 4096, _MM_HINT_T0);
  // _mm_prefetch((b_addr & mask) + 4096, _MM_HINT_T0);
  // _mm_prefetch((a_addr & mask) + 4096 * 2, _MM_HINT_T0);
  // _mm_prefetch((b_addr & mask) + 4096 * 2, _MM_HINT_T0);
  // _mm_prefetch((a_addr & mask) + 4096 * 3, _MM_HINT_T0);
  // _mm_prefetch((b_addr & mask) + 4096 * 3, _MM_HINT_T0);
  // uint64_t a_addr = &a->vec[i];
  // uint64_t b_addr = &b->vec[i];
  // uint64_t mask = 0xfffffffffffff000;

  // f0 = _mm256_load_si256((a_addr & mask));
  // f1 = _mm256_load_si256((b_addr & mask));
  // f0 = _mm256_add_epi16(f0, f1);
  // _mm256_store_si256((a_addr & mask), f0);

  // f0 = _mm256_load_si256((a_addr & mask) + 4096);
  // f1 = _mm256_load_si256((b_addr & mask) + 4096);
  // f0 = _mm256_add_epi16(f0, f1);
  // _mm256_store_si256((a_addr & mask) + 4096, f0);

  // f0 = _mm256_load_si256((a_addr & mask) + 4096 * 2);
  // f1 = _mm256_load_si256((b_addr & mask) + 4096 * 2);
  // f0 = _mm256_add_epi16(f0, f1);
  // _mm256_store_si256((a_addr & mask) + 4096 * 2, f0);

  // f0 = _mm256_load_si256((a_addr & mask) + 4096 * 3);
  // f1 = _mm256_load_si256((b_addr & mask) + 4096 * 3);
  // f0 = _mm256_add_epi16(f0, f1);
  // _mm256_store_si256((a_addr & mask) + 4096 * 3, f0);

  for (i = 0; i < KYBER_N; i++)
  {
    // _mm_prefetch(&a->vec[i + 2], _MM_HINT_T0);
    // _mm_prefetch(&b->vec[i + 2], _MM_HINT_T0);
    // start = cycles_now();
    f0 = _mm256_load_si256(&a->vec[i]);
    f1 = _mm256_load_si256(&b->vec[i]);
    f0 = _mm256_add_epi16(f0, f1);
    _mm256_store_si256(&r->vec[i], f0);
    // end = cycles_now();
    // cost[i] = end - start;
  }

  // for (i = 0; i < KYBER_N; i++)
  // {
  //   printf("%d: %d\n", i, cost[i]);
  // }

  // f0 = _mm256_load_si256(&a->vec[i]);
  // f1 = _mm256_load_si256(&b->vec[i]);
  // f0 = _mm256_add_epi16(f0, f1);
  // _mm256_store_si256(&r->vec[i], f0);
}

void poly_sub(poly_16 *r, const poly_16 *a, const poly_16 *b)
{
  unsigned int i;
  __m256i f0, f1;

  for (i = 0; i < KYBER_N; i++)
  {
    f0 = _mm256_load_si256(&a->vec[i]);
    f1 = _mm256_load_si256(&b->vec[i]);
    f0 = _mm256_sub_epi16(f0, f1);
    _mm256_store_si256(&r->vec[i], f0);
  }
}
