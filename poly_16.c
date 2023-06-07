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


#if (KYBER_POLYCOMPRESSEDBYTES == 96)
void poly_compress(uint8_t r[96], const poly * restrict a)
{
  unsigned int i;
  __m256i f0, f1, f2, f3;
  __m128i t0, t1;
  const __m256i v = _mm256_load_si256(&qdata.vec[_16XV/16]);
  const __m256i shift1 = _mm256_set1_epi16(1 << 8);
  const __m256i mask = _mm256_set1_epi16(7);
  const __m256i shift2 = _mm256_set1_epi16((8 << 8) + 1);
  const __m256i shift3 = _mm256_set1_epi32((64 << 16) + 1);
  const __m256i sllvdidx = _mm256_set1_epi64x(12LL << 32);
  const __m256i shufbidx = _mm256_set_epi8( 8, 2, 1, 0,-1,-1,-1,-1,14,13,12, 6, 5, 4,10, 9,
                                           -1,-1,-1,-1,14,13,12, 6, 5, 4,10, 9, 8, 2, 1, 0);

  for(i=0;i<KYBER_N/64;i++) {
    f0 = _mm256_load_si256(&a->vec[4*i+0]);
    f1 = _mm256_load_si256(&a->vec[4*i+1]);
    f2 = _mm256_load_si256(&a->vec[4*i+2]);
    f3 = _mm256_load_si256(&a->vec[4*i+3]);
    f0 = _mm256_mulhi_epi16(f0,v);
    f1 = _mm256_mulhi_epi16(f1,v);
    f2 = _mm256_mulhi_epi16(f2,v);
    f3 = _mm256_mulhi_epi16(f3,v);
    f0 = _mm256_mulhrs_epi16(f0,shift1);
    f1 = _mm256_mulhrs_epi16(f1,shift1);
    f2 = _mm256_mulhrs_epi16(f2,shift1);
    f3 = _mm256_mulhrs_epi16(f3,shift1);
    f0 = _mm256_and_si256(f0,mask);
    f1 = _mm256_and_si256(f1,mask);
    f2 = _mm256_and_si256(f2,mask);
    f3 = _mm256_and_si256(f3,mask);
    f0 = _mm256_packus_epi16(f0,f1);
    f2 = _mm256_packus_epi16(f2,f3);
    f0 = _mm256_maddubs_epi16(f0,shift2);	// a0 a1 a2 a3 b0 b1 b2 b3 a4 a5 a6 a7 b4 b5 b6 b7
    f2 = _mm256_maddubs_epi16(f2,shift2);	// c0 c1 c2 c3 d0 d1 d2 d3 c4 c5 c6 c7 d4 d5 d6 d7
    f0 = _mm256_madd_epi16(f0,shift3);		// a0 a1 b0 b1 a2 a3 b2 b3
    f2 = _mm256_madd_epi16(f2,shift3);		// c0 c1 d0 d1 c2 c3 d2 d3
    f0 = _mm256_sllv_epi32(f0,sllvdidx);
    f2 = _mm256_sllv_epi32(f2,sllvdidx);
    f0 = _mm256_hadd_epi32(f0,f2);		// a0 c0 c0 d0 a1 b1 c1 d1
    f0 = _mm256_permute4x64_epi64(f0,0xD8);	// a0 b0 a1 b1 c0 d0 c1 d1
    f0 = _mm256_shuffle_epi8(f0,shufbidx);
    t0 = _mm256_castsi256_si128(f0);
    t1 = _mm256_extracti128_si256(f0,1);
    t0 = _mm_blend_epi32(t0,t1,0x08);
    _mm_storeu_si128((__m128i *)&r[24*i+ 0],t0);
    _mm_storel_epi64((__m128i *)&r[24*i+16],t1);
  }
}


void poly_decompress(poly * restrict r, const uint8_t a[96])
{
  unsigned int i;
  __m128i t;
  __m256i f;
  const __m256i q = _mm256_load_si256(&qdata.vec[_16XQ/16]);
  const __m256i shufbidx = _mm256_set_epi8(5,5,5,5,5,4,4,4,4,4,4,3,3,3,3,3,
                                           2,2,2,2,2,1,1,1,1,1,1,0,0,0,0,0);
  const __m256i mask = _mm256_set_epi16(224,28,896,112,14,448,56,7,
                                        224,28,896,112,14,448,56,7);
  const __m256i shift = _mm256_set_epi16(128,1024,32,256,2048,64,512,4096,
                                         128,1024,32,256,2048,64,512,4096);

  for(i=0;i<KYBER_N/16;i++) {
    t = _mm_castps_si128(_mm_load_ss((float *)&a[6*i+0])));
    t = _mm_insert_epi16(t,*(int16_t *)&a[6*i+4],2);
    f = _mm256_broadcastsi128_si256(t);
    f = _mm256_blend_epi16(f,g,0x);
    f = _mm256_shuffle_epi8(f,shufbidx);
    f = _mm256_and_si256(f,mask);
    f = _mm256_mullo_epi16(f,shift);
    f = _mm256_mulhrs_epi16(f,q);
    _mm256_store_si256(&r->vec[i],f);
  }
}

#elif (KYBER_POLYCOMPRESSEDBYTES == 128)
void poly_compress(uint8_t r[128], const poly * restrict a)
{
  unsigned int i;
  __m256i f0, f1, f2, f3;
  const __m256i v = _mm256_load_si256(&qdata_16.vec[_16XV_16/16]);
  const __m256i shift1 = _mm256_set1_epi16(1 << 9);
  const __m256i mask = _mm256_set1_epi16(15);
  const __m256i shift2 = _mm256_set1_epi16((16 << 8) + 1);
  const __m256i permdidx = _mm256_set_epi32(7,3,6,2,5,1,4,0);

  for(i=0;i<KYBER_N/64;i++) {
    f0 = _mm256_load_si256(&a->vec[4*i+0]);
    f1 = _mm256_load_si256(&a->vec[4*i+1]);
    f2 = _mm256_load_si256(&a->vec[4*i+2]);
    f3 = _mm256_load_si256(&a->vec[4*i+3]);
    f0 = _mm256_mulhi_epi16(f0,v);
    f1 = _mm256_mulhi_epi16(f1,v);
    f2 = _mm256_mulhi_epi16(f2,v);
    f3 = _mm256_mulhi_epi16(f3,v);
    f0 = _mm256_mulhrs_epi16(f0,shift1);
    f1 = _mm256_mulhrs_epi16(f1,shift1);
    f2 = _mm256_mulhrs_epi16(f2,shift1);
    f3 = _mm256_mulhrs_epi16(f3,shift1);
    f0 = _mm256_and_si256(f0,mask);
    f1 = _mm256_and_si256(f1,mask);
    f2 = _mm256_and_si256(f2,mask);
    f3 = _mm256_and_si256(f3,mask);
    f0 = _mm256_packus_epi16(f0,f1);
    f2 = _mm256_packus_epi16(f2,f3);
    f0 = _mm256_maddubs_epi16(f0,shift2);
    f2 = _mm256_maddubs_epi16(f2,shift2);
    f0 = _mm256_packus_epi16(f0,f2);
    f0 = _mm256_permutevar8x32_epi32(f0,permdidx);
    _mm256_storeu_si256((__m256i *)&r[32*i],f0);
  }
}

void poly_decompress(poly * restrict r, const uint8_t a[128])
{
  unsigned int i;
  __m128i t;
  __m256i f;
  const __m256i q = _mm256_load_si256(&qdata_16.vec[_16XQ_16/16]);
  const __m256i shufbidx = _mm256_set_epi8(7,7,7,7,6,6,6,6,5,5,5,5,4,4,4,4,
                                           3,3,3,3,2,2,2,2,1,1,1,1,0,0,0,0);
  const __m256i mask = _mm256_set1_epi32(0x00F0000F);
  const __m256i shift = _mm256_set1_epi32((128 << 16) + 2048);

  for(i=0;i<KYBER_N/16;i++) {
    t = _mm_loadl_epi64((__m128i *)&a[8*i]);
    f = _mm256_broadcastsi128_si256(t);
    f = _mm256_shuffle_epi8(f,shufbidx);
    f = _mm256_and_si256(f,mask);
    f = _mm256_mullo_epi16(f,shift);
    f = _mm256_mulhrs_epi16(f,q);
    _mm256_store_si256(&r->vec[i],f);
  }
}

#elif (KYBER_POLYCOMPRESSEDBYTES == 160)
void poly_compress(uint8_t r[160], const poly * restrict a)
{
  unsigned int i;
  __m256i f0, f1;
  __m128i t0, t1;
  const __m256i v = _mm256_load_si256(&qdata.vec[_16XV/16]);
  const __m256i shift1 = _mm256_set1_epi16(1 << 10);
  const __m256i mask = _mm256_set1_epi16(31);
  const __m256i shift2 = _mm256_set1_epi16((32 << 8) + 1);
  const __m256i shift3 = _mm256_set1_epi32((1024 << 16) + 1);
  const __m256i sllvdidx = _mm256_set1_epi64x(12);
  const __m256i shufbidx = _mm256_set_epi8( 8,-1,-1,-1,-1,-1, 4, 3, 2, 1, 0,-1,12,11,10, 9,
                                           -1,12,11,10, 9, 8,-1,-1,-1,-1,-1 ,4, 3, 2, 1, 0);

  for(i=0;i<KYBER_N/32;i++) {
    f0 = _mm256_load_si256(&a->vec[2*i+0]);
    f1 = _mm256_load_si256(&a->vec[2*i+1]);
    f0 = _mm256_mulhi_epi16(f0,v);
    f1 = _mm256_mulhi_epi16(f1,v);
    f0 = _mm256_mulhrs_epi16(f0,shift1);
    f1 = _mm256_mulhrs_epi16(f1,shift1);
    f0 = _mm256_and_si256(f0,mask);
    f1 = _mm256_and_si256(f1,mask);
    f0 = _mm256_packus_epi16(f0,f1);
    f0 = _mm256_maddubs_epi16(f0,shift2);	// a0 a1 a2 a3 b0 b1 b2 b3 a4 a5 a6 a7 b4 b5 b6 b7
    f0 = _mm256_madd_epi16(f0,shift3);		// a0 a1 b0 b1 a2 a3 b2 b3
    f0 = _mm256_sllv_epi32(f0,sllvdidx);
    f0 = _mm256_srlv_epi64(f0,sllvdidx);
    f0 = _mm256_shuffle_epi8(f0,shufbidx);
    t0 = _mm256_castsi256_si128(f0);
    t1 = _mm256_extracti128_si256(f0,1);
    t0 = _mm_blendv_epi8(t0,t1,_mm256_castsi256_si128(shufbidx));
    _mm_storeu_si128((__m128i *)&r[20*i+ 0],t0);
    memcpy(&r[20*i+16],&t1,4);
  }
}

void poly_decompress(poly * restrict r, const uint8_t a[160])
{
  unsigned int i;
  __m128i t;
  __m256i f;
  int16_t ti;
  const __m256i q = _mm256_load_si256(&qdata.vec[_16XQ/16]);
  const __m256i shufbidx = _mm256_set_epi8(9,9,9,8,8,8,8,7,7,6,6,6,6,5,5,5,
                                           4,4,4,3,3,3,3,2,2,1,1,1,1,0,0,0);
  const __m256i mask = _mm256_set_epi16(248,1984,62,496,3968,124,992,31,
                                        248,1984,62,496,3968,124,992,31);
  const __m256i shift = _mm256_set_epi16(128,16,512,64,8,256,32,1024,
                                         128,16,512,64,8,256,32,1024);

  for(i=0;i<KYBER_N/16;i++) {
    t = _mm_loadl_epi64((__m128i *)&a[10*i+0]);
    memcpy(&ti,&a[10*i+8],2);
    t = _mm_insert_epi16(t,ti,4);
    f = _mm256_broadcastsi128_si256(t);
    f = _mm256_shuffle_epi8(f,shufbidx);
    f = _mm256_and_si256(f,mask);
    f = _mm256_mullo_epi16(f,shift);
    f = _mm256_mulhrs_epi16(f,q);
    _mm256_store_si256(&r->vec[i],f);
  }
}

#endif


void poly_tobytes(uint8_t r[KYBER_POLYBYTES*16], const poly_16 *a)
{
  ntttobytes_avx_16(r, a->vec, qdata_16.vec);
}


void poly_frombytes(poly_16 *r, const uint8_t a[KYBER_POLYBYTES*16])
{
  nttfrombytes_avx_16(r->vec, a, qdata_16.vec);
}


void poly_frommsg(poly_16 * restrict r, const uint8_t msg[16][KYBER_INDCPA_MSGBYTES])
{
#if (KYBER_INDCPA_MSGBYTES != 32)
#error "KYBER_INDCPA_MSGBYTES must be equal to 32!"
#endif
  __m256i f, g0, g1, g2, g3, h0, h1, h2, h3;
  const __m256i shift = _mm256_broadcastsi128_si256(_mm_set_epi32(0,1,2,3));
  const __m256i idx = _mm256_broadcastsi128_si256(_mm_set_epi8(15,14,11,10,7,6,3,2,13,12,9,8,5,4,1,0));
  const __m256i hqs = _mm256_set1_epi16((KYBER_Q+1)/2);

#define FROMMSG64(i, j)						\
  g3 = _mm256_shuffle_epi32(f,0x55*i);				\
  g3 = _mm256_sllv_epi32(g3,shift);				\
  g3 = _mm256_shuffle_epi8(g3,idx);				\
  g0 = _mm256_slli_epi16(g3,12);				\
  g1 = _mm256_slli_epi16(g3,8);					\
  g2 = _mm256_slli_epi16(g3,4);					\
  g0 = _mm256_srai_epi16(g0,15);				\
  g1 = _mm256_srai_epi16(g1,15);				\
  g2 = _mm256_srai_epi16(g2,15);				\
  g3 = _mm256_srai_epi16(g3,15);				\
  g0 = _mm256_and_si256(g0,hqs);  /* 19 18 17 16  3  2  1  0 */	\
  g1 = _mm256_and_si256(g1,hqs);  /* 23 22 21 20  7  6  5  4 */	\
  g2 = _mm256_and_si256(g2,hqs);  /* 27 26 25 24 11 10  9  8 */	\
  g3 = _mm256_and_si256(g3,hqs);  /* 31 30 29 28 15 14 13 12 */	\
  h0 = _mm256_unpacklo_epi64(g0,g1);				\
  h2 = _mm256_unpackhi_epi64(g0,g1);				\
  h1 = _mm256_unpacklo_epi64(g2,g3);				\
  h3 = _mm256_unpackhi_epi64(g2,g3);				\
  g0 = _mm256_permute2x128_si256(h0,h1,0x20);			\
  g2 = _mm256_permute2x128_si256(h0,h1,0x31);			\
  g1 = _mm256_permute2x128_si256(h2,h3,0x20);			\
  g3 = _mm256_permute2x128_si256(h2,h3,0x31);			\
  _mm256_store_si256(&r->vec[j*16+0+2*i+0],g0);	\
  _mm256_store_si256(&r->vec[j*16+0+2*i+1],g1);	\
  _mm256_store_si256(&r->vec[j*16+8+2*i+0],g2);	\
  _mm256_store_si256(&r->vec[j*16+8+2*i+1],g3)

  f = _mm256_loadu_si256((__m256i *)msg);
  FROMMSG64(0, 0);
  FROMMSG64(1, 0);
  FROMMSG64(2, 0);
  FROMMSG64(3, 0);
  f = _mm256_loadu_si256((__m256i *)(msg+256));
  FROMMSG64(0, 1);
  FROMMSG64(1, 1);
  FROMMSG64(2, 1);
  FROMMSG64(3, 1);
  f = _mm256_loadu_si256((__m256i *)(msg+512));
  FROMMSG64(0, 2);
  FROMMSG64(1, 2);
  FROMMSG64(2, 2);
  FROMMSG64(3, 2);
  f = _mm256_loadu_si256((__m256i *)(msg+768));
  FROMMSG64(0, 3);
  FROMMSG64(1, 3);
  FROMMSG64(2, 3);
  FROMMSG64(3, 3);
  f = _mm256_loadu_si256((__m256i *)(msg+1024));
  FROMMSG64(0, 4);
  FROMMSG64(1, 4);
  FROMMSG64(2, 4);
  FROMMSG64(3, 4);
  f = _mm256_loadu_si256((__m256i *)(msg+1280));
  FROMMSG64(0, 5);
  FROMMSG64(1, 5);
  FROMMSG64(2, 5);
  FROMMSG64(3, 5);
  f = _mm256_loadu_si256((__m256i *)(msg+1536));
  FROMMSG64(0, 6);
  FROMMSG64(1, 6);
  FROMMSG64(2, 6);
  FROMMSG64(3, 6);
  f = _mm256_loadu_si256((__m256i *)(msg+1792));
  FROMMSG64(0, 7);
  FROMMSG64(1, 7);
  FROMMSG64(2, 7);
  FROMMSG64(3, 7);
  f = _mm256_loadu_si256((__m256i *)(msg+2048));
  FROMMSG64(0, 8);
  FROMMSG64(1, 8);
  FROMMSG64(2, 8);
  FROMMSG64(3, 8);
  f = _mm256_loadu_si256((__m256i *)(msg+2304));
  FROMMSG64(0, 9);
  FROMMSG64(1, 9);
  FROMMSG64(2, 9);
  FROMMSG64(3, 9);
  f = _mm256_loadu_si256((__m256i *)(msg+2560));
  FROMMSG64(0, 10);
  FROMMSG64(1, 10);
  FROMMSG64(2, 10);
  FROMMSG64(3, 10);
  f = _mm256_loadu_si256((__m256i *)(msg+2816));
  FROMMSG64(0, 11);
  FROMMSG64(1, 11);
  FROMMSG64(2, 11);
  FROMMSG64(3, 11);
  f = _mm256_loadu_si256((__m256i *)(msg+3072));
  FROMMSG64(0, 12);
  FROMMSG64(1, 12);
  FROMMSG64(2, 12);
  FROMMSG64(3, 12);
  f = _mm256_loadu_si256((__m256i *)(msg+3328));
  FROMMSG64(0, 13);
  FROMMSG64(1, 13);
  FROMMSG64(2, 13);
  FROMMSG64(3, 13);
  f = _mm256_loadu_si256((__m256i *)(msg+3584));
  FROMMSG64(0, 14);
  FROMMSG64(1, 14);
  FROMMSG64(2, 14);
  FROMMSG64(3, 14);
  f = _mm256_loadu_si256((__m256i *)(msg+3840));
  FROMMSG64(0, 15);
  FROMMSG64(1, 15);
  FROMMSG64(2, 15);
  FROMMSG64(3, 15);

}


void poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const poly * restrict a)
{
  unsigned int i;
  uint32_t small;
  __m256i f0, f1, g0, g1;
  const __m256i hq = _mm256_set1_epi16((KYBER_Q - 1)/2);
  const __m256i hhq = _mm256_set1_epi16((KYBER_Q - 1)/4);

  for(i=0;i<KYBER_N/32;i++) {
    f0 = _mm256_load_si256(&a->vec[2*i+0]);
    f1 = _mm256_load_si256(&a->vec[2*i+1]);
    f0 = _mm256_sub_epi16(hq, f0);
    f1 = _mm256_sub_epi16(hq, f1);
    g0 = _mm256_srai_epi16(f0, 15);
    g1 = _mm256_srai_epi16(f1, 15);
    f0 = _mm256_xor_si256(f0, g0);
    f1 = _mm256_xor_si256(f1, g1);
    f0 = _mm256_sub_epi16(f0, hhq);
    f1 = _mm256_sub_epi16(f1, hhq);
    f0 = _mm256_packs_epi16(f0, f1);
    f0 = _mm256_permute4x64_epi64(f0, 0xD8);
    small = _mm256_movemask_epi8(f0);
    memcpy(&msg[4*i], &small, 4);
  }
}


void poly_getnoise_eta1(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce)
{
  ALIGNED_UINT8(KYBER_ETA1*KYBER_N/4+32) buf; // +32 bytes as required by poly_cbd_eta1
  prf(buf.coeffs, KYBER_ETA1*KYBER_N/4, seed, nonce);
  poly_cbd_eta1(r, buf.vec);
}


void poly_getnoise_eta2(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce)
{
  ALIGNED_UINT8(KYBER_ETA2*KYBER_N/4) buf;
  prf(buf.coeffs, KYBER_ETA2*KYBER_N/4, seed, nonce);
  poly_cbd_eta2(r, buf.vec);
}

#ifndef KYBER_90S
#define NOISE_NBLOCKS ((KYBER_ETA1*KYBER_N/4+SHAKE256_RATE-1)/SHAKE256_RATE)
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
  ALIGNED_UINT8(NOISE_NBLOCKS*16*SHAKE256_RATE) buf[4];    //NOISE_NBLOCKS = 1
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
  shake256x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, NOISE_NBLOCKS*16, &state);

  poly_cbd_eta1(r0, buf[0].vec);  //buf.vec数组的个数似乎都对不上，每一层系数中的数组个数都比下一层多几个
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
  ALIGNED_UINT8(NOISE_NBLOCKS*SHAKE256_RATE) buf[4];
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

void poly_nttunpack(poly_16 *r)
{
  nttunpack_avx_16(r->vec);
}


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
  unsigned int i;
  __m256i f0, f1;

  for(i=0;i<KYBER_N;i++) {
    f0 = _mm256_load_si256(&a->vec[i]);
    f1 = _mm256_load_si256(&b->vec[i]);
    f0 = _mm256_add_epi16(f0, f1);
    _mm256_store_si256(&r->vec[i], f0);
  }
}


void poly_sub(poly *r, const poly *a, const poly *b)
{
  unsigned int i;
  __m256i f0, f1;

  for(i=0;i<KYBER_N/16;i++) {
    f0 = _mm256_load_si256(&a->vec[i]);
    f1 = _mm256_load_si256(&b->vec[i]);
    f0 = _mm256_sub_epi16(f0, f1);
    _mm256_store_si256(&r->vec[i], f0);
  }
}
