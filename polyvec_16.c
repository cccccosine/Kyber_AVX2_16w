#include <stdint.h>
#include <immintrin.h>
#include <string.h>
#include "params.h"
#include "polyvec_16.h"
#include "poly_16.h"
#include "ntt_16.h"
#include "consts_16.h"

#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320 * 16))
static void poly_compress10(uint8_t r[320*16], const poly_16 * restrict a)
{
  unsigned int i;
  __m256i f0, f1, f2, f3, f4, f5, f6, f7, f8, f9, g0;
  const __m256i v = _mm256_load_si256(&qdata_16.vec[_16XV_16/16]);
  const __m256i v8 = _mm256_slli_epi16(v,3);
  const __m256i off = _mm256_set1_epi16(15);
  const __m256i shift1 = _mm256_set1_epi16(1 << 12);
  const __m256i mask = _mm256_set1_epi16(1023);

  for(i=0;i<KYBER_N/8;i++) {
    f0 = _mm256_load_si256(&a->vec[i*8]);
    f4 = _mm256_mullo_epi16(f0,v8);
    f5 = _mm256_add_epi16(f0,off);
    f0 = _mm256_slli_epi16(f0,3);
    f0 = _mm256_mulhi_epi16(f0,v);
    f5 = _mm256_sub_epi16(f4,f5);
    f4 = _mm256_andnot_si256(f4,f5);
    f4 = _mm256_srli_epi16(f4,15);
    f0 = _mm256_sub_epi16(f0,f4);
    f0 = _mm256_mulhrs_epi16(f0,shift1);
    f0 = _mm256_and_si256(f0,mask);

    f1 = _mm256_load_si256(&a->vec[i*8+1]);
    f4 = _mm256_mullo_epi16(f1,v8);
    f5 = _mm256_add_epi16(f1,off);
    f1 = _mm256_slli_epi16(f1,3);
    f1 = _mm256_mulhi_epi16(f1,v);
    f5 = _mm256_sub_epi16(f4,f5);
    f4 = _mm256_andnot_si256(f4,f5);
    f4 = _mm256_srli_epi16(f4,15);
    f1 = _mm256_sub_epi16(f1,f4);
    f1 = _mm256_mulhrs_epi16(f1,shift1);
    f1 = _mm256_and_si256(f1,mask);

    f2 = _mm256_load_si256(&a->vec[i*8+2]);
    f4 = _mm256_mullo_epi16(f2,v8);
    f5 = _mm256_add_epi16(f2,off);
    f2 = _mm256_slli_epi16(f2,3);
    f2 = _mm256_mulhi_epi16(f2,v);
    f5 = _mm256_sub_epi16(f4,f5);
    f4 = _mm256_andnot_si256(f4,f5);
    f4 = _mm256_srli_epi16(f4,15);
    f2 = _mm256_sub_epi16(f2,f4);
    f2 = _mm256_mulhrs_epi16(f2,shift1);
    f2 = _mm256_and_si256(f2,mask);

    f3 = _mm256_load_si256(&a->vec[i*8+3]);
    f4 = _mm256_mullo_epi16(f3,v8);
    f5 = _mm256_add_epi16(f3,off);
    f3 = _mm256_slli_epi16(f3,3);
    f3 = _mm256_mulhi_epi16(f3,v);
    f5 = _mm256_sub_epi16(f4,f5);
    f4 = _mm256_andnot_si256(f4,f5);
    f4 = _mm256_srli_epi16(f4,15);
    f3 = _mm256_sub_epi16(f3,f4);
    f3 = _mm256_mulhrs_epi16(f3,shift1);
    f3 = _mm256_and_si256(f3,mask);

    f6 = _mm256_load_si256(&a->vec[i*8+4]);
    f4 = _mm256_mullo_epi16(f6,v8);
    f5 = _mm256_add_epi16(f6,off);
    f6 = _mm256_slli_epi16(f6,3);
    f6 = _mm256_mulhi_epi16(f6,v);
    f5 = _mm256_sub_epi16(f4,f5);
    f4 = _mm256_andnot_si256(f4,f5);
    f4 = _mm256_srli_epi16(f4,15);
    f6 = _mm256_sub_epi16(f6,f4);
    f6 = _mm256_mulhrs_epi16(f6,shift1);
    f6 = _mm256_and_si256(f6,mask);

    f7 = _mm256_load_si256(&a->vec[i*8+5]);
    f4 = _mm256_mullo_epi16(f7,v8);
    f5 = _mm256_add_epi16(f7,off);
    f7 = _mm256_slli_epi16(f7,3);
    f7 = _mm256_mulhi_epi16(f7,v);
    f5 = _mm256_sub_epi16(f4,f5);
    f4 = _mm256_andnot_si256(f4,f5);
    f4 = _mm256_srli_epi16(f4,15);
    f7 = _mm256_sub_epi16(f7,f4);
    f7 = _mm256_mulhrs_epi16(f7,shift1);
    f7 = _mm256_and_si256(f7,mask);

    f8 = _mm256_load_si256(&a->vec[i*8+6]);
    f4 = _mm256_mullo_epi16(f8,v8);
    f5 = _mm256_add_epi16(f8,off);
    f8 = _mm256_slli_epi16(f8,3);
    f8 = _mm256_mulhi_epi16(f8,v);
    f5 = _mm256_sub_epi16(f4,f5);
    f4 = _mm256_andnot_si256(f4,f5);
    f4 = _mm256_srli_epi16(f4,15);
    f8 = _mm256_sub_epi16(f8,f4);
    f8 = _mm256_mulhrs_epi16(f8,shift1);
    f8 = _mm256_and_si256(f8,mask);

    f9 = _mm256_load_si256(&a->vec[i*8+7]);
    f4 = _mm256_mullo_epi16(f9,v8);
    f5 = _mm256_add_epi16(f9,off);
    f9 = _mm256_slli_epi16(f9,3);
    f9 = _mm256_mulhi_epi16(f9,v);
    f5 = _mm256_sub_epi16(f4,f5);
    f4 = _mm256_andnot_si256(f4,f5);
    f4 = _mm256_srli_epi16(f4,15);
    f9 = _mm256_sub_epi16(f9,f4);
    f9 = _mm256_mulhrs_epi16(f9,shift1);
    f9 = _mm256_and_si256(f9,mask);
    
    g0 = _mm256_slli_epi16(f1, 10);
    f0 = _mm256_add_epi16(f0, g0);   //f0 = b0 | b1[0:5]
    f1 = _mm256_srli_epi16(f1, 6);
    g0 = _mm256_slli_epi16(f2, 4);
    f1 = _mm256_add_epi16(f1, g0);   //f1 = b1[6:9] | b2[0:9]
    g0 = _mm256_slli_epi16(f3, 14);
    f1 = _mm256_add_epi16(f1, g0);   //f1 = b1[6:9] | b2[0:9] | b3[0:1]

    f3 = _mm256_srli_epi16(f3, 2);
    g0 = _mm256_slli_epi16(f6, 8);
    f3 = _mm256_add_epi16(f3, g0);   //f3 = b3[2:9] | b6[0:7]
    f6 = _mm256_srli_epi16(f6, 8);
    g0 = _mm256_slli_epi16(f7, 2);
    f6 = _mm256_add_epi16(f6, g0);   //f6 = b6[8:9] | b7[0:9]
    g0 = _mm256_slli_epi16(f8, 12);
    f6 = _mm256_add_epi16(f6, g0);   //f6 = b6[8:9] | b7[0:9] | b8[0:3]
    f8 = _mm256_srli_epi16(f8, 4);
    g0 = _mm256_slli_epi16(f9, 6);
    f8 = _mm256_add_epi16(f8, g0);   //f8 = b8[4:9] | b9[0:9]

    _mm256_storeu_si256((__m256i *)&r[i*160],f0);
    _mm256_storeu_si256((__m256i *)&r[i*160 + 32],f1);
    _mm256_storeu_si256((__m256i *)&r[i*160 + 64],f3);
    _mm256_storeu_si256((__m256i *)&r[i*160 + 96],f6);
    _mm256_storeu_si256((__m256i *)&r[i*160 + 128],f8);

  }
}

static void poly_decompress10(poly_16 * restrict r, const uint8_t a[320*16])
{
  unsigned int i;
  __m256i f0, f1, f2, f3, f4, g;
  const __m256i q = _mm256_set1_epi16(KYBER_Q<<3);
  const __m256i mask = _mm256_set1_epi16(4092);

  for(i=0;i<KYBER_N/8;i++) {
    f0 = _mm256_loadu_si256((__m256i *)&a[160*i]);
    f1 = _mm256_loadu_si256((__m256i *)&a[160*i + 32]);
    f2 = _mm256_loadu_si256((__m256i *)&a[160*i + 64]);
    f3 = _mm256_loadu_si256((__m256i *)&a[160*i + 96]);
    f4 = _mm256_loadu_si256((__m256i *)&a[160*i + 128]);

    g = _mm256_slli_epi16(f0,2);
    g = _mm256_and_si256(g,mask);
    g = _mm256_mulhrs_epi16(g,q);
    _mm256_store_si256(&r->vec[i*8],g);  //b0[9:0]
    f0 = _mm256_srli_epi16(f0, 8);
    g = _mm256_slli_epi16(f1, 8);
    f0 = _mm256_add_epi16(f0, g);
    f0 = _mm256_and_si256(f0,mask);
    f0 = _mm256_mulhrs_epi16(f0,q);
    _mm256_store_si256(&r->vec[i*8+1],f0);  //b1[9:0]
    g = _mm256_srli_epi16(f1, 2);
    g = _mm256_and_si256(g,mask);
    g = _mm256_mulhrs_epi16(g,q);
    _mm256_store_si256(&r->vec[i*8+2],g);  //b2[9:0]
    f1 = _mm256_srli_epi16(f1, 12);
    g = _mm256_slli_epi16(f2, 4);
    f1 = _mm256_add_epi16(f1, g);
    f1 = _mm256_and_si256(f1,mask);
    f1 = _mm256_mulhrs_epi16(f1,q);
    _mm256_store_si256(&r->vec[i*8+3],f1);  //b3[9:0]
    f2 = _mm256_srli_epi16(f2, 6);
    g = _mm256_slli_epi16(f3, 10);
    f2 = _mm256_add_epi16(f2, g);
    f2 = _mm256_and_si256(f2,mask);
    f2 = _mm256_mulhrs_epi16(f2,q);
    _mm256_store_si256(&r->vec[i*8+4],f2);  //b4[9:0]
    g = _mm256_slli_epi16(f3, 0);
    g = _mm256_and_si256(g,mask);
    g = _mm256_mulhrs_epi16(g,q);
    _mm256_store_si256(&r->vec[i*8+5],g);  //b5[9:0]
    f3 = _mm256_srli_epi16(f3, 10);
    g = _mm256_slli_epi16(f4, 6);
    f3 = _mm256_add_epi16(f3, g);
    f3 = _mm256_and_si256(f3,mask);
    f3 = _mm256_mulhrs_epi16(f3,q);
    _mm256_store_si256(&r->vec[i*8+6],f3);  //b6[9:0]
    f4 = _mm256_srli_epi16(f4, 4);
    f4 = _mm256_and_si256(f4,mask);
    f4 = _mm256_mulhrs_epi16(f4,q);
    _mm256_store_si256(&r->vec[i*8+7],f4);  //b7[9:0]

  }
}

#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352 * 16))
static void poly_compress11(uint8_t r[352*16+2], const poly_16 * restrict a)
{
  // unsigned int i;
  // __m256i f0, f1, f2;
  // __m128i t0, t1;
  // const __m256i v = _mm256_load_si256(&qdata_16.vec[_16XV_16/16]);
  // const __m256i v8 = _mm256_slli_epi16(v,3);
  // const __m256i off = _mm256_set1_epi16(36);
  // const __m256i shift1 = _mm256_set1_epi16(1 << 13);
  // const __m256i mask = _mm256_set1_epi16(2047);
  // const __m256i shift2 = _mm256_set1_epi64x((2048LL << 48) + (1LL << 32) + (2048 << 16) + 1);
  // const __m256i sllvdidx = _mm256_set1_epi64x(10);
  // const __m256i srlvqidx = _mm256_set_epi64x(30,10,30,10);
  // const __m256i shufbidx = _mm256_set_epi8( 4, 3, 2, 1, 0, 0,-1,-1,-1,-1,10, 9, 8, 7, 6, 5,
  //                                          -1,-1,-1,-1,-1,10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);

  // for(i=0;i<KYBER_N/16;i++) {
  //   f0 = _mm256_load_si256(&a->vec[i]);
  //   f1 = _mm256_mullo_epi16(f0,v8);
  //   f2 = _mm256_add_epi16(f0,off);
  //   f0 = _mm256_slli_epi16(f0,3);
  //   f0 = _mm256_mulhi_epi16(f0,v);
  //   f2 = _mm256_sub_epi16(f1,f2);
  //   f1 = _mm256_andnot_si256(f1,f2);
  //   f1 = _mm256_srli_epi16(f1,15);
  //   f0 = _mm256_sub_epi16(f0,f1);
  //   f0 = _mm256_mulhrs_epi16(f0,shift1);
  //   f0 = _mm256_and_si256(f0,mask);
  //   f0 = _mm256_madd_epi16(f0,shift2);
  //   f0 = _mm256_sllv_epi32(f0,sllvdidx);
  //   f1 = _mm256_bsrli_epi128(f0,8);
  //   f0 = _mm256_srlv_epi64(f0,srlvqidx);
  //   f1 = _mm256_slli_epi64(f1,34);
  //   f0 = _mm256_add_epi64(f0,f1);
  //   f0 = _mm256_shuffle_epi8(f0,shufbidx);
  //   t0 = _mm256_castsi256_si128(f0);
  //   t1 = _mm256_extracti128_si256(f0,1);
  //   t0 = _mm_blendv_epi8(t0,t1,_mm256_castsi256_si128(shufbidx));
  //   _mm_storeu_si128((__m128i *)&r[22*i+ 0],t0);
  //   _mm_storel_epi64((__m128i *)&r[22*i+16],t1);
  // }

  unsigned int i;
  __m256i f0, f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, f15, f16, f17, g0;
  const __m256i v = _mm256_load_si256(&qdata_16.vec[_16XV_16/16]);
  const __m256i v8 = _mm256_slli_epi16(v,3);
  const __m256i off = _mm256_set1_epi16(36);
  const __m256i shift1 = _mm256_set1_epi16(1 << 13);
  const __m256i mask = _mm256_set1_epi16(2047);

  for(i = 0; i < KYBER_N/16; i++) {
    f0 = _mm256_load_si256(&a->vec[i*16]);
    f4 = _mm256_mullo_epi16(f0,v8);
    f5 = _mm256_add_epi16(f0,off);
    f0 = _mm256_slli_epi16(f0,3);
    f0 = _mm256_mulhi_epi16(f0,v);
    f5 = _mm256_sub_epi16(f4,f5);
    f4 = _mm256_andnot_si256(f4,f5);
    f4 = _mm256_srli_epi16(f4,15);
    f0 = _mm256_sub_epi16(f0,f4);
    f0 = _mm256_mulhrs_epi16(f0,shift1);
    f0 = _mm256_and_si256(f0,mask);

    f1 = _mm256_load_si256(&a->vec[i*16+1]);
    f4 = _mm256_mullo_epi16(f1,v8);
    f5 = _mm256_add_epi16(f1,off);
    f1 = _mm256_slli_epi16(f1,3);
    f1 = _mm256_mulhi_epi16(f1,v);
    f5 = _mm256_sub_epi16(f4,f5);
    f4 = _mm256_andnot_si256(f4,f5);
    f4 = _mm256_srli_epi16(f4,15);
    f1 = _mm256_sub_epi16(f1,f4);
    f1 = _mm256_mulhrs_epi16(f1,shift1);
    f1 = _mm256_and_si256(f1,mask);

    f2 = _mm256_load_si256(&a->vec[i*16+2]);
    f4 = _mm256_mullo_epi16(f2,v8);
    f5 = _mm256_add_epi16(f2,off);
    f2 = _mm256_slli_epi16(f2,3);
    f2 = _mm256_mulhi_epi16(f2,v);
    f5 = _mm256_sub_epi16(f4,f5);
    f4 = _mm256_andnot_si256(f4,f5);
    f4 = _mm256_srli_epi16(f4,15);
    f2 = _mm256_sub_epi16(f2,f4);
    f2 = _mm256_mulhrs_epi16(f2,shift1);
    f2 = _mm256_and_si256(f2,mask);

    f3 = _mm256_load_si256(&a->vec[i*16+3]);
    f4 = _mm256_mullo_epi16(f3,v8);
    f5 = _mm256_add_epi16(f3,off);
    f3 = _mm256_slli_epi16(f3,3);
    f3 = _mm256_mulhi_epi16(f3,v);
    f5 = _mm256_sub_epi16(f4,f5);
    f4 = _mm256_andnot_si256(f4,f5);
    f4 = _mm256_srli_epi16(f4,15);
    f3 = _mm256_sub_epi16(f3,f4);
    f3 = _mm256_mulhrs_epi16(f3,shift1);
    f3 = _mm256_and_si256(f3,mask);

    f6 = _mm256_load_si256(&a->vec[i*16+4]);
    f4 = _mm256_mullo_epi16(f6,v8);
    f5 = _mm256_add_epi16(f6,off);
    f6 = _mm256_slli_epi16(f6,3);
    f6 = _mm256_mulhi_epi16(f6,v);
    f5 = _mm256_sub_epi16(f4,f5);
    f4 = _mm256_andnot_si256(f4,f5);
    f4 = _mm256_srli_epi16(f4,15);
    f6 = _mm256_sub_epi16(f6,f4);
    f6 = _mm256_mulhrs_epi16(f6,shift1);
    f6 = _mm256_and_si256(f6,mask);

    f7 = _mm256_load_si256(&a->vec[i*16+5]);
    f4 = _mm256_mullo_epi16(f7,v8);
    f5 = _mm256_add_epi16(f7,off);
    f7 = _mm256_slli_epi16(f7,3);
    f7 = _mm256_mulhi_epi16(f7,v);
    f5 = _mm256_sub_epi16(f4,f5);
    f4 = _mm256_andnot_si256(f4,f5);
    f4 = _mm256_srli_epi16(f4,15);
    f7 = _mm256_sub_epi16(f7,f4);
    f7 = _mm256_mulhrs_epi16(f7,shift1);
    f7 = _mm256_and_si256(f7,mask);

    f8 = _mm256_load_si256(&a->vec[i*16+6]);
    f4 = _mm256_mullo_epi16(f8,v8);
    f5 = _mm256_add_epi16(f8,off);
    f8 = _mm256_slli_epi16(f8,3);
    f8 = _mm256_mulhi_epi16(f8,v);
    f5 = _mm256_sub_epi16(f4,f5);
    f4 = _mm256_andnot_si256(f4,f5);
    f4 = _mm256_srli_epi16(f4,15);
    f8 = _mm256_sub_epi16(f8,f4);
    f8 = _mm256_mulhrs_epi16(f8,shift1);
    f8 = _mm256_and_si256(f8,mask);

    f9 = _mm256_load_si256(&a->vec[i*16+7]);
    f4 = _mm256_mullo_epi16(f9,v8);
    f5 = _mm256_add_epi16(f9,off);
    f9 = _mm256_slli_epi16(f9,3);
    f9 = _mm256_mulhi_epi16(f9,v);
    f5 = _mm256_sub_epi16(f4,f5);
    f4 = _mm256_andnot_si256(f4,f5);
    f4 = _mm256_srli_epi16(f4,15);
    f9 = _mm256_sub_epi16(f9,f4);
    f9 = _mm256_mulhrs_epi16(f9,shift1);
    f9 = _mm256_and_si256(f9,mask);

    f10 = _mm256_load_si256(&a->vec[i*16+8]);
    f4 = _mm256_mullo_epi16(f10,v8);
    f5 = _mm256_add_epi16(f10,off);
    f10 = _mm256_slli_epi16(f10,3);
    f10 = _mm256_mulhi_epi16(f10,v);
    f5 = _mm256_sub_epi16(f4,f5);
    f4 = _mm256_andnot_si256(f4,f5);
    f4 = _mm256_srli_epi16(f4,15);
    f10 = _mm256_sub_epi16(f10,f4);
    f10 = _mm256_mulhrs_epi16(f10,shift1);
    f10 = _mm256_and_si256(f10,mask);

    f11 = _mm256_load_si256(&a->vec[i*16+9]);
    f4 = _mm256_mullo_epi16(f11,v8);
    f5 = _mm256_add_epi16(f11,off);
    f11 = _mm256_slli_epi16(f11,3);
    f11 = _mm256_mulhi_epi16(f11,v);
    f5 = _mm256_sub_epi16(f4,f5);
    f4 = _mm256_andnot_si256(f4,f5);
    f4 = _mm256_srli_epi16(f4,15);
    f11 = _mm256_sub_epi16(f11,f4);
    f11 = _mm256_mulhrs_epi16(f11,shift1);
    f11 = _mm256_and_si256(f11,mask);

    f12 = _mm256_load_si256(&a->vec[i*16+10]);
    f4 = _mm256_mullo_epi16(f12,v8);
    f5 = _mm256_add_epi16(f12,off);
    f12 = _mm256_slli_epi16(f12,3);
    f12 = _mm256_mulhi_epi16(f12,v);
    f5 = _mm256_sub_epi16(f4,f5);
    f4 = _mm256_andnot_si256(f4,f5);
    f4 = _mm256_srli_epi16(f4,15);
    f12 = _mm256_sub_epi16(f12,f4);
    f12 = _mm256_mulhrs_epi16(f12,shift1);
    f12 = _mm256_and_si256(f12,mask);

    f13 = _mm256_load_si256(&a->vec[i*16+11]);
    f4 = _mm256_mullo_epi16(f13,v8);
    f5 = _mm256_add_epi16(f13,off);
    f13 = _mm256_slli_epi16(f13,3);
    f13 = _mm256_mulhi_epi16(f13,v);
    f5 = _mm256_sub_epi16(f4,f5);
    f4 = _mm256_andnot_si256(f4,f5);
    f4 = _mm256_srli_epi16(f4,15);
    f13 = _mm256_sub_epi16(f13,f4);
    f13 = _mm256_mulhrs_epi16(f13,shift1);
    f13 = _mm256_and_si256(f13,mask);

    f14 = _mm256_load_si256(&a->vec[i*16+12]);
    f4 = _mm256_mullo_epi16(f14,v8);
    f5 = _mm256_add_epi16(f14,off);
    f14 = _mm256_slli_epi16(f14,3);
    f14 = _mm256_mulhi_epi16(f14,v);
    f5 = _mm256_sub_epi16(f4,f5);
    f4 = _mm256_andnot_si256(f4,f5);
    f4 = _mm256_srli_epi16(f4,15);
    f14 = _mm256_sub_epi16(f14,f4);
    f14 = _mm256_mulhrs_epi16(f14,shift1);
    f14 = _mm256_and_si256(f14,mask);

    f15 = _mm256_load_si256(&a->vec[i*16+13]);
    f4 = _mm256_mullo_epi16(f15,v8);
    f5 = _mm256_add_epi16(f15,off);
    f15 = _mm256_slli_epi16(f15,3);
    f15 = _mm256_mulhi_epi16(f15,v);
    f5 = _mm256_sub_epi16(f4,f5);
    f4 = _mm256_andnot_si256(f4,f5);
    f4 = _mm256_srli_epi16(f4,15);
    f15 = _mm256_sub_epi16(f15,f4);
    f15 = _mm256_mulhrs_epi16(f15,shift1);
    f15 = _mm256_and_si256(f15,mask);

    f16 = _mm256_load_si256(&a->vec[i*16+14]);
    f4 = _mm256_mullo_epi16(f16,v8);
    f5 = _mm256_add_epi16(f16,off);
    f16 = _mm256_slli_epi16(f16,3);
    f16 = _mm256_mulhi_epi16(f16,v);
    f5 = _mm256_sub_epi16(f4,f5);
    f4 = _mm256_andnot_si256(f4,f5);
    f4 = _mm256_srli_epi16(f4,15);
    f16 = _mm256_sub_epi16(f16,f4);
    f16 = _mm256_mulhrs_epi16(f16,shift1);
    f16 = _mm256_and_si256(f16,mask);

    f17 = _mm256_load_si256(&a->vec[i*16+15]);
    f4 = _mm256_mullo_epi16(f17,v8);
    f5 = _mm256_add_epi16(f17,off);
    f17 = _mm256_slli_epi16(f17,3);
    f17 = _mm256_mulhi_epi16(f17,v);
    f5 = _mm256_sub_epi16(f4,f5);
    f4 = _mm256_andnot_si256(f4,f5);
    f4 = _mm256_srli_epi16(f4,15);
    f17 = _mm256_sub_epi16(f17,f4);
    f17 = _mm256_mulhrs_epi16(f17,shift1);
    f17 = _mm256_and_si256(f17,mask);
    
    g0 = _mm256_slli_epi16(f1, 11);
    f0 = _mm256_add_epi16(f0, g0);   //f0[15:0] = f1[4:0] | f0
    f1 = _mm256_srli_epi16(f1, 5);
    g0 = _mm256_slli_epi16(f2, 6);
    f1 = _mm256_add_epi16(f1, g0);   //f1 = f2[9:0] | f1[10:5]
    f2 = _mm256_slli_epi16(f2, 10);
    g0 = _mm256_srli_epi16(f3, 1);
    f2 = _mm256_add_epi16(f2, g0);   //f2 = f3[10:0] | f2[10]
    g0 = _mm256_slli_epi16(f6, 12);
    f2 = _mm256_add_epi16(f2, g0);   //f2 = f6[3:0] | f3[10:0] | f2[10]
    f6 = _mm256_srli_epi16(f6, 4);
    g0 = _mm256_slli_epi16(f7, 7);
    f6 = _mm256_add_epi16(f6, g0);   //f6 = f7[8:0] | f6[10:4]
    f7 = _mm256_srli_epi16(f7, 9);
    g0 = _mm256_slli_epi16(f8, 2);
    f7 = _mm256_add_epi16(f7, g0);   //f7 = f8[10:0] | f7[10:9]
    g0 = _mm256_slli_epi16(f9, 13);
    f7 = _mm256_add_epi16(f7, g0);   //f7 = f9[2:0] | f8[10:0] | f7[10:9]
    f9 = _mm256_srli_epi16(f9, 2);
    g0 = _mm256_slli_epi16(f10, 8);
    f9 = _mm256_add_epi16(f9, g0);   //f9 = f10[7:0] | f9[10:3]
    f10 = _mm256_srli_epi16(f10, 8);
    g0 = _mm256_slli_epi16(f11, 3);
    f10 = _mm256_add_epi16(f10, f11);
    g0 = _mm256_slli_epi16(f12, 14);
    f10 = _mm256_add_epi16(f10, f12);//f10 = f12[1:0] | f11[10:0] | f10[10:8]
    f12 = _mm256_srli_epi16(f12, 2);
    g0 = _mm256_slli_epi16(f13, 9);
    f12 = _mm256_add_epi16(f12, f13);//f12 = f13[6:0] | f12[10:2]
    f13 = _mm256_srli_epi16(f13, 27);
    g0 = _mm256_slli_epi16(f14, 4);
    f13 = _mm256_add_epi16(f13, f14);
    g0 = _mm256_slli_epi16(f15, 15);
    f13 = _mm256_add_epi16(f13, f15);//f13 = f15[0] | f14[10:0] | f13[10:7]
    f15 = _mm256_srli_epi16(f15, 1);
    g0 = _mm256_slli_epi16(f16, 10);
    f15 = _mm256_add_epi16(f15, f16);//f15 = f16[5:0] | f15[10:1]
    f16 = _mm256_srli_epi16(f16, 6);
    g0 = _mm256_slli_epi16(f17, 5);
    f16 = _mm256_add_epi16(f16, f17);//f16 = f17[10:0] | f16[10:6]

    _mm256_storeu_si256((__m256i *)&r[i*352],f0);
    _mm256_storeu_si256((__m256i *)&r[i*352 + 32],f1);
    _mm256_storeu_si256((__m256i *)&r[i*352 + 64],f2);
    _mm256_storeu_si256((__m256i *)&r[i*352 + 96],f6);
    _mm256_storeu_si256((__m256i *)&r[i*352 + 128],f7);
    _mm256_storeu_si256((__m256i *)&r[i*352 + 160],f9);
    _mm256_storeu_si256((__m256i *)&r[i*352 + 192],f10);
    _mm256_storeu_si256((__m256i *)&r[i*352 + 224],f12);
    _mm256_storeu_si256((__m256i *)&r[i*352 + 256],f13);
    _mm256_storeu_si256((__m256i *)&r[i*352 + 288],f15); 
    _mm256_storeu_si256((__m256i *)&r[i*352 + 320],f16);   

  }
}

static void poly_decompress11(poly_16 * restrict r, const uint8_t a[352*16+10])
{
  // unsigned int i;
  // __m256i f;
  // const __m256i q = _mm256_load_si256(&qdata_16.vec[_16XQ_16/16]);
  // const __m256i shufbidx = _mm256_set_epi8(13,12,12,11,10, 9, 9, 8,
  //                                           8, 7, 6, 5, 5, 4, 4, 3,
  //                                          10, 9, 9, 8, 7, 6, 6, 5,
  //                                           5, 4, 3, 2, 2, 1, 1, 0);
  // const __m256i srlvdidx = _mm256_set_epi32(0,0,1,0,0,0,1,0);
  // const __m256i srlvqidx = _mm256_set_epi64x(2,0,2,0);
  // const __m256i shift = _mm256_set_epi16(4,32,1,8,32,1,4,32,4,32,1,8,32,1,4,32);
  // const __m256i mask = _mm256_set1_epi16(32752);

  // for(i=0;i<KYBER_N/16;i++) {
  //   f = _mm256_loadu_si256((__m256i *)&a[22*i]);
  //   f = _mm256_permute4x64_epi64(f,0x94);
  //   f = _mm256_shuffle_epi8(f,shufbidx);
  //   f = _mm256_srlv_epi32(f,srlvdidx);
  //   f = _mm256_srlv_epi64(f,srlvqidx);
  //   f = _mm256_mullo_epi16(f,shift);
  //   f = _mm256_srli_epi16(f,1);
  //   f = _mm256_and_si256(f,mask);
  //   f = _mm256_mulhrs_epi16(f,q);
  //   _mm256_store_si256(&r->vec[i],f);
  // }

  unsigned int i;
  __m256i f0, f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, g;
  const __m256i q = _mm256_load_si256(&qdata_16.vec[_16XQ_16/16]);
  const __m256i mask = _mm256_set1_epi16(32752);

  for(i=0;i<KYBER_N/16;i++) {
    f0 = _mm256_loadu_si256((__m256i *)&a[352*i]);
    f1 = _mm256_loadu_si256((__m256i *)&a[352*i + 32]);
    f2 = _mm256_loadu_si256((__m256i *)&a[352*i + 64]);
    f3 = _mm256_loadu_si256((__m256i *)&a[352*i + 96]);
    f4 = _mm256_loadu_si256((__m256i *)&a[352*i + 128]);
    f5 = _mm256_loadu_si256((__m256i *)&a[352*i + 160]);
    f6 = _mm256_loadu_si256((__m256i *)&a[352*i + 192]);
    f7 = _mm256_loadu_si256((__m256i *)&a[352*i + 224]);
    f8 = _mm256_loadu_si256((__m256i *)&a[352*i + 256]);
    f9 = _mm256_loadu_si256((__m256i *)&a[352*i + 288]);
    f10 = _mm256_loadu_si256((__m256i *)&a[352*i + 320]);

    g = _mm256_slli_epi16(f0,4);
    g = _mm256_and_si256(g,mask);
    g = _mm256_mulhrs_epi16(g,q);
    _mm256_store_si256(&r->vec[i*16],g);  //b0[10:0]
    f0 = _mm256_srli_epi16(f0, 7);
    g = _mm256_slli_epi16(f1, 9);
    g = _mm256_add_epi16(f0, g);
    g = _mm256_and_si256(g,mask);
    g = _mm256_mulhrs_epi16(g,q);
    _mm256_store_si256(&r->vec[i*16 + 1],g);  //b1[10:0]
    f1 = _mm256_srli_epi16(f1, 2);
    g =  _mm256_slli_epi16(f2, 14);
    g = _mm256_add_epi16(f1, g);
    g = _mm256_and_si256(g,mask);
    g = _mm256_mulhrs_epi16(g,q);
    _mm256_store_si256(&r->vec[i*16 + 2],g);  //b2[10:0]
    g = _mm256_slli_epi16(f2, 3); 
    g = _mm256_and_si256(g,mask);
    g = _mm256_mulhrs_epi16(g,q);
    _mm256_store_si256(&r->vec[i*16 + 3],g);  //b3[10:0]
    f2 = _mm256_srli_epi16(f2, 8); 
    g =  _mm256_slli_epi16(f3, 8); 
    g =  _mm256_add_epi16(f2, g); 
    g = _mm256_and_si256(g,mask);
    g = _mm256_mulhrs_epi16(g,q);
    _mm256_store_si256(&r->vec[i*16 + 4],g);  //b4[10:0]
    f3 = _mm256_srli_epi16(f3, 3);
    g =  _mm256_slli_epi16(f4, 13); 
    g = _mm256_add_epi16(f3, g); 
    g = _mm256_and_si256(g,mask);
    g = _mm256_mulhrs_epi16(g,q);
    _mm256_store_si256(&r->vec[i*16 + 5],g);  //b5[10:0]
    g = _mm256_slli_epi16(f4, 2);
    g = _mm256_and_si256(g,mask);
    g = _mm256_mulhrs_epi16(g,q);
    _mm256_store_si256(&r->vec[i*16 + 6],g);  //b6[10:0]
    f4 = _mm256_srli_epi16(f4, 9);
    g = _mm256_slli_epi16(f5, 7);
    g = _mm256_add_epi16(f4, g); 
    g = _mm256_and_si256(g,mask);
    g = _mm256_mulhrs_epi16(g,q);
    _mm256_store_si256(&r->vec[i*16 + 7],g);  //b7[10:0]
    f5 = _mm256_srli_epi16(f5, 4);
    g = _mm256_slli_epi16(f6, 12);
    g = _mm256_add_epi16(f5, g); 
    g = _mm256_and_si256(g,mask);
    g = _mm256_mulhrs_epi16(g,q);
    _mm256_store_si256(&r->vec[i*16 + 8],g);  //b8[10:0]
    g = _mm256_slli_epi16(f6, 1);
    g = _mm256_and_si256(g,mask);
    g = _mm256_mulhrs_epi16(g,q);
    _mm256_store_si256(&r->vec[i*16 + 9],g);  //b9[10:0]
    f6 = _mm256_srli_epi16(f6, 10);
    g = _mm256_slli_epi16(f7, 6);
    g = _mm256_add_epi16(f6, g); 
    g = _mm256_and_si256(g,mask);
    g = _mm256_mulhrs_epi16(g,q);
    _mm256_store_si256(&r->vec[i*16 + 10],g);  //b10[10:0]
    f7 = _mm256_srli_epi16(f7, 5);
    g = _mm256_slli_epi16(f8, 11);
    g = _mm256_add_epi16(f7, g); 
    g = _mm256_and_si256(g,mask);
    g = _mm256_mulhrs_epi16(g,q);
    _mm256_store_si256(&r->vec[i*16 + 11],g);  //b11[10:0]
    g = _mm256_and_si256(f8,mask);
    g = _mm256_mulhrs_epi16(g,q);
    _mm256_store_si256(&r->vec[i*16 + 12],g);  //b12[10:0]
    f8 = _mm256_srli_epi16(f8, 11);
    g = _mm256_slli_epi16(f9, 5);
    g = _mm256_add_epi16(f8, g);
    g = _mm256_and_si256(g,mask);
    g = _mm256_mulhrs_epi16(g,q);
    _mm256_store_si256(&r->vec[i*16 + 13],g);  //b13[10:0]
    f9 = _mm256_srli_epi16(f9, 6);
    g = _mm256_slli_epi16(f10, 10);
    g = _mm256_add_epi16(f9, g);
    g = _mm256_and_si256(g,mask);
    g = _mm256_mulhrs_epi16(g,q);
    _mm256_store_si256(&r->vec[i*16 + 14],g);  //b14[10:0]
    f10 = _mm256_srli_epi16(f10, 1);
    g = _mm256_and_si256(f10,mask);
    g = _mm256_mulhrs_epi16(g,q);
    _mm256_store_si256(&r->vec[i*16 + 15],g);  //b15[10:0]

  }

}

#endif


void polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES+2], const polyvec_16 *a)
{
  unsigned int i;

#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320 * 16))
  for(i=0;i<KYBER_K;i++)
    poly_compress10(&r[320*16*i],&a->vec[i]);
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352 * 16))
  for(i=0;i<KYBER_K;i++)
    poly_compress11(&r[352*i],&a->vec[i]);
#endif
}


void polyvec_decompress(polyvec_16 *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES])
{
  unsigned int i;

#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320 * 16))
  for(i=0;i<KYBER_K;i++)
    poly_decompress10(&r->vec[i],&a[320*16*i]);
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352 * 16))
  for(i=0;i<KYBER_K;i++)
    poly_decompress11(&r->vec[i],&a[352*i]);
#endif
}


void polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES*16], const polyvec_16 *a)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++){
    poly_tobytes(r+i*KYBER_POLYBYTES*16, &a->vec[i]);
  }
}


void polyvec_frombytes(polyvec_16 *r, const uint8_t a[KYBER_POLYVECBYTES*16])
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    poly_frombytes(&r->vec[i], a+i*KYBER_POLYBYTES*16);
}


void polyvec_ntt(polyvec_16 *r)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    poly_ntt(&r->vec[i]);
}


void polyvec_invntt_tomont(polyvec_16 *r)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    poly_invntt_tomont(&r->vec[i]);
}


void polyvec_basemul_acc_montgomery(poly_16 *r, const polyvec_16 *a, const polyvec_16 *b)
{
  unsigned int i;
  poly_16 tmp;

  poly_basemul_montgomery(r,&a->vec[0],&b->vec[0]);
  for(i=1;i<KYBER_K;i++) {
    poly_basemul_montgomery(&tmp,&a->vec[i],&b->vec[i]);
    poly_add(r,r,&tmp);
  }
}


void polyvec_reduce(polyvec_16 *r)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    poly_reduce(&r->vec[i]);
}


void polyvec_add(polyvec_16 *r, const polyvec_16 *a, const polyvec_16 *b)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
}
