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

  for(i=0;i<KYBER_N*16/16/8;i++) {
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

    // memcpy(&r[256*i],&f0,32);

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

    // memcpy(&r[256*i+32],&f1,32);

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

    // memcpy(&r[256*i+64],&f2,32);

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

    // memcpy(&r[256*i+96],&f3,32);

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

    // memcpy(&r[256*i+128],&f6,32);

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

    // memcpy(&r[256*i+160],&f7,32);

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

    // memcpy(&r[256*i+192],&f8,32);

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

    // memcpy(&r[256*i+224],&f9,32);
    
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

    _mm256_store_si256((__m256i *)&r[i*160],f0);
    _mm256_store_si256((__m256i *)&r[i*160 + 32],f1);
    _mm256_store_si256((__m256i *)&r[i*160 + 64],f3);
    _mm256_store_si256((__m256i *)&r[i*160 + 96],f6);
    _mm256_store_si256((__m256i *)&r[i*160 + 128],f8);

  }
}

static void poly_decompress10(poly_16 * restrict r, const uint8_t a[320*16])
{
  unsigned int i;
  __m256i f0, f1, f2, f3, f4, g;
  const __m256i q = _mm256_set1_epi16(KYBER_Q<<3);
  const __m256i mask = _mm256_set1_epi16(4092);

  for(i=0;i<KYBER_N*16/16/8;i++) {
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

#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))
static void poly_compress11(uint8_t r[352+2], const poly * restrict a)
{
  unsigned int i;
  __m256i f0, f1, f2;
  __m128i t0, t1;
  const __m256i v = _mm256_load_si256(&qdata.vec[_16XV/16]);
  const __m256i v8 = _mm256_slli_epi16(v,3);
  const __m256i off = _mm256_set1_epi16(36);
  const __m256i shift1 = _mm256_set1_epi16(1 << 13);
  const __m256i mask = _mm256_set1_epi16(2047);
  const __m256i shift2 = _mm256_set1_epi64x((2048LL << 48) + (1LL << 32) + (2048 << 16) + 1);
  const __m256i sllvdidx = _mm256_set1_epi64x(10);
  const __m256i srlvqidx = _mm256_set_epi64x(30,10,30,10);
  const __m256i shufbidx = _mm256_set_epi8( 4, 3, 2, 1, 0, 0,-1,-1,-1,-1,10, 9, 8, 7, 6, 5,
                                           -1,-1,-1,-1,-1,10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);

  for(i=0;i<KYBER_N/16;i++) {
    f0 = _mm256_load_si256(&a->vec[i]);
    f1 = _mm256_mullo_epi16(f0,v8);
    f2 = _mm256_add_epi16(f0,off);
    f0 = _mm256_slli_epi16(f0,3);
    f0 = _mm256_mulhi_epi16(f0,v);
    f2 = _mm256_sub_epi16(f1,f2);
    f1 = _mm256_andnot_si256(f1,f2);
    f1 = _mm256_srli_epi16(f1,15);
    f0 = _mm256_sub_epi16(f0,f1);
    f0 = _mm256_mulhrs_epi16(f0,shift1);
    f0 = _mm256_and_si256(f0,mask);
    f0 = _mm256_madd_epi16(f0,shift2);
    f0 = _mm256_sllv_epi32(f0,sllvdidx);
    f1 = _mm256_bsrli_epi128(f0,8);
    f0 = _mm256_srlv_epi64(f0,srlvqidx);
    f1 = _mm256_slli_epi64(f1,34);
    f0 = _mm256_add_epi64(f0,f1);
    f0 = _mm256_shuffle_epi8(f0,shufbidx);
    t0 = _mm256_castsi256_si128(f0);
    t1 = _mm256_extracti128_si256(f0,1);
    t0 = _mm_blendv_epi8(t0,t1,_mm256_castsi256_si128(shufbidx));
    _mm_storeu_si128((__m128i *)&r[22*i+ 0],t0);
    _mm_storel_epi64((__m128i *)&r[22*i+16],t1);
  }
}

static void poly_decompress11(poly * restrict r, const uint8_t a[352+10])
{
  unsigned int i;
  __m256i f;
  const __m256i q = _mm256_load_si256(&qdata.vec[_16XQ/16]);
  const __m256i shufbidx = _mm256_set_epi8(13,12,12,11,10, 9, 9, 8,
                                            8, 7, 6, 5, 5, 4, 4, 3,
                                           10, 9, 9, 8, 7, 6, 6, 5,
                                            5, 4, 3, 2, 2, 1, 1, 0);
  const __m256i srlvdidx = _mm256_set_epi32(0,0,1,0,0,0,1,0);
  const __m256i srlvqidx = _mm256_set_epi64x(2,0,2,0);
  const __m256i shift = _mm256_set_epi16(4,32,1,8,32,1,4,32,4,32,1,8,32,1,4,32);
  const __m256i mask = _mm256_set1_epi16(32752);

  for(i=0;i<KYBER_N/16;i++) {
    f = _mm256_loadu_si256((__m256i *)&a[22*i]);
    f = _mm256_permute4x64_epi64(f,0x94);
    f = _mm256_shuffle_epi8(f,shufbidx);
    f = _mm256_srlv_epi32(f,srlvdidx);
    f = _mm256_srlv_epi64(f,srlvqidx);
    f = _mm256_mullo_epi16(f,shift);
    f = _mm256_srli_epi16(f,1);
    f = _mm256_and_si256(f,mask);
    f = _mm256_mulhrs_epi16(f,q);
    _mm256_store_si256(&r->vec[i],f);
  }
}

#endif


void polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES+2], const polyvec_16 *a)
{
  unsigned int i;

#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320 * 16))
  for(i=0;i<KYBER_K;i++)
    poly_compress10(&r[320*16*i],&a->vec[i]);
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))
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
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))
  for(i=0;i<KYBER_K;i++)
    poly_decompress11(&r->vec[i],&a[352*i]);
#endif
}


void polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES*16], const polyvec_16 *a)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    poly_tobytes(r+i*KYBER_POLYBYTES*16, &a->vec[i]);
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
