#ifndef NTT_16_H
#define NTT_16_H

#include <stdint.h>
#include <immintrin.h>

#define ntt_avx_16 KYBER_NAMESPACE(ntt_avx_16)
void ntt_avx_16(__m256i *r, const __m256i *qdata_16);

#define basemul_avx_16 KYBER_NAMESPACE(basemul_avx_16)
void basemul_avx_16(__m256i *r,
                 const __m256i *a,
                 const __m256i *b,
                 const __m256i *qdata_16);

#define invntt_avx_16 KYBER_NAMESPACE(invntt_avx_16)
void invntt_avx_16(__m256i *r, const __m256i *qdata);

#define nttunpack_avx_16 KYBER_NAMESPACE(nttunpack_avx_16)
void nttunpack_avx_16(__m256i *r);


#define ntttobytes_avx_16 KYBER_NAMESPACE(ntttobytes_avx_16)
void ntttobytes_avx_16(uint8_t *r, const __m256i *a, const __m256i *qdata);
#define nttfrombytes_avx_16 KYBER_NAMESPACE(nttfrombytes_avx_16)
void nttfrombytes_avx_16(__m256i *r, const uint8_t *a, const __m256i *qdata);

#endif