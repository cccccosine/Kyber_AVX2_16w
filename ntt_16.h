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

#define poly_formseqto16_AVX2 KYBER_NAMESPACE(poly_formseqto16_AVX2)
void poly_formseqto16_AVX2(__m256i *a, __m256i *t, __m256i *aseq, const __m256i *qdata_16);

#define keypair_formseqfrom16_AVX2 KYBER_NAMESPACE(keypair_formseqfrom16_AVX2)
void keypair_formseqfrom16_AVX2(uint8_t *k, uint8_t *kseq, uint8_t *t, const __m256i *qdata_16);
#define keypair_formseqto16_AVX2 KYBER_NAMESPACE(keypair_formseqto16_AVX2)
void keypair_formseqto16_AVX2(uint8_t *k, uint8_t *t, uint8_t *kseq, const __m256i *qdata_16);

#define cipher_formseqfrom16_AVX2 KYBER_NAMESPACE(cipher_formseqfrom16_AVX2)
void cipher_formseqfrom16_AVX2(uint8_t *c, uint8_t *cseq, uint8_t *t,  const __m256i *qdata_16);
#define cipher_formseqto16_AVX2 KYBER_NAMESPACE(cipher_formseqto16_AVX2)
void cipher_formseqto16_AVX2(uint8_t *c, uint8_t *t, uint8_t *cseq,  const __m256i *qdata_16);

#endif