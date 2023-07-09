#include <stddef.h>
#include <stdint.h>
#include <immintrin.h>
#include <string.h>
#include <malloc.h>
#include "align.h"
#include "params.h"
#include "indcpa_16.h"
#include "polyvec_16.h"
#include "poly_16.h"
#include "ntt_16.h"
#include "cbd.h"
#include "rejsample.h"
#include "symmetric.h"
#include "randombytes.h"


static void pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES],
                    polyvec_16 *pk,
                    const uint8_t seed[KYBER_SYMBYTES])
{
  polyvec_tobytes(r, pk);
  memcpy(r+KYBER_POLYVECBYTES*16, seed, KYBER_SYMBYTES);
}


static void unpack_pk(polyvec_16 *pk,
                      uint8_t seed[KYBER_SYMBYTES],
                      const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES])
{
  polyvec_frombytes(pk, packedpk);
  memcpy(seed, packedpk+KYBER_POLYVECBYTES*16, KYBER_SYMBYTES);
}


static void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvec_16 *sk)
{
  polyvec_tobytes(r, sk);
}


static void unpack_sk(polyvec *sk, const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES])
{
  polyvec_frombytes(sk, packedsk);
}


static void pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES], polyvec_16 *b, poly_16 *v)
{
  polyvec_compress(r, b);
  poly_compress(r+KYBER_POLYVECCOMPRESSEDBYTES, v);
}


static void unpack_ciphertext(polyvec_16 *b, poly_16 *v, const uint8_t c[KYBER_INDCPA_BYTES])
{
  polyvec_decompress(b, c);
  poly_decompress(v, c+KYBER_POLYVECCOMPRESSEDBYTES);
}


static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
  unsigned int ctr, pos;
  uint16_t val0, val1;

  ctr = pos = 0;
  while(ctr < len && pos <= buflen - 3) {  // buflen is always at least 3
    val0 = ((buf[pos+0] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
    val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
    pos += 3;

    if(val0 < KYBER_Q)
      r[ctr++] = val0;
    if(ctr < len && val1 < KYBER_Q)
      r[ctr++] = val1;
  }

  return ctr;
}

#define gen_a(A,B)  gen_matrix(A,B,0)
#define gen_at(A,B) gen_matrix(A,B,1)


#ifdef KYBER_90S
void gen_matrix(polyvec *a, const uint8_t seed[32], int transposed)
{
  unsigned int ctr, i, j, k;
  unsigned int buflen, off;
  uint64_t nonce = 0;
  ALIGNED_UINT8(REJ_UNIFORM_AVX_NBLOCKS*AES256CTR_BLOCKBYTES) buf;
  aes256ctr_ctx state;

  aes256ctr_init(&state, seed, 0);

  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_K;j++) {
      if(transposed)
        nonce = (j << 8) | i;
      else
        nonce = (i << 8) | j;

      state.n = _mm_loadl_epi64((__m128i *)&nonce);
      aes256ctr_squeezeblocks(buf.coeffs, REJ_UNIFORM_AVX_NBLOCKS, &state);
      buflen = REJ_UNIFORM_AVX_NBLOCKS*AES256CTR_BLOCKBYTES;
      ctr = rej_uniform_avx(a[i].vec[j].coeffs, buf.coeffs);

      while(ctr < KYBER_N) {
        off = buflen % 3;
        for(k = 0; k < off; k++)
          buf.coeffs[k] = buf.coeffs[buflen - off + k];
        aes256ctr_squeezeblocks(buf.coeffs + off, 1, &state);
        buflen = off + AES256CTR_BLOCKBYTES;
        ctr += rej_uniform(a[i].vec[j].coeffs + ctr, KYBER_N - ctr, buf.coeffs, buflen);
      }

      poly_nttunpack(&a[i].vec[j]);
    }
  }
}
#else
#if KYBER_K == 2
void gen_matrix(polyvec *a, const uint8_t seed[32], int transposed)
{
  unsigned int ctr0, ctr1, ctr2, ctr3;
  ALIGNED_UINT8(REJ_UNIFORM_AVX_NBLOCKS*SHAKE128_RATE) buf[4];
  __m256i f;
  keccakx4_state state;

  f = _mm256_loadu_si256((__m256i *)seed);
  _mm256_store_si256(buf[0].vec, f);
  _mm256_store_si256(buf[1].vec, f);
  _mm256_store_si256(buf[2].vec, f);
  _mm256_store_si256(buf[3].vec, f);

  if(transposed) {
    buf[0].coeffs[32] = 0;
    buf[0].coeffs[33] = 0;
    buf[1].coeffs[32] = 0;
    buf[1].coeffs[33] = 1;
    buf[2].coeffs[32] = 1;
    buf[2].coeffs[33] = 0;
    buf[3].coeffs[32] = 1;
    buf[3].coeffs[33] = 1;
  }
  else {
    buf[0].coeffs[32] = 0;
    buf[0].coeffs[33] = 0;
    buf[1].coeffs[32] = 1;
    buf[1].coeffs[33] = 0;
    buf[2].coeffs[32] = 0;
    buf[2].coeffs[33] = 1;
    buf[3].coeffs[32] = 1;
    buf[3].coeffs[33] = 1;
  }

  shake128x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 34);
  shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, REJ_UNIFORM_AVX_NBLOCKS, &state);

  ctr0 = rej_uniform_avx(a[0].vec[0].coeffs, buf[0].coeffs);
  ctr1 = rej_uniform_avx(a[0].vec[1].coeffs, buf[1].coeffs);
  ctr2 = rej_uniform_avx(a[1].vec[0].coeffs, buf[2].coeffs);
  ctr3 = rej_uniform_avx(a[1].vec[1].coeffs, buf[3].coeffs);

  while(ctr0 < KYBER_N || ctr1 < KYBER_N || ctr2 < KYBER_N || ctr3 < KYBER_N) {
    shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 1, &state);

    ctr0 += rej_uniform(a[0].vec[0].coeffs + ctr0, KYBER_N - ctr0, buf[0].coeffs, SHAKE128_RATE);
    ctr1 += rej_uniform(a[0].vec[1].coeffs + ctr1, KYBER_N - ctr1, buf[1].coeffs, SHAKE128_RATE);
    ctr2 += rej_uniform(a[1].vec[0].coeffs + ctr2, KYBER_N - ctr2, buf[2].coeffs, SHAKE128_RATE);
    ctr3 += rej_uniform(a[1].vec[1].coeffs + ctr3, KYBER_N - ctr3, buf[3].coeffs, SHAKE128_RATE);
  }

  poly_nttunpack(&a[0].vec[0]);
  poly_nttunpack(&a[0].vec[1]);
  poly_nttunpack(&a[1].vec[0]);
  poly_nttunpack(&a[1].vec[1]);
}
#elif KYBER_K == 3
void gen_matrix(polyvec_16 *a, const uint8_t seed[32], int transposed)
{
  unsigned int ctr0, ctr1, ctr2, ctr3;
  ALIGNED_UINT8(REJ_UNIFORM_AVX_NBLOCKS*16*SHAKE128_RATE) buf[4];   //3*16*168
  __m256i f;
  keccakx4_state state;
  keccak_state state1x;

  f = _mm256_loadu_si256((__m256i *)seed); 
  _mm256_store_si256(buf[0].vec, f);
  _mm256_store_si256(buf[1].vec, f);
  _mm256_store_si256(buf[2].vec, f);
  _mm256_store_si256(buf[3].vec, f);


  if(transposed) {
    buf[0].coeffs[32] = 0;
    buf[0].coeffs[33] = 0;
    buf[1].coeffs[32] = 0;
    buf[1].coeffs[33] = 1;
    buf[2].coeffs[32] = 0;
    buf[2].coeffs[33] = 2;
    buf[3].coeffs[32] = 1;
    buf[3].coeffs[33] = 0;
  }
  else {
    buf[0].coeffs[32] = 0;
    buf[0].coeffs[33] = 0;
    buf[1].coeffs[32] = 1;
    buf[1].coeffs[33] = 0;
    buf[2].coeffs[32] = 2;
    buf[2].coeffs[33] = 0;
    buf[3].coeffs[32] = 0;
    buf[3].coeffs[33] = 1;
  }

  shake128x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 34);
  shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, REJ_UNIFORM_AVX_NBLOCKS*16, &state);

  ctr0 = rej_uniform_avx(a[0].vec[0].coeffs, buf[0].coeffs);  //对rej的16w修改不确定
  ctr1 = rej_uniform_avx(a[0].vec[1].coeffs, buf[1].coeffs);
  ctr2 = rej_uniform_avx(a[0].vec[2].coeffs, buf[2].coeffs);
  ctr3 = rej_uniform_avx(a[1].vec[0].coeffs, buf[3].coeffs);

  while(ctr0 < KYBER_N*16 || ctr1 < KYBER_N*16 || ctr2 < KYBER_N*16 || ctr3 < KYBER_N*16) {
    shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 16, &state);  

    ctr0 += rej_uniform(a[0].vec[0].coeffs + ctr0, KYBER_N*16 - ctr0, buf[0].coeffs, SHAKE128_RATE);
    ctr1 += rej_uniform(a[0].vec[1].coeffs + ctr1, KYBER_N*16 - ctr1, buf[1].coeffs, SHAKE128_RATE);
    ctr2 += rej_uniform(a[0].vec[2].coeffs + ctr2, KYBER_N*16 - ctr2, buf[2].coeffs, SHAKE128_RATE);
    ctr3 += rej_uniform(a[1].vec[0].coeffs + ctr3, KYBER_N*16 - ctr3, buf[3].coeffs, SHAKE128_RATE);
  }

  // poly_nttunpack(&a[0].vec[0]);
  // poly_nttunpack(&a[0].vec[1]);
  // poly_nttunpack(&a[0].vec[2]);
  // poly_nttunpack(&a[1].vec[0]);

  f = _mm256_loadu_si256((__m256i *)seed);
  _mm256_store_si256(buf[0].vec, f);
  _mm256_store_si256(buf[1].vec, f);
  _mm256_store_si256(buf[2].vec, f);
  _mm256_store_si256(buf[3].vec, f);

  if(transposed) {
    buf[0].coeffs[32] = 1;
    buf[0].coeffs[33] = 1;
    buf[1].coeffs[32] = 1;
    buf[1].coeffs[33] = 2;
    buf[2].coeffs[32] = 2;
    buf[2].coeffs[33] = 0;
    buf[3].coeffs[32] = 2;
    buf[3].coeffs[33] = 1;
  }
  else {
    buf[0].coeffs[32] = 1;
    buf[0].coeffs[33] = 1;
    buf[1].coeffs[32] = 2;
    buf[1].coeffs[33] = 1;
    buf[2].coeffs[32] = 0;
    buf[2].coeffs[33] = 2;
    buf[3].coeffs[32] = 1;
    buf[3].coeffs[33] = 2;
  }

  shake128x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 34);
  shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, REJ_UNIFORM_AVX_NBLOCKS*16, &state);

  ctr0 = rej_uniform_avx(a[1].vec[1].coeffs, buf[0].coeffs);
  ctr1 = rej_uniform_avx(a[1].vec[2].coeffs, buf[1].coeffs);
  ctr2 = rej_uniform_avx(a[2].vec[0].coeffs, buf[2].coeffs);
  ctr3 = rej_uniform_avx(a[2].vec[1].coeffs, buf[3].coeffs);

  while(ctr0 < KYBER_N*16 || ctr1 < KYBER_N*16 || ctr2 < KYBER_N*16 || ctr3 < KYBER_N*16) {
    shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 16, &state);

    ctr0 += rej_uniform(a[1].vec[1].coeffs + ctr0, KYBER_N*16 - ctr0, buf[0].coeffs, SHAKE128_RATE);
    ctr1 += rej_uniform(a[1].vec[2].coeffs + ctr1, KYBER_N*16 - ctr1, buf[1].coeffs, SHAKE128_RATE);
    ctr2 += rej_uniform(a[2].vec[0].coeffs + ctr2, KYBER_N*16 - ctr2, buf[2].coeffs, SHAKE128_RATE);
    ctr3 += rej_uniform(a[2].vec[1].coeffs + ctr3, KYBER_N*16 - ctr3, buf[3].coeffs, SHAKE128_RATE);
  }

  // poly_nttunpack(&a[1].vec[1]);
  // poly_nttunpack(&a[1].vec[2]);
  // poly_nttunpack(&a[2].vec[0]);
  // poly_nttunpack(&a[2].vec[1]);

  f = _mm256_loadu_si256((__m256i *)seed);
  _mm256_store_si256(buf[0].vec, f);
  buf[0].coeffs[32] = 2;
  buf[0].coeffs[33] = 2;
  shake128_absorb_once(&state1x, buf[0].coeffs, 34);
  shake128_squeezeblocks(buf[0].coeffs, REJ_UNIFORM_AVX_NBLOCKS*16, &state1x);
  ctr0 = rej_uniform_avx(a[2].vec[2].coeffs, buf[0].coeffs);
  while(ctr0 < KYBER_N*16) {
    shake128_squeezeblocks(buf[0].coeffs, 16, &state1x);
    ctr0 += rej_uniform(a[2].vec[2].coeffs + ctr0, KYBER_N*16 - ctr0, buf[0].coeffs, SHAKE128_RATE);
  }

  // poly_nttunpack(&a[2].vec[2]);
}
#elif KYBER_K == 4
void gen_matrix(polyvec *a, const uint8_t seed[32], int transposed)
{
  unsigned int i, ctr0, ctr1, ctr2, ctr3;
  ALIGNED_UINT8(REJ_UNIFORM_AVX_NBLOCKS*SHAKE128_RATE) buf[4];
  __m256i f;
  keccakx4_state state;

  for(i=0;i<4;i++) {
    f = _mm256_loadu_si256((__m256i *)seed);
    _mm256_store_si256(buf[0].vec, f);
    _mm256_store_si256(buf[1].vec, f);
    _mm256_store_si256(buf[2].vec, f);
    _mm256_store_si256(buf[3].vec, f);

    if(transposed) {
      buf[0].coeffs[32] = i;
      buf[0].coeffs[33] = 0;
      buf[1].coeffs[32] = i;
      buf[1].coeffs[33] = 1;
      buf[2].coeffs[32] = i;
      buf[2].coeffs[33] = 2;
      buf[3].coeffs[32] = i;
      buf[3].coeffs[33] = 3;
    }
    else {
      buf[0].coeffs[32] = 0;
      buf[0].coeffs[33] = i;
      buf[1].coeffs[32] = 1;
      buf[1].coeffs[33] = i;
      buf[2].coeffs[32] = 2;
      buf[2].coeffs[33] = i;
      buf[3].coeffs[32] = 3;
      buf[3].coeffs[33] = i;
    }

    shake128x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 34);
    shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, REJ_UNIFORM_AVX_NBLOCKS, &state);

    ctr0 = rej_uniform_avx(a[i].vec[0].coeffs, buf[0].coeffs);
    ctr1 = rej_uniform_avx(a[i].vec[1].coeffs, buf[1].coeffs);
    ctr2 = rej_uniform_avx(a[i].vec[2].coeffs, buf[2].coeffs);
    ctr3 = rej_uniform_avx(a[i].vec[3].coeffs, buf[3].coeffs);

    while(ctr0 < KYBER_N || ctr1 < KYBER_N || ctr2 < KYBER_N || ctr3 < KYBER_N) {
      shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 1, &state);

      ctr0 += rej_uniform(a[i].vec[0].coeffs + ctr0, KYBER_N - ctr0, buf[0].coeffs, SHAKE128_RATE);
      ctr1 += rej_uniform(a[i].vec[1].coeffs + ctr1, KYBER_N - ctr1, buf[1].coeffs, SHAKE128_RATE);
      ctr2 += rej_uniform(a[i].vec[2].coeffs + ctr2, KYBER_N - ctr2, buf[2].coeffs, SHAKE128_RATE);
      ctr3 += rej_uniform(a[i].vec[3].coeffs + ctr3, KYBER_N - ctr3, buf[3].coeffs, SHAKE128_RATE);
    }

    poly_nttunpack(&a[i].vec[0]);
    poly_nttunpack(&a[i].vec[1]);
    poly_nttunpack(&a[i].vec[2]);
    poly_nttunpack(&a[i].vec[3]);
  }
}
#endif
#endif


void indcpa_keypair(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],     
                    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES])
{
  unsigned int i, j, k, p;
  uint8_t buf[2*KYBER_SYMBYTES];
  // uint8_t buf[2*KYBER_SYMBYTES] = {17};
  const uint8_t *publicseed = buf;
  const uint8_t *noiseseed = buf + KYBER_SYMBYTES;
  polyvec_16 a[KYBER_K], skpv, e, pkpv;

  randombytes(buf, KYBER_SYMBYTES);
  hash_g(buf, buf, KYBER_SYMBYTES);

  gen_a(a, publicseed);

  // for (i = 0; i < KYBER_K; i++) {
  //   for (j = 0; j < KYBER_K; j++) {
  //     for(k = 0; k < KYBER_N; k++){
  //       for(p = 0; p < 16; p++) {
  //         a[i].vec[j].coeffs[k*16+p] = 1;
  //       }
  //     }
  //   }
  // }

#ifdef KYBER_90S  //not changed
#define NOISE_NBLOCKS ((KYBER_ETA1*KYBER_N/4)/AES256CTR_BLOCKBYTES) /* Assumes divisibility */
  uint64_t nonce = 0;
  ALIGNED_UINT8(NOISE_NBLOCKS*AES256CTR_BLOCKBYTES+32) coins; // +32 bytes as required by poly_cbd_eta1
  aes256ctr_ctx state;
  aes256ctr_init(&state, noiseseed, nonce++);
  for(i=0;i<KYBER_K;i++) {
    aes256ctr_squeezeblocks(coins.coeffs, NOISE_NBLOCKS, &state);
    state.n = _mm_loadl_epi64((__m128i *)&nonce);
    nonce += 1;
    poly_cbd_eta1(&skpv.vec[i], coins.vec);
  }
  for(i=0;i<KYBER_K;i++) {
    aes256ctr_squeezeblocks(coins.coeffs, NOISE_NBLOCKS, &state);
    state.n = _mm_loadl_epi64((__m128i *)&nonce);
    nonce += 1;
    poly_cbd_eta1(&e.vec[i], coins.vec);
  }
#else
#if KYBER_K == 2    //not changed
  poly_getnoise_eta1_4x(skpv.vec+0, skpv.vec+1, e.vec+0, e.vec+1, noiseseed, 0, 1, 2, 3);
#elif KYBER_K == 3 
  // for (j = 0; j < KYBER_K; j++) {
  //   for(k = 0; k < 256; k++) {
  //     for(p = 0; p < 16; p++) {
  //       skpv.vec[j].coeffs[k*16+p] = 19;
  //       e.vec[j].coeffs[k*16+p] = 19;
  //     }
  //   }
  // }
  poly_getnoise_eta1_4x(skpv.vec+0, skpv.vec+1, skpv.vec+2, e.vec+0, noiseseed, 0, 1, 2, 3);
  poly_getnoise_eta1_4x(e.vec+1, e.vec+2, pkpv.vec+0, pkpv.vec+1, noiseseed, 4, 5, 6, 7);
#elif KYBER_K == 4    //not changed
  poly_getnoise_eta1_4x(skpv.vec+0, skpv.vec+1, skpv.vec+2, skpv.vec+3, noiseseed,  0, 1, 2, 3);
  poly_getnoise_eta1_4x(e.vec+0, e.vec+1, e.vec+2, e.vec+3, noiseseed, 4, 5, 6, 7);
#endif
#endif

  polyvec_ntt(&skpv);
  polyvec_reduce(&skpv);
  polyvec_ntt(&e);

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++) {
    polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
    poly_tomont(&pkpv.vec[i]);
  }

  polyvec_add(&pkpv, &pkpv, &e);
  polyvec_reduce(&pkpv);

  pack_sk(sk, &skpv);
  pack_pk(pk, &pkpv, publicseed);

}


void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES*16],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES]
                // int16_t pkpvprint[KYBER_K*KYBER_N*16],
                // int16_t vprint[KYBER_N*16]
                )
{
  unsigned int i, j, l, p;
  uint8_t seed[KYBER_SYMBYTES];
  polyvec_16 sp, pkpv, ep, at[KYBER_K], b;
  poly_16 v, k, epp;

  // uint8_t *pkseq = (uint8_t *)malloc(KYBER_INDCPA_PUBLICKEYBYTES);

  // for(int i = 0; i < 3*192; i++) {
  //   for(int j = 0; j < 16; j++) {
  //     pkseq[i*32+j*2] = pk[j*3*384+i*2];
  //     pkseq[i*32+j*2+1] = pk[j*3*384+1+i*2];
  //   }
  // }

  // for(int i = 0; i < 3*384*16; i++) {
  //   pk[i] = pkseq[i];
  // }
  // free(pkseq);

  unpack_pk(&pkpv, seed, pk);
  poly_frommsg_16(&k, m);

  // for (i = 0; i < KYBER_K; i++) {
  //   for (j = 0; j < KYBER_K; j++) {
  //     for(p = 0; p < KYBER_N; p++) {
  //       for(l = 0; l < 16; l++) {
  //         at[i].vec[j].coeffs[p*16+l] = 1;
  //       }
  //     }
  //   }
  // }

  gen_at(at, seed);

#ifdef KYBER_90S
#define NOISE_NBLOCKS ((KYBER_ETA1*KYBER_N/4)/AES256CTR_BLOCKBYTES) /* Assumes divisibility */
#define CIPHERTEXTNOISE_NBLOCKS ((KYBER_ETA2*KYBER_N/4)/AES256CTR_BLOCKBYTES) /* Assumes divisibility */
  uint64_t nonce = 0;
  ALIGNED_UINT8(NOISE_NBLOCKS*AES256CTR_BLOCKBYTES+32) buf; /* +32 bytes as required by poly_cbd_eta1 */
  aes256ctr_ctx state;
  aes256ctr_init(&state, coins, nonce++);
  for(i=0;i<KYBER_K;i++) {
    aes256ctr_squeezeblocks(buf.coeffs, NOISE_NBLOCKS, &state);
    state.n = _mm_loadl_epi64((__m128i *)&nonce);
    nonce += 1;
    poly_cbd_eta1(&sp.vec[i], buf.vec);
  }
  for(i=0;i<KYBER_K;i++) {
    aes256ctr_squeezeblocks(buf.coeffs, CIPHERTEXTNOISE_NBLOCKS, &state);
    state.n = _mm_loadl_epi64((__m128i *)&nonce);
    nonce += 1;
    poly_cbd_eta2(&ep.vec[i], buf.vec);
  }
  aes256ctr_squeezeblocks(buf.coeffs, CIPHERTEXTNOISE_NBLOCKS, &state);
  poly_cbd_eta2(&epp, buf.vec);
#else
#if KYBER_K == 2
  poly_getnoise_eta1122_4x(sp.vec+0, sp.vec+1, ep.vec+0, ep.vec+1, coins, 0, 1, 2, 3);
  poly_getnoise_eta2(&epp, coins, 4);
#elif KYBER_K == 3
  // for (j = 0; j < KYBER_K; j++) {
  //   for(l = 0; l < KYBER_N; l++) {
  //     for(p = 0; p < 16; p++) {
  //       sp.vec[j].coeffs[l*16+p] = 19;
  //       ep.vec[j].coeffs[l*16+p] = 19;
  //     }
  //   }
  // }
  poly_getnoise_eta1_4x(sp.vec+0, sp.vec+1, sp.vec+2, ep.vec+0, coins, 0, 1, 2 ,3);
  poly_getnoise_eta1_4x(ep.vec+1, ep.vec+2, &epp, b.vec+0, coins,  4, 5, 6, 7);
#elif KYBER_K == 4
  poly_getnoise_eta1_4x(sp.vec+0, sp.vec+1, sp.vec+2, sp.vec+3, coins, 0, 1, 2, 3);
  poly_getnoise_eta1_4x(ep.vec+0, ep.vec+1, ep.vec+2, ep.vec+3, coins, 4, 5, 6, 7);
  poly_getnoise_eta2(&epp, coins, 8);
#endif
#endif

  polyvec_ntt(&sp);

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++)
    polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);
  polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);

  polyvec_invntt_tomont(&b);
  poly_invntt_tomont(&v);

  polyvec_add(&b, &b, &ep);
  poly_add(&v, &v, &epp);
  poly_add(&v, &v, &k);
  polyvec_reduce(&b);
  poly_reduce(&v);

  // for(i = 0; i < 3; i++) {
    // for(j = 0; j < 256; j++) {
    //   for(int k = 0; k < 16; k++) {
    //     // b.vec[i].coeffs[j*16+k] = 1024;
    //     vprint[j*16+k] = v.coeffs[j*16+k];
    //   }
    // }
  // }

  pack_ciphertext(c, &b, &v);

  // for(i = 0; i < KYBER_K; i++) {
  //   for(j = 0; j < KYBER_N*16; j++) {
  //     // skpvprint[i*KYBER_N*16+j] = skpv.vec[i].coeffs[j];
  //     // pkpvprint[i*KYBER_N*16+j] = pkpv.vec[i].coeffs[j];
  //     // pkpvprint[i*KYBER_N*16+j] = e.vec[i].coeffs[j];
  //     // pkpvprint[i*KYBER_N*16+j] = a[1].vec[i].coeffs[j];
  //     pkpvprint[i*KYBER_N*16+j] = b.vec[i].coeffs[j];
  //     // pkpvprint[i*KYBER_N*16+j] = sp.vec[i].coeffs[j];
  //   }
  // }
  // for(i = 0; i < KYBER_N*16; i++) {
  //   vprint[i] = v.coeffs[i];
  // }
}


void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES*16],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]
                // int16_t bprint[KYBER_K*KYBER_N*16],
                // int16_t vprint[KYBER_N*16]
                )
{
  polyvec_16 b, skpv;
  poly_16 v, mp;

  unpack_ciphertext(&b, &v, c);
  // for(int i = 0; i < KYBER_K; i++) {
  //   for(int j = 0; j < KYBER_N*16; j++) {
  //    bprint[i*KYBER_N*16+j] = b.vec[i].coeffs[j];
  //   }
  // }
  // for(int j = 0; j < KYBER_N*16; j++) {
  //    vprint[j] = v.coeffs[j];
  // }

  // uint8_t *skseq = (uint8_t *)malloc(KYBER_INDCPA_SECRETKEYBYTES);

  // for(int i = 0; i < 3*192; i++) {
  //   for(int j = 0; j < 16; j++) {
  //     skseq[i*32+j*2] = sk[j*3*384+i*2];
  //     skseq[i*32+j*2+1] = sk[j*3*384+1+i*2];
  //   }
  // }

  // for(int i = 0; i < 3*384*16; i++) {
  //   sk[i] = skseq[i];
  // }
  // free(skseq);

  unpack_sk(&skpv, sk);

  polyvec_ntt(&b);
  polyvec_basemul_acc_montgomery(&mp, &skpv, &b);
  poly_invntt_tomont(&mp);

  poly_sub(&mp, &v, &mp);
  poly_reduce(&mp);

  // for(int j = 0; j < KYBER_N*16; j++) {
  //    vprint[j] = mp.coeffs[j];
  // }

  poly_tomsg_16(m, &mp);
}
