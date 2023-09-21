#ifndef PARAMS_16_H
#define PARAMS_16_H

#ifndef KYBER_K
#define KYBER_K 3	/* Change this for different security strengths */
#endif

//#define KYBER_90S	/* Uncomment this if you want the 90S variant */

/* Don't change parameters below this line */
#if   (KYBER_K == 2)
#ifdef KYBER_90S
#define KYBER_NAMESPACE(s) pqcrystals_kyber512_90s_avx2_##s
#else
#define KYBER_NAMESPACE(s) pqcrystals_kyber512_avx2_##s
#endif
#elif (KYBER_K == 3)
#ifdef KYBER_90S
#define KYBER_NAMESPACE(s) pqcrystals_kyber768_90s_avx2_##s
#else
#define KYBER_NAMESPACE(s) pqcrystals_kyber768_avx2_##s
#endif
#elif (KYBER_K == 4)
#ifdef KYBER_90S
#define KYBER_NAMESPACE(s) pqcrystals_kyber1024_90s_avx2_##s
#else
#define KYBER_NAMESPACE(s) pqcrystals_kyber1024_avx2_##s
#endif
#else
#error "KYBER_K must be in {2,3,4}"
#endif

#define KYBER_N 256
#define KYBER_Q 3329

#define KYBER_SYMBYTES 32   /* size in bytes of hashes, and seeds */
#define KYBER_SSBYTES  32   /* size in bytes of shared key */

#define KYBER_POLYBYTES		384
#define KYBER_POLYVECBYTES	(KYBER_K * KYBER_POLYBYTES)  //3*384

#if KYBER_K == 2
#define KYBER_ETA1 3
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 3
#define KYBER_ETA1 2
#define KYBER_POLYCOMPRESSEDBYTES    128 * 16
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320 * 16)  //3*320*16
#elif KYBER_K == 4
#define KYBER_ETA1 2
#define KYBER_POLYCOMPRESSEDBYTES    160
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 352)
#endif

#define KYBER_ETA2 2

#define KYBER_INDCPA_MSGBYTES       (KYBER_SYMBYTES)  //32
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES*2)*16  //(3*384+32*2)*16  其实pk后面没有跟2个32B，只是publicseed需要间隔存放，在kem_keypair()中sk = sk||pk||publicseed||H(pk)||random，没有空格了
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES*16)  //3*384*16
#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)  //3*320*16 + 128*16

#define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES)  //(3*384+32*2)*16
/* 32 bytes of additional space to save H(pk) */
#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 16*KYBER_SYMBYTES)  //3*384*16 + (3*384+32*2)*16 +16*32
#define KYBER_CIPHERTEXTBYTES (KYBER_INDCPA_BYTES)  //3*320*16 + 128*16

#endif
