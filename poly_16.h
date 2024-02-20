#ifndef POLY_16_H
#define POLY_16_H

#include <stdint.h>
#include "align.h"
#include "params.h"

typedef ALIGNED_INT16(KYBER_N) poly;
typedef ALIGNED_INT16(KYBER_N*16) poly_16;

#define poly_compress KYBER_NAMESPACE(poly_compress)
void poly_compress(uint8_t r[KYBER_POLYCOMPRESSEDBYTES], const poly_16 *a);
#define poly_decompress KYBER_NAMESPACE(poly_decompress)
void poly_decompress(poly_16 *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES]);

#define poly_tobytes KYBER_NAMESPACE(poly_tobytes)
void poly_tobytes(uint8_t r[KYBER_POLYBYTES*16], const poly_16 *a);
#define poly_frombytes KYBER_NAMESPACE(poly_frombytes)
void poly_frombytes(poly_16 *r, const uint8_t a[KYBER_POLYBYTES*16]);

#define poly_frommsg_16 KYBER_NAMESPACE(poly_frommsg_16)
void poly_frommsg_16(poly_16 *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES*16]);
#define poly_tomsg_16 KYBER_NAMESPACE(poly_tomsg_16)
void poly_tomsg_16(uint8_t msg[KYBER_INDCPA_MSGBYTES*16], const poly_16 *r);

#define poly_getnoise_eta1 KYBER_NAMESPACE(poly_getnoise_eta1)
void poly_getnoise_eta1(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);

#define poly_getnoise_eta2 KYBER_NAMESPACE(poly_getnoise_eta2)
void poly_getnoise_eta2(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);

#ifndef KYBER_90S
#define poly_getnoise_eta1_4x KYBER_NAMESPACE(poly_getnoise_eta1_4x)
void poly_getnoise_eta1_4x(poly_16 *r0,
                           poly_16 *r1,
                           poly_16 *r2,
                           poly_16 *r3,
                           const uint8_t seed[32],
                           uint8_t nonce0,
                           uint8_t nonce1,
                           uint8_t nonce2,
                           uint8_t nonce3);

#define poly_getnoise_eta2_4x KYBER_NAMESPACE(poly_getnoise_eta2_4x)
void poly_getnoise_eta2_4x(poly_16 *r, const uint8_t seed[KYBER_SYMBYTES*(16*2-1)], uint8_t nonce);

#if KYBER_K == 2
#define poly_getnoise_eta1122_4x KYBER_NAMESPACE(poly_getnoise_eta1122_4x)
void poly_getnoise_eta1122_4x(poly_16 *r0,
                              poly_16 *r1,
                              poly_16 *r2,
                              poly_16 *r3,
                              const uint8_t seed[32*(16*2-1)],
                              uint8_t nonce0,
                              uint8_t nonce1,
                              uint8_t nonce2,
                              uint8_t nonce3);

#endif
#endif


#define poly_ntt KYBER_NAMESPACE(poly_ntt)
void poly_ntt(poly_16 *r);
#define poly_invntt_tomont KYBER_NAMESPACE(poly_invntt_tomont)
void poly_invntt_tomont(poly_16 *r);
#define poly_nttunpack KYBER_NAMESPACE(poly_nttunpack)
void poly_nttunpack(poly_16 *r);
#define poly_basemul_montgomery KYBER_NAMESPACE(poly_basemul_montgomery)
void poly_basemul_montgomery(poly_16 *r, const poly_16 *a, const poly_16 *b);
#define poly_tomont KYBER_NAMESPACE(poly_tomont)
void poly_tomont(poly_16 *r);

#define poly_reduce KYBER_NAMESPACE(poly_reduce)
void poly_reduce(poly_16 *r);

#define poly_add KYBER_NAMESPACE(poly_add)
void poly_add(poly_16 *r, const poly_16 *a, const poly_16 *b);
#define poly_sub KYBER_NAMESPACE(poly_sub)
void poly_sub(poly_16 *r, const poly_16 *a, const poly_16 *b);

#endif
