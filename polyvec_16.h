#ifndef POLYVEC_16_H
#define POLYVEC_16_H

#include <stdint.h>
#include "params.h"
#include "poly_16.h"

typedef struct{
  poly vec[KYBER_K];
} polyvec;
typedef struct{
  poly_16 vec[KYBER_K];
} polyvec_16;

#define polyvec_compress KYBER_NAMESPACE(polyvec_compress)
void polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES+2], const polyvec_16 *a);
#define polyvec_decompress KYBER_NAMESPACE(polyvec_decompress)
void polyvec_decompress(polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES+12]);

#define polyvec_tobytes KYBER_NAMESPACE(polyvec_tobytes)
void polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES*16], const polyvec_16 *a);
#define polyvec_frombytes KYBER_NAMESPACE(polyvec_frombytes)
void polyvec_frombytes(polyvec_16 *r, const uint8_t a[KYBER_POLYVECBYTES*16]);

#define polyvec_ntt KYBER_NAMESPACE(polyvec_ntt)
void polyvec_ntt(polyvec_16 *r);
#define polyvec_invntt_tomont KYBER_NAMESPACE(polyvec_invntt_tomont)
void polyvec_invntt_tomont(polyvec_16 *r);

#define polyvec_basemul_acc_montgomery KYBER_NAMESPACE(polyvec_basemul_acc_montgomery)
void polyvec_basemul_acc_montgomery(poly_16 *r, const polyvec_16 *a, const polyvec_16 *b);

#define polyvec_reduce KYBER_NAMESPACE(polyvec_reduce)
void polyvec_reduce(polyvec_16 *r);

#define polyvec_add KYBER_NAMESPACE(polyvec_add)
void polyvec_add(polyvec_16 *r, const polyvec_16 *a, const polyvec_16 *b);

#endif
