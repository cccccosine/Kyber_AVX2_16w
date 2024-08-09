#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "params.h"
#include "align.h"


typedef ALIGNED_INT16(KYBER_N) poly;
typedef ALIGNED_INT16(KYBER_N*16) poly_16;


#define poly_ntt_16 KYBER_NAMESPACE(poly_ntt_16)
void poly_ntt_16(poly_16 *r);

#define poly_ntt KYBER_NAMESPACE(poly_ntt)
void poly_ntt(poly *r);

#define poly_basemul_montgomery KYBER_NAMESPACE(poly_basemul_montgomery)
void poly_basemul_montgomery(poly *r, const poly *a, const poly *b);

#define poly_basemul_montgomery_16 KYBER_NAMESPACE(poly_basemul_montgomery_16)
void poly_basemul_montgomery_16(poly_16 *r, const poly_16 *a, const poly_16 *b);

#define poly_invntt_tomont KYBER_NAMESPACE(poly_invntt_tomont)
void poly_invntt_tomont(poly *r);

#define poly_invntt_tomont_16 KYBER_NAMESPACE(poly_invntt_tomont_16)
void poly_invntt_tomont_16(poly_16 *r);

#endif