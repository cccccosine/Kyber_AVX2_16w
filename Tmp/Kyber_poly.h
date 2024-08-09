#ifndef KYBER_POLY_H
#define KYBER_POLY_H

#include <stdint.h>
#include "params.h"

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*coeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct{
  int16_t coeffs[KYBER_N];
} Kyber_poly;


#define Kyber_poly_ntt KYBER_NAMESPACE(Kyber_poly_ntt)
void Kyber_poly_ntt(Kyber_poly *r);
#define Kyber_poly_invntt_tomont KYBER_NAMESPACE(Kyber_poly_invntt_tomont)
void Kyber_poly_invntt_tomont(Kyber_poly *r);
#define Kyber_poly_basemul_montgomery KYBER_NAMESPACE(Kyber_poly_basemul_montgomery)
void Kyber_poly_basemul_montgomery(Kyber_poly *r, const Kyber_poly *a, const Kyber_poly *b);

#define Kyber_poly_reduce KYBER_NAMESPACE(Kyber_poly_reduce)
void Kyber_poly_reduce(Kyber_poly *r);


#endif
