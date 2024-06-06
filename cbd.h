#ifndef CBD_16_H
#define CBD_16_H

#include <stdint.h>
#include <immintrin.h>
#include "params.h"
#include "poly_16.h"

#define poly_cbd_eta1 KYBER_NAMESPACE(poly_cbd_eta1)
void poly_cbd_eta1(int16_t *r, const __m256i buf[KYBER_ETA1*KYBER_N/128+1]);

#define poly_cbd_eta2 KYBER_NAMESPACE(poly_cbd_eta2)
void poly_cbd_eta2(poly *r, const __m256i buf[KYBER_ETA2*KYBER_N/128]);

#endif
