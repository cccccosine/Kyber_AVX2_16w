#ifndef REDUCE_16_H
#define REDUCE_16_H

#include "params.h"
#include <immintrin.h>

#define reduce_avx_16 KYBER_NAMESPACE(reduce_avx_16)
void reduce_avx_16(__m256i *r, const __m256i *qdata);
#define tomont_avx_16 KYBER_NAMESPACE(tomont_avx_16)
void tomont_avx_16(__m256i *r, const __m256i *qdata);

#endif
