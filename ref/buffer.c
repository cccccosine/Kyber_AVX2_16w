#include <stdint.h>
#include "params.h"
#include "consts.h"

#define Q KYBER_Q
#define MONT -1044 // 2^16 mod q
#define QINV -3327 // q^-1 mod 2^16
#define V 20159 // floor(2^26/q + 0.5)
#define FHI 1441 // mont^2/128
#define FLO -10079 // qinv*FHI
#define MONTSQHI 1353 // mont^2
#define MONTSQLO 20553 // qinv*MONTSQHI
#define MASK 4095
#define SHIFT 32

const int qdata[] = {
#define _ZETAS_EXP 0
//0                                 zeta^64*R modq  
    31498,  31498,  31498,  31498,    -758,   -758,   -758,   -758,    
//8                                 zeta^32 zeta^96
    14745,    787,  14745,    787,   -359,  -1517,   -359,  -1517,
//16                                zeta^16 zeta^80 zeta^48 zeta^112
    13525, -12402,  28191, -16694,   1493,   1422,    287,    202,
/******************************************************************/
//24                                zeta^8
   -20907, -20907, -20907, -20907,   -171,   -171,   -171,   -171,
//32                                zeta^4 zeta^68
    -5827,  17363,  -5827,  17363,    573,  -1325,    573,  -1325,
//40                                zeta^2 zeta^66 zeta^34 zeta^98
    -5689,  -6516,   1496,  30967,   1223,    652,   -552,   1015,
/************************************************/
//48                                zeta^72
    27758,  27758,  27758,  27758,    622,    622,    622,    622,
//56                                zeta^36 zeta^100
   -26360, -29057, -26360, -29057,    264,    383,    264,    383,
//64                                zeta^18 zeta^82 zeta^50 zeta^114
   -23565,  20179,  20710,  25080,  -1293,   1491,   -282,  -1544,

/************************************************/
//72                                zeta^40
    -3799,  -3799,  -3799,  -3799,   1577,   1577,   1577,   1577,
//80                                zeta^20 zeta^84
     5571,  -1102,   5571,  -1102,   -829,   1458,   -829,   1458,
//88                                zeta^10 zeta^74 zeta^42 zeta^106
   -12796,  26616,  16064, -12442,    516,     -8,   -320,   -666,

/************************************************/
//96                                zeta^104
   -15690, -15690, -15690, -15690,    182,    182,    182,    182,
//104                               zeta^52 zeta^116
    21438, -26242,  21438, -26242,  -1602,   -130,  -1602,   -130,
//112                               zeta^26 zeta^90 zeta^58 zeta^122
     9134,   -650, -25986,  27837,  -1618,  -1162,    126,   1469,

/************************************************/
//120                               zeta^24
    10690,  10690,  10690,  10690,    962,    962,    962,    962,
//128                               zeta^12 zeta^76
   -28073,  24313, -28073,  24313,   -681,   1017,   -681,   1017,
//136                               zeta^6 zeta^70 zeta^38 zeta^102
    19883, -28250, -15887,  -8898,   -853,    -90,   -271,    830,

/************************************************/
//144                               zeta^88
     1358,   1358,   1358,   1358,  -1202,  -1202,  -1202,  -1202,
//152                               zeta^44 zeta^108
   -10532,   8800, -10532,   8800,    732,    608,    732,    608,
//160                               zeta^22 zeta^86 zeta^54 zeta^118
   -28309,   9075, -30199,  18249,    107,  -1421,   -247,   -951,

/************************************************/
//168                               zeta^56
   -11202, -11202, -11202, -11202,  -1474,  -1474,  -1474,  -1474,
//176                               zeta^28 zeta^92
    18426,   8859,  18426,   8859,  -1542,    411,  -1542,    411,
//184                               zeta^14 zeta^78 zeta^46 zeta^110
    13426,  14017, -29156, -12757,   -398,    961,  -1508,   -725,

/************************************************/
//192                               zeta^120
    31164,  31164,  31164,  31164,   1468,   1468,   1468,   1468,
//200                               zeta^60 zeta^124
    26675, -16163,  26675, -16163,   -205,  -1571,   -205,  -1571,
//208                               zeta^30 zeta^94 zeta^62 zeta^126
    16832,   4311, -24155, -17915,    448,  -1065,    677,  -1275,

/******************************************************************/
//216                               zeta^1           zeta^65 
     -335,   -335,  11182,  11182,  -1103,  -1103,    430,    430,
//224                               zeta^33          zeta^97
   -11477, -11477,  13387,  13387,    555,    555,    843,    843,
//232                               zeta^17          zeta^81
   -32227, -32227, -14233, -14233,  -1251,  -1251,    871,    871,
//240                               zeta^49          zeta^113
    20494,  20494, -21655, -21655,   1550,   1550,    105,    105,
//248                               zeta^9           zeta^73 
   -27738, -27738,  13131,  13131,    422,    422,    587,    587,
//256                               zeta^41          zeta^105
      945,    945,  -4587,  -4587,    177,    177,   -235,   -235,
//264                               zeta^25          zeta^89
   -14883, -14883,  23092,  23092,   -291,   -291,   -460,   -460,
//272                               zeta^57          zeta^121
     6182,   6182,   5493,   5493,   1574,   1574,   1653,   1653,
//280                               zeta^5           zeta^69
    32010,  32010, -32502, -32502,   -246,   -246,    778,    778,
//288                               zeta^37          zeta^101
    10631,  10631,  30317,  30317,   1159,   1159,   -147,   -147,
//296                               zeta^21          zeta^85
    29175,  29175, -18741, -18741,   -777,   -777,   1483,   1483,
//304                               zeta^53          zeta^117
   -28762, -28762,  12639,  12639,   -602,   -602,   1119,   1119,
//312                               zeta^13          zeta^77
   -18486, -18486,  20100,  20100,  -1590,  -1590,    644,    644,
//320                               zeta^45          zeta^109
    17560,  17560,  18525,  18525,   -872,   -872,    349,    349,
//328                               zeta^29          zeta^93
   -14430, -14430,  19529,  19529,    418,    418,    329,    329,
//336                               zeta^61          zeta^125
    -5276,  -5276, -12619, -12619,   -156,   -156,    -75,    -75,
//344                               zeta^3           zeta^67 
   -31183, -31183,  20297,  20297,    817,    817,   1097,   1097,
//352                               zeta^35          zeta^99
    25435,  25435,   2146,   2146,    603,    603,    610,    610,
//360                               zeta^19          zeta^83
    -7382,  -7382,  15355,  15355,   1322,   1322,  -1285,  -1285,
//368                               zeta^51          zeta^115
    24391,  24391, -32384, -32384,  -1465,  -1465,    384,    384,
//376                               zeta^11           zeta^75 
   -20927, -20927,  -6280,  -6280,  -1215,  -1215,   -136,   -136,
//384                               zeta^43          zeta^107
    10946,  10946, -14903, -14903,   1218,   1218,  -1335,  -1335,
//392                               zeta^27          zeta^91
    24214,  24214, -11044, -11044,   -874,   -874,    220,    220,
//400                               zeta^59          zeta^123
    16989,  16989,  14469,  14469,  -1187,  -1187,  -1659,  -1659,
//408                               zeta^7           zeta^71
    10335,  10335, -21498, -21498,  -1185,  -1185,  -1530,  -1530,
//416                               zeta^39          zeta^103
    -7934,  -7934, -20198, -20198,  -1278,  -1278,    794,    794,
//424                               zeta^23          zeta^87
   -22502, -22502,  23210,  23210,  -1510,  -1510,   -854,   -854,
//432                               zeta^55          zeta^119
    10906,  10906, -17442, -17442,   -870,   -870,    478,    478,
//440                               zeta^15          zeta^79
    28644,  28644, -23860, -23860,   -108,   -108,   -308,   -308,
//448                               zeta^47          zeta^111
    17560,  17560, -20257, -20257,    996,    996,    991,    991,
//456                               zeta^31          zeta^95
    23998,  23998,   7756,   7756,    958,    958,  -1460,  -1460,
//464                               zeta^63          zeta^127
   -17422, -17422,  23132,  23132,   1522,   1522,   1628,   1628,

};


/*************************************************
* Name:        poly_basemul_montgomery     //16-way
*
* Description: Multiplication of two polynomials in NTT domain.
*              One of the input polynomials needs to have coefficients
*              bounded by q, the other polynomial can have arbitrary
*              coefficients. Output coefficients are bounded by 6656.
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial
**************************************************/
void poly_basemul_montgomery_16(poly *r, const poly *a, const poly *b)
{
  basemul_avx(r->vec, a->vec, b->vec, qdata.vec);
}

const int16_t zetas[128] = {
  -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
   -171,   622,  1577,   182,   962, -1202, -1474,  1468,
    573, -1325,   264,   383,  -829,  1458, -1602,  -130,
   -681,  1017,   732,   608, -1542,   411,  -205, -1571,
   1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
    516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
   -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
   -398,   961, -1508,  -725,   448, -1065,   677, -1275,
  -1103,   430,   555,   843, -1251,   871,  1550,   105,
    422,   587,   177,  -235,  -291,  -460,  1574,  1653,
   -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
  -1590,   644,  -872,   349,   418,   329,  -156,   -75,
    817,  1097,   603,   610,  1322, -1285, -1465,   384,
  -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
  -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
   -108,  -308,   996,   991,   958, -1460,  1522,  1628
};

/*************************************************
* Name:        fqmul
*
* Description: Multiplication followed by Montgomery reduction
*
* Arguments:   - int16_t a: first factor
*              - int16_t b: second factor
*
* Returns 16-bit integer congruent to a*b*R^{-1} mod q
**************************************************/
static int16_t fqmul(int16_t a, int16_t b) {
  return montgomery_reduce((int32_t)a*b);
}

/*************************************************
* Name:        ntt
*
* Description: Inplace number-theoretic transform (NTT) in Rq.
*              input is in standard order, output is in bitreversed order
*
* Arguments:   - int16_t r[256]: pointer to input/output vector of elements of Zq
**************************************************/
void ntt(int16_t r[256]) {
  unsigned int len, start, j, k;
  int16_t t, zeta;

  k = 1;
  for(len = 128; len >= 2; len >>= 1) {  //layer3: len >= 32     layer6: len >= 4     layer7: len >= 2
    for(start = 0; start < 256; start = j + len) {
      zeta = zetas[k++];
      for(j = start; j < start + len; ++j) {
        t = fqmul(zeta, r[j + len]);
        r[j + len] = r[j] - t;
        r[j] = r[j] + t;
      }
    }
  }
}

/*************************************************
* Name:        basemul
*
* Description: Multiplication of polynomials in Zq[X]/(X^2-zeta)
*              used for multiplication of elements in Rq in NTT domain
*
* Arguments:   - int16_t r[2]: pointer to the output polynomial
*              - const int16_t a[2]: pointer to the first factor
*              - const int16_t b[2]: pointer to the second factor
*              - int16_t zeta: integer defining the reduction polynomial
**************************************************/
void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta)
{
  r[0]  = fqmul(a[1], b[1]);
  r[0]  = fqmul(r[0], zeta);
  r[0] += fqmul(a[0], b[0]);
  r[1]  = fqmul(a[0], b[1]);
  r[1] += fqmul(a[1], b[0]);
}

/*************************************************
* Name:        poly_basemul_montgomery
*
* Description: Multiplication of two polynomials in NTT domain
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial
**************************************************/
void poly_basemul_montgomery(int16_t *r, const int16_t *a, const int16_t *b)
{
  unsigned int i;
  for(i=0;i<KYBER_N/4;i++) {
    basemul(&r[4*i], &a[4*i], &b[4*i], zetas[64+i]);
    basemul(&r[4*i+2], &a[4*i+2], &b[4*i+2], -zetas[64+i]);
  }
}

void poly_reduce(int16_t *r)
{
  unsigned int i;
  for(i=0;i<KYBER_N;i++)
    r[i] = barrett_reduce(r[i]);
}





#define poly_basemul_montgomery_16 KYBER_NAMESPACE(poly_basemul_montgomery_16)
void poly_basemul_montgomery_16(poly *r, const poly *a, const poly *b);

#define ntt KYBER_NAMESPACE(ntt)
void ntt(int16_t r[256]);

#define poly_reduce KYBER_NAMESPACE(poly_reduce)
void poly_reduce(int16_t *r);

#define fqmul KYBER_NAMESPACE(fqmul)
static int16_t fqmul(int16_t a, int16_t b);

#define basemul KYBER_NAMESPACE(basemul)
void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

#define poly_basemul_montgomery KYBER_NAMESPACE(poly_basemul_montgomery)
void poly_basemul_montgomery(int16_t *r, const int16_t *a, const int16_t *b);






