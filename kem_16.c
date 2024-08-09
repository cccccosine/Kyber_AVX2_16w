#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "align.h"
#include "params.h"
#include "kem_16.h"
#include "indcpa_16.h"
#include "verify_16.h"
#include "symmetric.h"
#include "randombytes.h"
#include "rejsample.h"

//16个单独pk需要变成(packed pk)+publicseed的形式才可进行unpack操作
void pk_separate16(uint8_t *pk, uint8_t *pk_sepa_16) {   //此函数未按照KYBER_K进行修改
  for(int i = 0; i < 16; i++) {
    for(int j = 0; j < 3*384; j++) {
      pk_sepa_16[j+i*(3*384+64)] = pk[j+i*3*384];
    }
    for(int k = 0; k < 64; k++) {
      pk_sepa_16[i*(3*384+64)+3*384+k] = pk[3*384*16+k+i*64];
    }
  }
}

int crypto_kem_keypair(uint8_t *pk,
                       uint8_t *sk)
{
  uint8_t buf[KYBER_SYMBYTES*16];
  uint8_t *sk_16 = (uint8_t *)malloc(KYBER_INDCPA_SECRETKEYBYTES);
  // keccakx4_state state;

  indcpa_keypair(pk, sk_16);
  // 16个分离的sk||pk||publicseed,无noiseseed
  for(int i = 0; i < 16; i++) {
    memcpy(sk+((KYBER_INDCPA_SECRETKEYBYTES+KYBER_INDCPA_PUBLICKEYBYTES)/16+KYBER_SYMBYTES)*i, sk_16+KYBER_INDCPA_SECRETKEYBYTES/16*i, KYBER_INDCPA_SECRETKEYBYTES/16);
    memcpy(sk+((KYBER_INDCPA_SECRETKEYBYTES+KYBER_INDCPA_PUBLICKEYBYTES)/16+KYBER_SYMBYTES)*i+KYBER_INDCPA_SECRETKEYBYTES/16, pk+KYBER_POLYVECBYTES*i, KYBER_POLYVECBYTES);
    memcpy(sk+((KYBER_INDCPA_SECRETKEYBYTES+KYBER_INDCPA_PUBLICKEYBYTES)/16+KYBER_SYMBYTES)*i+KYBER_INDCPA_SECRETKEYBYTES*2/16, pk+KYBER_INDCPA_PUBLICKEYBYTES-2*(16-i)*32, KYBER_SYMBYTES);
  }
  
  for(int i = 0; i < 4; i++) {
    hash_hx4(sk+(4*i)*((KYBER_INDCPA_SECRETKEYBYTES+KYBER_INDCPA_PUBLICKEYBYTES)/16+KYBER_SYMBYTES)+2*KYBER_POLYVECBYTES+KYBER_SYMBYTES,
             sk+(4*i+1)*((KYBER_INDCPA_SECRETKEYBYTES+KYBER_INDCPA_PUBLICKEYBYTES)/16+KYBER_SYMBYTES)+2*KYBER_POLYVECBYTES+KYBER_SYMBYTES,
             sk+(4*i+2)*((KYBER_INDCPA_SECRETKEYBYTES+KYBER_INDCPA_PUBLICKEYBYTES)/16+KYBER_SYMBYTES)+2*KYBER_POLYVECBYTES+KYBER_SYMBYTES,
             sk+(4*i+3)*((KYBER_INDCPA_SECRETKEYBYTES+KYBER_INDCPA_PUBLICKEYBYTES)/16+KYBER_SYMBYTES)+2*KYBER_POLYVECBYTES+KYBER_SYMBYTES,
             sk+(4*i)*((KYBER_INDCPA_SECRETKEYBYTES+KYBER_INDCPA_PUBLICKEYBYTES)/16+KYBER_SYMBYTES)+KYBER_POLYVECBYTES,
             sk+(4*i+1)*((KYBER_INDCPA_SECRETKEYBYTES+KYBER_INDCPA_PUBLICKEYBYTES)/16+KYBER_SYMBYTES)+KYBER_POLYVECBYTES,
             sk+(4*i+2)*((KYBER_INDCPA_SECRETKEYBYTES+KYBER_INDCPA_PUBLICKEYBYTES)/16+KYBER_SYMBYTES)+KYBER_POLYVECBYTES,
             sk+(4*i+3)*((KYBER_INDCPA_SECRETKEYBYTES+KYBER_INDCPA_PUBLICKEYBYTES)/16+KYBER_SYMBYTES)+KYBER_POLYVECBYTES,
             KYBER_INDCPA_PUBLICKEYBYTES/16-KYBER_SYMBYTES);
  }
  // /* Value z for pseudo-random output on reject */
  randombytes(buf, KYBER_SYMBYTES*16);

  for(int i = 0; i < 16; i++) {
    memcpy(sk+(i+1)*(KYBER_SECRETKEYBYTES/16)-KYBER_SYMBYTES, buf+i*KYBER_SYMBYTES, KYBER_SYMBYTES);
  }

  free(sk_16);

  return 0;
}


int crypto_kem_enc(uint8_t *ct,
                   uint8_t *ss,
                   uint8_t *pk)
{
  uint8_t buf[KYBER_INDCPA_MSGBYTES*32];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES*16];
  /* Will store the pk whose format is polyvec * 16 || publicseed * 16, i.e., separating the public key and public seed */
  uint8_t *pk_sepa_16 = (uint8_t *)malloc(KYBER_PUBLICKEYBYTES);  //16个单独pk需要变成polyvec+publicseed的形式
  /* Will store the pk in 16-way format without publicseed */
  keccakx4_state state;

  randombytes(buf + KYBER_SYMBYTES*16, KYBER_SYMBYTES*16);

  /* Don't release system RNG output */
  //产生16个H(m)，并且留出下一步进行单路连接H(pk)需要的空间
  for(int i = 0; i < 4; i++) {
    hash_hx4(buf+8*i*KYBER_SYMBYTES, 
             buf+(8*i+2)*KYBER_SYMBYTES, 
             buf+(8*i+4)*KYBER_SYMBYTES, 
             buf+(8*i+6)*KYBER_SYMBYTES, 
             buf+KYBER_SYMBYTES*16+KYBER_SYMBYTES*i*4, 
             buf+KYBER_SYMBYTES*16+KYBER_SYMBYTES*(i*4+1), 
             buf+KYBER_SYMBYTES*16+KYBER_SYMBYTES*(i*4+2), 
             buf+KYBER_SYMBYTES*16+KYBER_SYMBYTES*(i*4+3), 
             KYBER_SYMBYTES);
  }

  /* Multitarget countermeasure for coins + contributory KEM */
  pk_separate16(pk, pk_sepa_16);  //这一步将kem_keypair产生的pk分离成每一路都是polyvec+publicseed的正常格式
  for(int i = 0; i < 4; i++) {
    hash_hx4(buf+(8*i+1)*KYBER_SYMBYTES, 
             buf+(8*i+3)*KYBER_SYMBYTES, 
             buf+(8*i+5)*KYBER_SYMBYTES, 
             buf+(8*i+7)*KYBER_SYMBYTES, 
             pk_sepa_16+KYBER_PUBLICKEYBYTES/16*i*4, 
             pk_sepa_16+KYBER_PUBLICKEYBYTES/16*(i*4+1), 
             pk_sepa_16+KYBER_PUBLICKEYBYTES/16*(i*4+2), 
             pk_sepa_16+KYBER_PUBLICKEYBYTES/16*(i*4+3), 
             KYBER_PUBLICKEYBYTES/16-KYBER_SYMBYTES);
  }

  //buf = (m||H(pk)) * 16
  //kr = (K||r) * 16
  for(int i = 0; i < 4; i++) {
    hash_gx4(kr+8*i*KYBER_SYMBYTES, 
             kr+(8*i+2)*KYBER_SYMBYTES, 
             kr+(8*i+4)*KYBER_SYMBYTES, 
             kr+(8*i+6)*KYBER_SYMBYTES, 
             buf+8*i*KYBER_SYMBYTES, 
             buf+(8*i+2)*KYBER_SYMBYTES, 
             buf+(8*i+4)*KYBER_SYMBYTES, 
             buf+(8*i+6)*KYBER_SYMBYTES, 
             KYBER_SYMBYTES*2);
  }

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES);  //ct是one-way格式, 使用的pk需要是polyvec*16+publicseed*16的形式

  /* overwrite coins in kr with H(c) */
  for(int i = 0; i < 4; i++) {
    hash_hx4(kr+(8*i+1)*KYBER_SYMBYTES, 
             kr+(8*i+3)*KYBER_SYMBYTES, 
             kr+(8*i+5)*KYBER_SYMBYTES, 
             kr+(8*i+7)*KYBER_SYMBYTES, 
             ct+KYBER_CIPHERTEXTBYTES/16*i*4, 
             ct+KYBER_CIPHERTEXTBYTES/16*(i*4+1), 
             ct+KYBER_CIPHERTEXTBYTES/16*(i*4+2), 
             ct+KYBER_CIPHERTEXTBYTES/16*(i*4+3), 
             KYBER_CIPHERTEXTBYTES/16);
  }
  
  /* hash concatenation of pre-k and H(c) to k */
  for(int i = 0; i < 4; i++) {
    kdfx4(ss + 4*i*KYBER_SSBYTES, 
          ss + (4*i+1)*KYBER_SSBYTES, 
          ss + (4*i+2)*KYBER_SSBYTES, 
          ss + (4*i+3)*KYBER_SSBYTES, 
          kr+8*i*KYBER_SYMBYTES, 
          kr+(8*i+2)*KYBER_SYMBYTES, 
          kr+(8*i+4)*KYBER_SYMBYTES, 
          kr+(8*i+6)*KYBER_SYMBYTES, 
          2*KYBER_SYMBYTES);
  }

  free(pk_sepa_16);
  
  return 0;
}


int crypto_kem_dec(uint8_t *ss,
                   uint8_t *ct,
                   const uint8_t *sk)
{
  //现在传进来的sk参数是16个分离的sk||pk||publicseed||H(pk)||random
  int fail;
  uint8_t buf[32*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*16*KYBER_SYMBYTES];
  uint8_t *skseq = (uint8_t *)malloc(KYBER_INDCPA_SECRETKEYBYTES);
  uint8_t *sk_sepa_16 = (uint8_t *)malloc(KYBER_INDCPA_SECRETKEYBYTES);
  uint8_t *pk = (uint8_t *)malloc(KYBER_INDCPA_PUBLICKEYBYTES);
  ALIGNED_UINT8(KYBER_CIPHERTEXTBYTES) cmp;

  for(int i = 0; i < 16; i++) {
    memcpy(sk_sepa_16+i*KYBER_INDCPA_SECRETKEYBYTES/16, sk+KYBER_SECRETKEYBYTES*i/16, KYBER_POLYVECBYTES);
    memcpy(pk+i*KYBER_POLYVECBYTES, sk+KYBER_SECRETKEYBYTES*i/16+KYBER_INDCPA_SECRETKEYBYTES/16, KYBER_POLYVECBYTES);
    memcpy(pk+16*KYBER_POLYVECBYTES+KYBER_SYMBYTES*2*i, sk+KYBER_SECRETKEYBYTES*i/16+KYBER_POLYVECBYTES*2, KYBER_SYMBYTES);
  }
  indcpa_dec(buf, ct, sk_sepa_16);

  /* Multitarget countermeasure for coins + contributory KEM */
  for(int i = 0; i < 16; i++) {
    memcpy(buf+KYBER_SYMBYTES*(2*i+1), sk+KYBER_SECRETKEYBYTES*i/16+2*KYBER_POLYVECBYTES+KYBER_SYMBYTES, KYBER_SYMBYTES);
  }
  
  //After the step above, buf = (m||H(pk)) * 16
  for(int i = 0; i < 4; i++) {
    hash_gx4(kr+8*i*KYBER_SYMBYTES, 
             kr+(8*i+2)*KYBER_SYMBYTES, 
             kr+(8*i+4)*KYBER_SYMBYTES, 
             kr+(8*i+6)*KYBER_SYMBYTES, 
             buf+8*i*KYBER_SYMBYTES, 
             buf+(8*i+2)*KYBER_SYMBYTES, 
             buf+(8*i+4)*KYBER_SYMBYTES, 
             buf+(8*i+6)*KYBER_SYMBYTES, 
             KYBER_SYMBYTES*2);
  }
  
  //After the step above, kr = (K||r) * 16

  indcpa_enc(cmp.coeffs, buf, pk, kr+KYBER_SYMBYTES);

  fail = verify(ct, cmp.coeffs, KYBER_CIPHERTEXTBYTES);

  /* overwrite coins in kr with H(c) */
  for(int i = 0; i < 4; i++) {
    hash_hx4(kr+KYBER_SYMBYTES*(8*i+1), 
             kr+KYBER_SYMBYTES*(8*i+3), 
             kr+KYBER_SYMBYTES*(8*i+5), 
             kr+KYBER_SYMBYTES*(8*i+7), 
             ct+KYBER_CIPHERTEXTBYTES/16*i*4, 
             ct+KYBER_CIPHERTEXTBYTES/16*(i*4+1), 
             ct+KYBER_CIPHERTEXTBYTES/16*(i*4+2), 
             ct+KYBER_CIPHERTEXTBYTES/16*(i*4+3), 
             KYBER_CIPHERTEXTBYTES/16);
  }

  /* Overwrite pre-k with z on re-encryption failure */
  for(int i = 0; i < 16; i++) {
    cmov(kr+KYBER_SYMBYTES*2*i, sk+KYBER_SECRETKEYBYTES/16*i-KYBER_SYMBYTES, KYBER_SYMBYTES, fail);
  }
  
  /* hash concatenation of pre-k and H(c) to k */
  for(int i = 0; i < 4; i++) {
    kdfx4(ss + 4*i*KYBER_SSBYTES, 
          ss + (4*i+1)*KYBER_SSBYTES, 
          ss + (4*i+2)*KYBER_SSBYTES, 
          ss + (4*i+3)*KYBER_SSBYTES, 
          kr+8*i*KYBER_SYMBYTES, 
          kr+(8*i+2)*KYBER_SYMBYTES, 
          kr+(8*i+4)*KYBER_SYMBYTES, 
          kr+(8*i+6)*KYBER_SYMBYTES, 
          2*KYBER_SYMBYTES);
  }

  free(skseq);
  free(sk_sepa_16);
  free(pk);

  return 0;
}
