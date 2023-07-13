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


void ct_formseq(uint8_t *ct, uint8_t *ctseq) {
  for(int k = 0; k < 16; k++) {
    for(int i = 0; i < 3; i++) {
      for(int j = 0; j < 160; j++) {
        ctseq[k*(3*320+128)+i*320+j*2] = ct[i*32*160+32*j+k*2];
        ctseq[k*(3*320+128)+i*320+j*2+1] = ct[i*32*160+32*j+k*2+1];
      }
    }
  }
  for(int k = 0; k < 16; k++) {
    for(int j = 0; j < 64; j++) {
      ctseq[3*320+k*(3*320+128)+j*2] = ct[3*320*16+32*j+k*2];
      ctseq[3*320+k*(3*320+128)+j*2+1] = ct[3*320*16+32*j+k*2+1];
    }
  }
}


int crypto_kem_keypair(uint8_t *pk,
                       uint8_t *sk)
{
  indcpa_keypair(pk, sk);
  memcpy(sk+KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_INDCPA_PUBLICKEYBYTES);
  hash_h(sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  /* Value z for pseudo-random output on reject */
  randombytes(sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES);
  return 0;
}


int crypto_kem_enc(uint8_t *ct,
                   uint8_t *ss,
                   uint8_t *pk)
{
  /* To adapt to the shake128x4, the size of buf is defined as 4*168 bytes, which is enough to include 16*32 bytes */
  uint8_t buf[4*168];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];
  /* Will store the ct with rearranged sequence */
  uint8_t *ctseq = (uint8_t *)malloc(KYBER_CIPHERTEXTBYTES);
  keccakx4_state state;

  // TODO: lack a complete explain here
  randombytes(buf, KYBER_SYMBYTES);
  buf[0] += 0;
  buf[1] += 1;
  buf[2] += 2;
  buf[3] += 3;
  shake128x4_absorb_once(&state, buf, buf+1, buf+2, buf+3, KYBER_SYMBYTES);
  shake128x4_squeezeblocks(buf, buf+168, buf+168*2, buf+168*3, 1, &state);

  /* Don't release system RNG output */
  for(int i = 0; i < 4; i++) {
    hash_hx4(buf+4*i*KYBER_SYMBYTES, buf+KYBER_SYMBYTES*i*4, buf+KYBER_SYMBYTES*(i*4+1), buf+KYBER_SYMBYTES*(i*4+2), buf+KYBER_SYMBYTES*(i*4+3), KYBER_SYMBYTES);
  }

  hash_h(buf+16*KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);

  hash_g(kr, buf, 17*KYBER_SYMBYTES);

  indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES);

#ifdef test_kem_enc_flag 
  FILE *f0 = fopen("test_kem_enc_ct.txt", "w+");

  for (int i = 0; i < KYBER_CIPHERTEXTBYTES; i++)
  {
      fprintf(f0, "%7d", ct[i]);
      fputs("\n", f0);
  }

  FILE *f1 = fopen("test_kem_enc_buf.txt", "w+");

  for (int i = 0; i < 16*KYBER_SYMBYTES+KYBER_SYMBYTES; i++)
  {
      fprintf(f1, "%7d", buf[i]);
      fputs("\n", f1);
  }

  FILE *f2 = fopen("test_kem_enc_pk.txt", "w+");

  for (int i = 0; i < KYBER_INDCPA_PUBLICKEYBYTES/16; i++)
  {
      for(int j = 0; j < 16; j++) {
          fprintf(f2, "%7d", pk[i*16+j]);
      }
      fputs("\n", f2);
  }

  FILE *f3 = fopen("test_kem_enc_coin.txt", "w+");

  for (int i = 0; i < KYBER_SYMBYTES; i++)
  {
      fprintf(f3, "%7d", kr[32+i]);
      fputs("\n", f3);
  }

  fclose(f0);
  fclose(f1);
  fclose(f2);
  fclose(f3);

#endif

  ct_formseq(ct, ctseq);

  for(int i = 0; i < 4; i++) {
    hash_hx4(ctseq+8*i*KYBER_SYMBYTES + KYBER_SYMBYTES, ctseq+KYBER_CIPHERTEXTBYTES/16*i*4, ctseq+KYBER_CIPHERTEXTBYTES/16*(i*4+1), ctseq+KYBER_CIPHERTEXTBYTES/16*(i*4+2), ctseq+KYBER_CIPHERTEXTBYTES/16*(i*4+3), KYBER_CIPHERTEXTBYTES/16);
  }

  for(int i = 0; i < 16; i++) {
    for(int j = 0; j < 32; j++) {
      ctseq[KYBER_SYMBYTES*i*2+j] = kr[j];
    }
  }
  
  /* hash concatenation of pre-k and H(c) to k */
  for(int i = 0; i < 4; i++) {
    kdfx4(ss + 4*i*KYBER_SSBYTES, ss + (4*i+1)*KYBER_SSBYTES, ss + (4*i+2)*KYBER_SSBYTES, ss + (4*i+3)*KYBER_SSBYTES, ctseq+4*i*2*KYBER_SYMBYTES, ctseq+(4*i+1)*2*KYBER_SYMBYTES, ctseq+(4*i+2)*2*KYBER_SYMBYTES, ctseq+(4*i+3)*2*KYBER_SYMBYTES, 2*KYBER_SYMBYTES);
  }
  
  return 0;
}


int crypto_kem_dec(uint8_t *ss,
                   const uint8_t *ct,
                   const uint8_t *sk)
{
  int fail;
  uint8_t buf[16*KYBER_SYMBYTES+KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];
  ALIGNED_UINT8(KYBER_CIPHERTEXTBYTES) cmp;
  const uint8_t *pk = sk+KYBER_INDCPA_SECRETKEYBYTES;
  uint8_t *ctseq = (uint8_t *)malloc(KYBER_CIPHERTEXTBYTES);

  indcpa_dec(buf, ct, sk);

  memcpy(buf+KYBER_SYMBYTES*16, sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, KYBER_SYMBYTES);
  hash_g(kr, buf, 17*KYBER_SYMBYTES);

  indcpa_enc(cmp.coeffs, buf, pk, kr+KYBER_SYMBYTES);

  fail = verify(ct, cmp.coeffs, KYBER_CIPHERTEXTBYTES);

  /* overwrite coins in kr with H(c) */
  ct_formseq(ct, ctseq);
  for(int i = 0; i < 4; i++) {
    hash_hx4(ctseq+8*i*KYBER_SYMBYTES + KYBER_SYMBYTES, ctseq+KYBER_CIPHERTEXTBYTES/16*i*4, ctseq+KYBER_CIPHERTEXTBYTES/16*(i*4+1), ctseq+KYBER_CIPHERTEXTBYTES/16*(i*4+2), ctseq+KYBER_CIPHERTEXTBYTES/16*(i*4+3), KYBER_CIPHERTEXTBYTES/16);
  }

  for(int i = 0; i < 16; i++) {
    for(int j = 0; j < 32; j++) {
      ctseq[KYBER_SYMBYTES*i*2+j] = kr[j];
    }
  }


  /* Overwrite pre-k with z on re-encryption failure */
  for(int i = 0; i < 16; i++) {
    cmov(ctseq+i*KYBER_SYMBYTES*2, sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES, fail);
  }

  /* hash concatenation of pre-k and H(c) to k */
  for(int i = 0; i < 4; i++) {
    kdfx4(ss + 4*i*KYBER_SSBYTES, ss + (4*i+1)*KYBER_SSBYTES, ss + (4*i+2)*KYBER_SSBYTES, ss + (4*i+3)*KYBER_SSBYTES, ctseq+4*i*2*KYBER_SYMBYTES, ctseq+(4*i+1)*2*KYBER_SYMBYTES, ctseq+(4*i+2)*2*KYBER_SYMBYTES, ctseq+(4*i+3)*2*KYBER_SYMBYTES, 2*KYBER_SYMBYTES);
  }

  return 0;
}
