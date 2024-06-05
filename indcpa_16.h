#ifndef INDCPA_16_H
#define INDCPA_16_H

#include <stdint.h>
#include "params.h"
#include "polyvec_16.h"

#define matrix_formseqto16 KYBER_NAMESPACE(matrix_formseqto16)
void matrix_formseqto16(polyvec_16 *a, polyvec_16 *t, polyvec_16 *aseq);
#define polyvec_formseqto16 KYBER_NAMESPACE(polyvec_formseqto16)
void polyvec_formseqto16(polyvec_16 *pv, polyvec_16 *t, polyvec_16 *pvseq);
#define poly_formseqto16 KYBER_NAMESPACE(poly_formseqto16)
void poly_formseqto16(poly_16 *p, poly_16 *t, poly_16 *pseq);
#define keypair_formseqfrom16 KYBER_NAMESPACE(keypair_formseqfrom16)
void keypair_formseqfrom16(uint8_t *keyseq, uint8_t *t, uint8_t *key);
#define keypair_formseqto16 KYBER_NAMESPACE(keypair_formseqto16)
void keypair_formseqto16(uint8_t *key, uint8_t *t, uint8_t *keyseq);
#define msg_formseqto16 KYBER_NAMESPACE(msg_formseqto16)
void msg_formseqto16(const uint8_t *m, uint8_t *mseq);
#define msg_formseqfrom16 KYBER_NAMESPACE(msg_formseqfrom16)
void msg_formseqfrom16(uint8_t *mseq, uint8_t *m);
#define cipher_formseqfrom16 KYBER_NAMESPACE(cipher_formseqfrom16)
void cipher_formseqfrom16(uint8_t *cseq, uint8_t *t, uint8_t *c);
#define cipher_formseqto16 KYBER_NAMESPACE(cipher_formseqto16)
void cipher_formseqto16(uint8_t *c, uint8_t *t, uint8_t *cseq);

#define gen_matrix KYBER_NAMESPACE(gen_matrix)
void gen_matrix(polyvec_16 *a, const uint8_t seed[32*(2*16)], int transposed);
#define indcpa_keypair KYBER_NAMESPACE(indcpa_keypair)
void indcpa_keypair(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]
                    // uint16_t pkpvprint[KYBER_INDCPA_PUBLICKEYBYTES]
                    );

#define indcpa_enc KYBER_NAMESPACE(indcpa_enc)
void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES*32],
                uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                uint8_t coins[KYBER_SYMBYTES*32-32]
                );

#define indcpa_dec KYBER_NAMESPACE(indcpa_dec)
void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES*32],
                uint8_t c[KYBER_INDCPA_BYTES],
                uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]
                );

#endif
