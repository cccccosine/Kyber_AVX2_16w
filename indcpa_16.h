#ifndef INDCPA_16_H
#define INDCPA_16_H

#include <stdint.h>
#include "params.h"
#include "polyvec_16.h"


#define gen_matrix KYBER_NAMESPACE(gen_matrix)
void gen_matrix(polyvec_16 *a, const uint8_t seed[KYBER_SYMBYTES], int transposed);
#define indcpa_keypair KYBER_NAMESPACE(indcpa_keypair)
void indcpa_keypair(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES*16],
                    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES*16]);
                    // int16_t skpvprint[KYBER_K*KYBER_N*16],
                    // int16_t pkpvprint[KYBER_K*KYBER_N*16]);

#define indcpa_enc KYBER_NAMESPACE(indcpa_enc)
void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES*16],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES*16],
                const uint8_t coins[KYBER_SYMBYTES]);
                // int16_t pkpvprint[KYBER_K*KYBER_N*16],
                // int16_t vprint[KYBER_N*16]);

#define indcpa_dec KYBER_NAMESPACE(indcpa_dec)
void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);

#endif
