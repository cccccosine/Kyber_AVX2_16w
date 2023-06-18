#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "indcpa_16.h"
#include "poly_16.h"
#include "polyvec_16.h"
#include "clocks.h"
#include "randombytes.h"
#include "cpucycles.h"
#include "speed_print.h"

#define NTESTS 100000
#define indcpa_keypair_flag 1
#define indcpa_enc_flag 1
#define indcpa_dec_flag 1

uint64_t t[NTESTS];

int main() {
    int i, j;
    uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES*16];
    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES*16];
    // int16_t skpvprint[KYBER_K*KYBER_N*16];
    int16_t pkpvprint[KYBER_K*KYBER_N*16];
    int16_t vprint[KYBER_N*16];
    poly_16 r, p, q;
    polyvec_16 a, b;
    uint8_t c[KYBER_INDCPA_BYTES];
    uint8_t m[KYBER_INDCPA_MSGBYTES*16];
    uint8_t coins[KYBER_SYMBYTES] = {1};



#ifdef indcpa_keypair_flag
    // for(int i=0;i<NTESTS;i++) {
    //     t[i] = cpucycles();
    //     indcpa_keypair(pk, sk);
    // }
    // print_results("indcpa_keypair: ", t, NTESTS);

    // oper_second_n(while (0), Kyber_AVX2_16w_indcpa_keypair, indcpa_keypair(pk, sk),
    //               20000, 16);

    FILE *f = fopen("test_indcpakeypair.txt", "w+");
    if (f == NULL) {
        printf("Fail to open test_indcpakeypair.txt!");
        fclose(f);
        return -1;
    }

    indcpa_keypair(pk, sk);

    for(int i = 0; i < KYBER_INDCPA_PUBLICKEYBYTES-2; i++) {
        for(int j = 0; j < 16; j++) {
            fprintf(f, "%7d", pk[i*16+j]); 
        }
        fputs("\n", f);
    }

    fclose(f);
#endif

#ifdef indcpa_enc_flag
    // for(i = 0; i < KYBER_INDCPA_PUBLICKEYBYTES*16; i++) {
    //     pk[i] = 12;
    // }
    for(i = 0; i < KYBER_INDCPA_MSGBYTES*16; i++) {
        m[i] = 1;
    }

    FILE *f1 = fopen("test_indcpaenc.txt", "w+");
    if (f1 == NULL) {
        printf("Fail to open test_indcpaenc.txt!");
        fclose(f1);
        return -1;
    }

    // oper_second_n(while (0), Kyber_AVX2_16w_indcpa_enc, indcpa_enc(c, m, pk, coins),
    //               20000, 16);

    // indcpa_enc(c, m, pk, coins, pkpvprint, vprint);
    indcpa_enc(c, m, pk, coins);
    
    // for(i = (KYBER_POLYVECCOMPRESSEDBYTES/16); i < (KYBER_INDCPA_BYTES/16); i++) {
    //     for(int j = 0; j < 16; j++) {
    //         fprintf(f1, "%7d", c[i*16+j]); 
    //     }
    //     fputs("\n", f1);
    // }
    // for(int i = 0; i < KYBER_K; i++) {
    //     for(int j = 0; j < KYBER_N; j++) {
    //         // fprintf(f1, "%7d", skpvprint[(i*KYBER_N+j)*16]); 
    //         fprintf(f1, "%7d", pkpvprint[(i*KYBER_N+j)*16]); 
    //         fputs("\n", f1);
    //     }
    // }

    // for(int i = 0; i < KYBER_N; i++) {
    //     for(int j = 0; j < 16; j++) {
    //         fprintf(f1, "%7d", vprint[i*16+j]);
    //     }
    //     fputs("\n", f1);
    // }

    fclose(f1);
#endif

#ifdef indcpa_dec_flag

    // oper_second_n(while (0), Kyber_AVX2_16w_indcpa_keypair, indcpa_keypair(pk, sk),
    //               20000, 16);

    FILE *f2= fopen("test_indcpadec.txt", "w+");
    if (f2== NULL) {
        printf("Fail to open test_indcpadec.txt!");
        fclose(f2);
        return -1;
    }

    indcpa_keypair(pk, sk);

    for(int i = 0; i < KYBER_INDCPA_PUBLICKEYBYTES-2; i++) {
        for(int j = 0; j < 16; j++) {
            fprintf(f2, "%7d", pk[i*16+j]); 
        }
        fputs("\n", f2);
    }

    fclose(f2);
#endif



    return 0;
}