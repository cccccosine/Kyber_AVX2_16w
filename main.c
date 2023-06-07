#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "indcpa_16.h"
#include "poly_16.h"
#include "polyvec_16.h"


int main() {
    uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES*16];
    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES*16];
    int16_t skpvprint[KYBER_K*KYBER_N*16];
    int16_t pkpvprint[KYBER_K*KYBER_N*16];
    poly_16 r, p, q;
    polyvec_16 a, b;

    FILE *f = fopen("test_correct.txt", "w+");
    if (f == NULL) {
        printf("Fail to open test_correct.txt!");
        fclose(f);
        return -1;
    }

    // indcpa_keypair(pk, sk, skpvprint, pkpvprint);
    indcpa_keypair(pk, sk);
    
    // for(int i = 0; i < KYBER_K; i++) {
    //     for(int j = 0; j < KYBER_N; j++) {
    //         // fprintf(f, "%7d", skpvprint[(i*KYBER_N+j)*16]); 
    //         fprintf(f, "%7d", pkpvprint[(i*KYBER_N+j)*16]); 
    //         fputs("\n", f);
    //     }
    // }

    for(int i = 0; i < KYBER_INDCPA_PUBLICKEYBYTES-2; i++) {
        for(int j = 0; j < 16; j++) {
            fprintf(f, "%7d", sk[i*16+j]); 
        }
        fputs("\n", f);
    }

    // for(int i = 0; i < KYBER_N; i++) {
    //     for(int j = 0; j < 16; j++) {
    //         p.coeffs[i*16+j] = 1;
    //         q.coeffs[i*16+j] = 1;
    //     }
    // }
    // poly_basemul_montgomery(&r, &p, &q);
    // for(int i = 0; i < KYBER_N; i++) {
    //     for(int j = 0; j < 16; j++) {
    //         fprintf(f, "%7d", r.coeffs[i*16+j]); 
    //     }
    //     fputs("\n", f);
    // }

    // for(int i = 0; i < KYBER_K; i++) {
    //   for(int j = 0; j < KYBER_N*16; j++) {
    //     a.vec[i].coeffs[j] = 1;
    //     b.vec[i].coeffs[j] = 1;
    //   }
    // }
    // polyvec_basemul_acc_montgomery(&r, &a, &b);
    // for(int i = 0; i < KYBER_N; i++) {
    //     for(int j = 0; j < 16; j++) {
    //         fprintf(f, "%7d", r.coeffs[i*16+j]); 
    //     }
    //     fputs("\n", f);
    // }




    fclose(f);

    return 0;
}