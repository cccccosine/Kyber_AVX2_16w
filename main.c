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

    indcpa_keypair(pk, sk);


    for(int i = 0; i < KYBER_INDCPA_PUBLICKEYBYTES-2; i++) {
        for(int j = 0; j < 16; j++) {
            fprintf(f, "%7d", sk[i*16+j]); 
        }
        fputs("\n", f);
    }


    fclose(f);

    return 0;
}