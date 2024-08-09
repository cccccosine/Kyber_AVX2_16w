#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <immintrin.h>
#include <time.h>
#include "params.h"
#include "poly.h"
#include "Kyber_ntt.h"
#include "Kyber_poly.h"
#include "ntt.h"
#include "consts.h"
#include "ntt_16.h"
#include "consts_16.h"
#include "align.h"
#include "cpucycles.h"
#include "speed_print.h"


#define NTT_TIMES 1
#define NTT_TESTS 10000000

uint64_t test[NTT_TESTS];

 
void poly_ntt(poly *r)
{
  ntt_avx(r->vec, qdata.vec);
}

void poly_ntt_16(poly_16 *r)
{
  ntt_avx_16(r->vec, qdata_16.vec);
}

void poly_basemul_montgomery(poly *r, const poly *a, const poly *b)
{
  basemul_avx(r->vec, a->vec, b->vec, qdata.vec);
}

void poly_basemul_montgomery_16(poly_16 *r, const poly_16 *a, const poly_16 *b)
{
  basemul_avx_16(r->vec, a->vec, b->vec, qdata_16.vec);
}

void poly_invntt_tomont(poly *r)
{
  invntt_avx(r->vec, qdata.vec);
}

void poly_invntt_tomont_16(poly_16 *r)
{
  invntt_avx_16(r->vec, qdata_16.vec);
}

int main() {
    
    int i, j, k;
    uint8_t buf[256];
    Kyber_poly co1_Kyber[256];          //Kyber_ntt.C coefficients
    Kyber_poly co2_Kyber[256];
    Kyber_poly r_Kyber[256];            //Kyber_basemul result


    poly co1;                        //ntt coefficients
    poly co2;    
    poly r;
    poly_16 a;                          //ntt_16 coefficients
    poly_16 b;
    poly_16 r_16;                          //basemul_16 result

    FILE *f = fopen("file_input.txt", "w+");           //polynomial coefficients
    FILE *fn = fopen("file_ntt.txt", "w+");            //Kyber_ntt result
    FILE *fn_16 = fopen("file_ntt16.txt", "w+");       //ntt_16 result
    FILE *fb = fopen("file_basemul.txt", "w+");        //Kyber_basemul result
    FILE *fb_16 = fopen("file_basemul16.txt", "w+");   //basemul_16 result
    FILE *finvn = fopen("file_invn.txt", "w+");        //Kyber_invntt result
    FILE *finvn_16 = fopen("file_invn16.txt", "w+");   //invntt_16 result
    if (f == NULL) {
        printf("Fail to open file_input.txt!");
        fclose(f);
        return -1;
    }
    if (fn == NULL) {
        printf("Fail to open file_ntt.txt!");
        fclose(fn);
        return -1;
    }
    if (fn_16 == NULL) {
        printf("Fail to open file_ntt16.txt!");
        fclose(fn_16);
        return -1;
    }
    if (fb == NULL) {
        printf("Fail to open file_basemul.txt!");
        fclose(fb);
        return -1;
    }
    if (fb_16 == NULL) {
        printf("Fail to open file_basemul16.txt!");
        fclose(fb_16);
        return -1;
    }
    if (finvn == NULL) {
        printf("Fail to open file_invn.txt!");
        fclose(finvn);
        return -1;
    }
    if (finvn_16 == NULL) {
        printf("Fail to open file_invn16.txt!");
        fclose(finvn_16);
        return -1;
    }

/*gererate random coefficients of polynomial and write into file f*/
    srand(time(0));

    for(j = 0; j < NTT_TIMES; j++) {
        for(i = 0; i < KYBER_N; i++){
            buf[i] = (rand() % KYBER_Q);
            fprintf(f, "%7d", buf[i]);
            
            // fprintf(f, "%7d", 3328);     //极限情况运行
            // fprintf(f, "%7d", 0);

        }
        fputs("\n", f);
    }



/*Get coefficients from file f and have NTT operation*/
    rewind(f);
    for(i = 0; i < NTT_TIMES; i++){

        for(k = 0; k < KYBER_N; k++){
            fscanf(f, "%d", &a.coeffs[k*16]);
            // fscanf(f, "%d", &r[0][k]);
            // co1_Kyber->coeffs[k] = a.coeffs[k*16];
            // co2_Kyber->coeffs[k] = a.coeffs[k*16];
            co1.coeffs[k] = a.coeffs[k*16];
            co2.coeffs[k] = a.coeffs[k*16];
            b.coeffs[k*16] = a.coeffs[k*16];

            for(j = 1 + k*16; j < 16 + k*16; j++) {
                a.coeffs[j] = a.coeffs[k*16];
                b.coeffs[j] = b.coeffs[k*16];
            }
        }

/*Test the ntt_16 cpucycles*/
        // for(i=0; i<NTT_TESTS; i++) {
        //     test[i] = cpucycles();
        //     poly_ntt_16(&a);
        // }
        // print_results("NTT_16: ", test, NTT_TESTS);

        // for(i=0; i<NTT_TESTS; i++) {
        //     test[i] = cpucycles();
        //     poly_ntt(&co1);
        // }
        // print_results("NTT: ", test, NTT_TESTS);
        // Kyber_poly_ntt(co1_Kyber);
        // Kyber_poly_ntt(co2_Kyber);
        poly_ntt(&co1);
        poly_ntt(&co2);
        poly_ntt_16(&a);
        poly_ntt_16(&b);
        

/*Test whether file_ntt equal to file_ntt16*/
/*
        for(i = 0; i < KYBER_N; i++) {
          while(a.coeffs[i*16] >= KYBER_Q ) {
            a.coeffs[i*16] -= KYBER_Q;
          }
          while(a.coeffs[i*16] < (-KYBER_Q) ) {
            a.coeffs[i*16] += KYBER_Q;
          }
          if(a.coeffs[i*16] < 0){
            a.coeffs[i*16] += KYBER_Q;
          }
          if(co1_Kyber[0][i] < 0){
            co1_Kyber[0][i] += KYBER_Q;
          }
          if(co1_Kyber[0][i] >= KYBER_Q){
            co1_Kyber[0][i] -= KYBER_Q;
          }
        }
*/


/*Basemul operation*/
        // for(i=0; i<NTT_TESTS; i++) {
        //     test[i] = cpucycles();
        //     poly_basemul_montgomery(&r, &co1, &co2);
        // }
        // print_results("Basemul: ", test, NTT_TESTS);
        
        // for(i=0; i<NTT_TESTS; i++) {
        //     test[i] = cpucycles();
        //     poly_basemul_montgomery_16(&r_16, &a, &b);
        // }
        // print_results("Basemul_16: ", test, NTT_TESTS);

        // Kyber_poly_basemul_montgomery(r_Kyber, co1_Kyber, co2_Kyber);
        poly_basemul_montgomery(&r, &co1, &co2);
        poly_basemul_montgomery_16(&r_16, &a, &b);

        

/*Inverse NTT Operation*/
        // for(i=0; i<NTT_TESTS; i++) {
        //     test[i] = cpucycles();
        //     poly_invntt_tomont(&r);
        // }
        // print_results("Invntt: ", test, NTT_TESTS);
        
        // for(i=0; i<NTT_TESTS; i++) {
        //     test[i] = cpucycles();
        //     poly_invntt_tomont_16(&r_16);
        // }
        // print_results("Invntt_16: ", test, NTT_TESTS);
        // Kyber_poly_invntt_tomont(r_Kyber);
        poly_invntt_tomont(&r);
        poly_invntt_tomont_16(&r_16);


/*Output the results into files. Only print the first way of 16-way*/
        for(k = 0; k < KYBER_N; k++){ 
          // fprintf(fn, "%7d ", co1.coeffs[k]);
          // fprintf(fn_16, "%7d ", a.coeffs[k*16]);
          // fprintf(fb, "%7d ", r_Kyber->coeffs[k]);
          // fprintf(fb_16, "%7d ", r_16.coeffs[k*16]);
          fprintf(finvn, "%7d ", r.coeffs[k]);
          fprintf(finvn_16, "%7d ", r_16.coeffs[k*16]);
          // fprintf(finvn, "%7d ", r_Kyber->coeffs[k]);
          // fprintf(finvn_16, "%7d ", r_16.coeffs[k*16]);


          fputs("\n", fn);
          fputs("\n", fn_16);
          fputs("\n", fb);
          fputs("\n", fb_16);
          fputs("\n", finvn);
          fputs("\n", finvn_16);
        }
        fputs("\n", fn);
        fputs("\n", fn_16);
        fputs("\n", fb);
        fputs("\n", fb_16);
        fputs("\n", finvn);
        fputs("\n", finvn_16);

    }



    
    fclose(f);
    fclose(fn);
    fclose(fn_16);
    fclose(fb);
    fclose(fb_16);
    fclose(finvn);
    fclose(finvn_16);

    return 0;
}
