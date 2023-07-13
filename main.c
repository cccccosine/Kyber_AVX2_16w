#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "indcpa_16.h"
#include "kem_16.h"
#include "poly_16.h"
#include "polyvec_16.h"
#include "clocks.h"
#include "randombytes.h"
#include "symmetric.h"
#include "cpucycles.h"
#include "speed_print.h"


#define all_function_test 1
#define indcpa_keypair_flag 1
#define indcpa_enc_flag 1
#define indcpa_dec_flag 1
#define kem_keypair_flag 1
#define kem_enc_flag 1
#define kem_dec_flag 1


int main()
{
    int i, j;
    uint8_t *pk = (uint8_t *)malloc(KYBER_PUBLICKEYBYTES);
    uint8_t *sk = (uint8_t *)malloc(KYBER_SECRETKEYBYTES);
    uint8_t *ct = (uint8_t *)malloc(KYBER_CIPHERTEXTBYTES);
    uint8_t *ctseq = (uint8_t *)malloc(KYBER_CIPHERTEXTBYTES);
    uint8_t *ss = (uint8_t *)malloc(KYBER_SSBYTES*16);
    uint8_t *c = (uint8_t *)malloc(KYBER_INDCPA_BYTES);
    uint8_t m[KYBER_INDCPA_MSGBYTES * 16];
    uint8_t coins[KYBER_SYMBYTES] = {1};
    keccak_state state;
    keccakx4_state statex4;
    uint8_t buffer[168*32];

#ifdef all_function_test
#define gen_a(A, B) gen_matrix(A, B, 0)
#define gen_at(A, B) gen_matrix(A, B, 1)

    uint8_t buf[2 * KYBER_SYMBYTES] = {0};
    const uint8_t *publicseed = buf;
    const uint8_t *noiseseed = buf + KYBER_SYMBYTES;
    uint8_t r[320 * 16];
    polyvec_16 a[KYBER_K], skpv, e, pkpv, b;
    poly_16 v, k, epp, mp;


    // oper_second_n(while (0), NTT_16w, ntt_avx_16(v.vec, qdata_16.vec),
    //               200000, 16);
    // oper_second_n(while (0), INTT_16w, invntt_avx_16(v.vec, qdata_16.vec),
    //               200000, 16);
    // oper_second_n(while (0), basemul_16w, basemul_avx_16(v.vec, v.vec, v.vec, qdata_16.vec),
    //               200000, 16);
    // oper_second_n(while (0), poly_basemul_montgomery, poly_basemul_montgomery(&v, &k, &epp),
    //               200000, 16);
    // oper_second_n(while (0), polyvec_ntt, polyvec_ntt(&skpv),
    //               200000, 16);
    // oper_second_n(while (0), polyvec_basemul_acc_montgomery, polyvec_basemul_acc_montgomery(&pkpv.vec[0], &a[0], &skpv),
    //               20000000, 1);
    // oper_second_n(while (0), polyvec_invntt_tomont, polyvec_invntt_tomont(&b),
    //               200000, 1);
    // oper_second_n(while (0), shake128_absorb_once, shake128_absorb_once(&state, buffer, 168),
    //               200000, 1);
    // oper_second_n(while (0), shake128_absorb_once, shake128_absorb_once(&state, buffer, 32),
    //               200000, 1);
    // oper_second_n(while (0), shake128_squeezeblocks, shake128_squeezeblocks(buffer, 1, &state),
    //               200000, 1);
    // oper_second_n(while (0), shake128x4_absorb_once, shake128x4_absorb_once(&statex4, buffer, buffer+1, buffer+2, buffer+3, 168),
    //               200000, 1);
    // oper_second_n(while (0), shake128x4_absorb_once, shake128x4_absorb_once(&statex4, buffer, buffer+1, buffer+2, buffer+3, 32),
    //               200000, 1);
    // oper_second_n(while (0), shake128x4_squeezeblocks, shake128x4_squeezeblocks(buffer, buffer+5, buffer+10, buffer+15, 1, &statex4),
    //               200000, 1);


#endif

#ifdef indcpa_keypair_flag

    oper_second_n(while (0), Kyber_AVX2_16w_indcpa_keypair, indcpa_keypair(pk, sk),
                  200000, 16);

    // FILE *f = fopen("test_indcpakeypair.txt", "w+");
    // if (f == NULL)
    // {
    //     printf("Fail to open test_indcpakeypair.txt!");
    //     fclose(f);
    //     return -1;
    // }

    // // indcpa_keypair(pk, sk);

    // for (int i = 0; i < KYBER_INDCPA_PUBLICKEYBYTES/16-2; i++)
    // {
    //     for(int j = 0; j < 16; j++) {
    //         // fprintf(f, "%7d", pk[i*16+j]);
    //         fprintf(f, "%7d", sk[i*16+j]);
    //     }
    //     // fprintf(f, "%7d%7d", pk[i], pk[i + 384]);
    //     fputs("\n", f);
    // }

    // fclose(f);

#endif

#ifdef indcpa_enc_flag

    for (i = 0; i < KYBER_INDCPA_MSGBYTES; i++)
    {
        for(j = 0; j < 16; j++)
        {
            m[i*16+j] = i;
        }
    }

    // FILE *f1 = fopen("test_indcpaenc.txt", "w+");
    // if (f1 == NULL)
    // {
    //     printf("Fail to open test_indcpaenc.txt!");
    //     fclose(f1);
    //     return -1;
    // }

    oper_second_n(while (0), Kyber_AVX2_16w_indcpa_enc, indcpa_enc(c, m, pk, coins),
                  200000, 16);

    // indcpa_enc(c, m, pk, coins);

    // ct_formseq(c, ctseq);

    // for (i = 0; i < (KYBER_INDCPA_BYTES/16); i++)
    // {
    //     fprintf(f1, "%7d %7d", ctseq[i], ctseq[i+KYBER_INDCPA_BYTES/16]);
    //     fputs("\n", f1);
    // }

    // for (i = 0; i < (KYBER_INDCPA_BYTES/16); i++)
    // {
    //     for (int j = 0; j < 16; j++)
    //     {
    //         fprintf(f1, "%7d", c[i*16+j]);
    //     }
    //     fputs("\n", f1);
    // }

    // fclose(f1);
#endif

#ifdef indcpa_dec_flag

    // FILE *f2 = fopen("test_indcpadec.txt", "w+");
    // if (f2 == NULL)
    // {
    //     printf("Fail to open test_indcpadec.txt!");
    //     fclose(f2);
    //     return -1;
    // }

    oper_second_n(while (0), Kyber_AVX2_16w_indcpa_dec, indcpa_dec(m, c, sk),
                  200000, 16);

    // indcpa_dec(m, c, sk);

    // for(int i = 0; i < KYBER_POLYVECCOMPRESSEDBYTES/16; i++) {
    //     for(int j = 0; j < 16; j++) {
    //         fprintf(f2, "%7d", b[i*16+j]);
    //     }
    //     fputs("\n", f2);
    // }

    // for (int i = 0; i < KYBER_INDCPA_MSGBYTES; i++)
    // {
    //     for (int j = 0; j < 16; j++)
    //     {
    //         fprintf(f2, "%7d", m[i * 16 + j]);
    //     }
    //     fputs("\n", f2);
    // }

    // fclose(f2);
#endif

#ifdef kem_keypair_flag
    oper_second_n(while (0), crypto_kem_keypair_16w, crypto_kem_keypair(pk, sk),
                  200000, 16);
    // crypto_kem_keypair(pk, sk);

#endif

#ifdef kem_enc_flag
    oper_second_n(while (0), crypto_kem_enc_16w, crypto_kem_enc(ct, ss, pk),
                  200000, 16);
    // crypto_kem_enc(ct, ss, pk);

    // FILE *f4 = fopen("test_kem_enc_ss.txt", "w+");
    // if (f4 == NULL)
    // {
    //     printf("Fail to open test_kem_enc_ss.txt!");
    //     fclose(f4);
    //     return -1;
    // }

    // for (int i = 0; i < 32*16; i++)
    // {
    //     fprintf(f4, "%7d", ss[i]);
    //     fputs("\n", f4);
    // }

    // fclose(f4);

#endif

#ifdef kem_dec_flag
    oper_second_n(while (0), crypto_kem_dec_16w, crypto_kem_dec(ss, ct, sk),
                  200000, 16);
    // crypto_kem_dec(ss, ct, sk);

    // FILE *f5 = fopen("test_kem_dec_ss.txt", "w+");
    // if (f5 == NULL)
    // {
    //     printf("Fail to open test_kem_dec_ss.txt!");
    //     fclose(f5);
    //     return -1;
    // }

    // for (int i = 0; i < 32*16; i++)
    // {
    //     fprintf(f5, "%7d", ss[i]);
    //     fputs("\n", f5);
    // }

    // fclose(f5);

#endif

    free(pk);
    free(sk);
    free(c);
    free(ct);
    free(ctseq);
    free(ss);

    return 0;
}