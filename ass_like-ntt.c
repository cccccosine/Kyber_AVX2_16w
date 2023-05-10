#include "consts.h"


//coeffients of the polynomial
//这里的系数数组应为调用ntt时传进来的参数
int16_t coeffs[256];

//Montgomery R
int R = 2<<15;

int i;

//16 ymm registers
    int16_t ymm0[16];
    int16_t ymm1[16];
    int16_t ymm2[16];
    int16_t ymm3[16];
    int16_t ymm4[16];
    int16_t ymm5[16];
    int16_t ymm6[16];
    int16_t ymm7[16];
    int16_t ymm8[16];
    int16_t ymm9[16];
    int16_t ymm10[16];
    int16_t ymm11[16];
    int16_t ymm12[16];
    int16_t ymm13[16];
    int16_t ymm14[16];
    int16_t ymm15[16];


void mul(int16_t* rh0, int16_t* rh1, int16_t* rh2, int16_t* rh3, 
         int16_t* zl0, int16_t* zl1, int16_t* zh0, int16_t* zh1) {

    //vpmullw		%ymm\zl0,%ymm\rh0,%ymm12
    for(i = 0; i < 16; i++) {
        ymm12[i] = (rh0[i]*zl0[i])%R;
    } 
    //vpmullw		%ymm\zl0,%ymm\rh1,%ymm13
    for(i = 0; i < 16; i++) {
        ymm13[i] = (rh1[i]*zl0[i])%R;
    } 

/************************************************/

    //vpmullw		%ymm\zl1,%ymm\rh2,%ymm14
    for(i = 0; i < 16; i++) {
        ymm14[i] = (rh2[i]*zl1[i])%R;
    } 
    //vpmullw		%ymm\zl1,%ymm\rh3,%ymm15
    for(i = 0; i < 16; i++) {
        ymm15[i] = (rh3[i]*zl1[i])%R;
    }
    
/************************************************/

    //vpmulhw		%ymm\zh0,%ymm\rh0,%ymm\rh0
    for(i = 0; i < 16; i++) {
        rh0[i] = (rh0[i]*zh0[i])/R;
    }
    //vpmulhw		%ymm\zh0,%ymm\rh1,%ymm\rh1
    for(i = 0; i < 16; i++) {
        rh1[i] = (rh1[i]*zh0[i])/R;
    }
    
/************************************************/

    //vpmulhw		%ymm\zh1,%ymm\rh2,%ymm\rh2
    for(i = 0; i < 16; i++) {
        rh2[i] = (rh2[i]*zh1[i])/R;
    }
    //vpmulhw		%ymm\zh1,%ymm\rh3,%ymm\rh3
    for(i = 0; i < 16; i++) {
        rh3[i] = (rh3[i]*zh1[i])/R;
    }

}


void reduce() {

    //vpmulhw		%ymm0,%ymm12,%ymm12
    for(i = 0; i < 16; i++) {
        ymm12[i] = (ymm12[i]*ymm0[i])/R;
    }
    //vpmulhw		%ymm0,%ymm13,%ymm13
    for(i = 0; i < 16; i++) {
        ymm13[i] = (ymm13[i]*ymm0[i])/R;
    }
    
/************************************************/

    //vpmulhw		%ymm0,%ymm14,%ymm14
    for(i = 0; i < 16; i++) {
        ymm14[i] = (ymm14[i]*ymm0[i])/R;
    }
    //vpmulhw		%ymm0,%ymm15,%ymm15
    for(i = 0; i < 16; i++) {
        ymm15[i] = (ymm15[i]*ymm0[i])/R;
    }

}


void update(int16_t* rln, int16_t* rl0, int16_t* rl1, int16_t* rl2, int16_t* rl3,
            int16_t* rh0, int16_t* rh1, int16_t* rh2, int16_t* rh3) {

    //vpaddw		%ymm\rh0,%ymm\rl0,%ymm\rln
    for(i = 0; i < 16; i++) {
        rln[i] = rl0[i]+rh0[i];
    }
    //vpsubw		%ymm\rh0,%ymm\rl0,%ymm\rh0
    for(i = 0; i < 16; i++) {
        rh0[i] = rl0[i]-rh0[i];
    }
    //vpaddw		%ymm\rh1,%ymm\rl1,%ymm\rl0
    for(i = 0; i < 16; i++) {
        rl0[i] = rl1[i]+rh1[i];
    }
    
/************************************************/

    //vpsubw		%ymm\rh1,%ymm\rl1,%ymm\rh1
    for(i = 0; i < 16; i++) {
        rh1[i] = rl1[i]-rh1[i];
    }
    //vpaddw		%ymm\rh2,%ymm\rl2,%ymm\rl1
    for(i = 0; i < 16; i++) {
        rl1[i] = rl2[i]+rh2[i];
    }
    //vpsubw		%ymm\rh2,%ymm\rl2,%ymm\rh2
    for(i = 0; i < 16; i++) {
        rh2[i] = rl2[i]-rh2[i];
    }
    
/************************************************/

    //vpaddw		%ymm\rh3,%ymm\rl3,%ymm\rl2
    for(i = 0; i < 16; i++) {
        rl2[i] = rl3[i]+rh3[i];
    }
    //vpsubw		%ymm\rh3,%ymm\rl3,%ymm\rh3
    for(i = 0; i < 16; i++) {
        rh3[i] = rl3[i]-rh3[i];
    }
    
/************************************************/
  
    //vpsubw		%ymm12,%ymm\rln,%ymm\rln
    for(i = 0; i < 16; i++) {
        rln[i] = rln[i]-ymm12[i];
    }
    //vpaddw		%ymm12,%ymm\rh0,%ymm\rh0
    for(i = 0; i < 16; i++) {
        rh0[i] = rh0[i]+ymm12[i];
    }
    //vpsubw		%ymm13,%ymm\rl0,%ymm\rl0
    for(i = 0; i < 16; i++) {
        rl0[i] = rl0[i]-ymm13[i];
    }
    
/************************************************/

    //vpaddw		%ymm13,%ymm\rh1,%ymm\rh1
    for(i = 0; i < 16; i++) {
        rh1[i] = rh1[i]+ymm13[i];
    }
    //vpsubw		%ymm14,%ymm\rl1,%ymm\rl1
    for(i = 0; i < 16; i++) {
        rl1[i] = rl1[i]-ymm14[i];
    }
    //vpaddw		%ymm14,%ymm\rh2,%ymm\rh2
    for(i = 0; i < 16; i++) {
        rh2[i] = rh2[i]+ymm14[i];
    }
    
/************************************************/

    //vpsubw		%ymm15,%ymm\rl2,%ymm\rl2
    for(i = 0; i < 16; i++) {
        rl2[i] = rl2[i]-ymm15[i];
    }
    //vpaddw		%ymm15,%ymm\rh3,%ymm\rh3
    for(i = 0; i < 16; i++) {
        rh3[i] = rh3[i]+ymm15[i];
    }

}


void shuffle8(int16_t* r0, int16_t* r1, int16_t* r2, int16_t* r3) {
    //vperm2i128	$0x20,%ymm\r1,%ymm\r0,%ymm\r2
    //0x20 = (0010 0000)
    for(i = 0; i < 8; i++) {
        r2[i] = r0[i];
        r2[i+8] = r1[i];
    }
    //vperm2i128	$0x31,%ymm\r1,%ymm\r0,%ymm\r3
    //0x31 = (0011 0001)
    for(i = 0; i < 8; i++) {
        r3[i] = r0[i+8];
        r3[i+8] = r1[i+8];
    }

}


void shuffle4(int16_t* r0, int16_t* r1, int16_t* r2, int16_t* r3) {
    //vpunpcklqdq	%ymm\r1,%ymm\r0,%ymm\r2
    for(i = 0; i < 4; i++) {
        r2[i] = r0[i];
        r2[i+4] = r1[i];
        r2[i+8] = r0[i+8];
        r2[i+12] = r1[i+8];
    }
    //vpunpckhqdq	%ymm\r1,%ymm\r0,%ymm\r3
    for(i = 0; i < 4; i++) {
        r3[i] = r0[i+4];
        r3[i+4] = r1[i+4];
        r3[i+8] = r0[i+12];
        r3[i+12] = r1[i+12];
    }

}


void shuffle2(int16_t* r0, int16_t* r1, int16_t* r2, int16_t* r3) {
    //vmovsldup	%ymm\r1,%ymm\r2
    for(i = 0; i < 2; i++) {
        r2[i] = r1[i];
        r2[i+2] = r1[i];
        r2[i+4] = r1[i+4];
        r2[i+6] = r1[i+4];
        r2[i+8] = r1[i+8];
        r2[i+10] = r1[i+8];
        r2[i+12] = r1[i+12];
        r2[i+14] = r1[i+12];
    }
    //vpblendd	$0xAA,%ymm\r2,%ymm\r0,%ymm\r2
    //0xAA = (1010 1010)
    for(i = 0; i < 2; i++) {
        r2[i] = r0[i];
        r2[i+2] = r2[i+2];
        r2[i+4] = r0[i+4];
        r2[i+6] = r2[i+6];
        r2[i+8] = r0[i+8];
        r2[i+10] = r2[i+10];
        r2[i+12] = r0[i+12];
        r2[i+14] = r2[i+14];
    }
    //vpsrlq		$32,%ymm\r0,%ymm\r0
    for(i = 0; i < 16; i = i + 4) {
        r0[i] = r0[i+2];
        r0[i+1] = r0[i+3];
        r0[i+2] = 0;
        r0[i+3] = 0;   
    }
    //vpblendd	$0xAA,%ymm\r1,%ymm\r0,%ymm\r3
    //0xAA = (1010 1010)
    for(i = 0; i < 2; i++) {
        r3[i] = r0[i];
        r3[i+2] = r1[i+2];
        r3[i+4] = r0[i+4];
        r3[i+6] = r1[i+6];
        r3[i+8] = r0[i+8];
        r3[i+10] = r1[i+10];
        r3[i+12] = r0[i+12];
        r3[i+14] = r1[i+14];
    }

}


void shuffle1(int16_t* r0, int16_t* r1, int16_t* r2, int16_t* r3) {
    //vpslld		$16,%ymm\r1,%ymm\r2
    for(i = 0; i < 16; i = i + 2) {
        r2[i] = 0;
        r2[i+1] = r1[i];   
    }
    //vpblendw	$0xAA,%ymm\r2,%ymm\r0,%ymm\r2
    //0xAA = (1010 1010)
    r2[0] = r0[0];
    r2[1] = r2[1];
    r2[2] = r0[2];
    r2[3] = r2[3];
    r2[4] = r0[4];
    r2[5] = r2[5];
    r2[6] = r0[6];
    r2[7] = r2[7];
    r2[8] = r0[8];
    r2[9] = r2[9];
    r2[10] = r0[10];
    r2[11] = r2[11];
    r2[12] = r0[12];
    r2[13] = r2[13];
    r2[14] = r0[14];
    r2[15] = r2[15];
    //vpsrld		$16,%ymm\r0,%ymm\r0
    for(i = 0; i < 16; i = i + 2) {
        r0[i] = r0[i+1];
        r0[i+1] = 0;  
    }
    //vpblendw	$0xAA,%ymm\r1,%ymm\r0,%ymm\r3
    //0xAA = (1010 1010)
    r3[0] = r0[0];
    r3[1] = r1[1];
    r3[2] = r0[2];
    r3[3] = r1[3];
    r3[4] = r0[4];
    r3[5] = r1[5];
    r3[6] = r0[6];
    r3[7] = r1[7];
    r3[8] = r0[8];
    r3[9] = r1[9];
    r3[10] = r0[10];
    r3[11] = r1[11];
    r3[12] = r0[12];
    r3[13] = r1[13];
    r3[14] = r0[14];
    r3[15] = r1[15];

}


void level0(int off) {
    int j;
    //vpbroadcastq	(_ZETAS_EXP+0)*2(%rsi),%ymm15
    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            ymm15[i*4 + j] = qdata[_ZETAS_EXP + j];
        }
    }
    //vmovdqa		(64*\off+128)*2(%rdi),%ymm8
    for(i = 0; i < 16; i++) {
        ymm8[i] = coeffs[64*off + 128 + i];
    }
    //vmovdqa		(64*\off+144)*2(%rdi),%ymm9
    for(i = 0; i < 16; i++) {
        ymm9[i] = coeffs[64*off + 144 + i];
    }
    //vmovdqa		(64*\off+160)*2(%rdi),%ymm10
    for(i = 0; i < 16; i++) {
        ymm10[i] = coeffs[64*off + 160 + i];
    }
    //vmovdqa		(64*\off+176)*2(%rdi),%ymm11
    for(i = 0; i < 16; i++) {
        ymm11[i] = coeffs[64*off + 176 + i];
    }
    //vpbroadcastq	(_ZETAS_EXP+4)*2(%rsi),%ymm2
    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            ymm2[i*4 + j] = qdata[_ZETAS_EXP+4 + j];
        }
    }
    
/************************************************/

    mul(ymm8, ymm9, ymm10, ymm11, ymm15, ymm15, ymm2, ymm2);
    
/************************************************/

    //vmovdqa		(64*\off+  0)*2(%rdi),%ymm4
    for(i = 0; i < 16; i++) {
        ymm4[i] = coeffs[64*off + 0 + i];
    }
    //vmovdqa		(64*\off+ 16)*2(%rdi),%ymm5
    for(i = 0; i < 16; i++) {
        ymm5[i] = coeffs[64*off + 16 + i];
    }
    //vmovdqa		(64*\off+ 32)*2(%rdi),%ymm6
    for(i = 0; i < 16; i++) {
        ymm6[i] = coeffs[64*off + 32 + i];
    }
    //vmovdqa		(64*\off+ 48)*2(%rdi),%ymm7
    for(i = 0; i < 16; i++) {
        ymm7[i] = coeffs[64*off + 48 + i];
    }
    
/************************************************/

    reduce();
    update(ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, ymm9, ymm10, ymm11);
    
/************************************************/

    //vmovdqa		%ymm3,(64*\off+  0)*2(%rdi)
    for(i = 0; i < 16; i++) {
        coeffs[64*off + 0 + i] = ymm3[i];
    }
    //vmovdqa		%ymm4,(64*\off+ 16)*2(%rdi)
    for(i = 0; i < 16; i++) {
        coeffs[64*off + 16 + i] = ymm4[i];
    }
    //vmovdqa		%ymm5,(64*\off+ 32)*2(%rdi)
    for(i = 0; i < 16; i++) {
        coeffs[64*off + 32 + i] = ymm5[i];
    }
    //vmovdqa		%ymm6,(64*\off+ 48)*2(%rdi)
    for(i = 0; i < 16; i++) {
        coeffs[64*off + 48 + i] = ymm6[i];
    }
    //vmovdqa		%ymm8,(64*\off+128)*2(%rdi)
    for(i = 0; i < 16; i++) {
        coeffs[64*off + 128 + i] = ymm8[i];
    }
    //vmovdqa		%ymm9,(64*\off+144)*2(%rdi)
    for(i = 0; i < 16; i++) {
        coeffs[64*off + 144 + i] = ymm9[i];
    }
    //vmovdqa		%ymm10,(64*\off+160)*2(%rdi)
    for(i = 0; i < 16; i++) {
        coeffs[64*off + 160 + i] = ymm10[i];
    }
    //vmovdqa		%ymm11,(64*\off+176)*2(%rdi)
    for(i = 0; i < 16; i++) {
        coeffs[64*off + 176 + i] = ymm11[i];
    }

}


void levels1t6(int off) {

    /* level1 */
    //vmovdqa		(_ZETAS_EXP+224*\off+16)*2(%rsi),%ymm15
    for(i = 0; i < 16; i++) {
        ymm15[i] = qdata[_ZETAS_EXP+224*off + 16 + i];
    }
    //vmovdqa		(128*\off+ 64)*2(%rdi),%ymm8
    for(i = 0; i < 16; i++) {
        ymm8[i] = coeffs[128*off + 64 + i];
    }
    //vmovdqa		(128*\off+ 80)*2(%rdi),%ymm9
    for(i = 0; i < 16; i++) {
        ymm9[i] = coeffs[128*off + 80 + i];
    }
    //vmovdqa		(128*\off+ 96)*2(%rdi),%ymm10
    for(i = 0; i < 16; i++) {
        ymm10[i] = coeffs[128*off + 96 + i];
    }
    //vmovdqa		(128*\off+112)*2(%rdi),%ymm11
    for(i = 0; i < 16; i++) {
        ymm11[i] = coeffs[128*off + 112 + i];
    }
    //vmovdqa		(_ZETAS_EXP+224*\off+32)*2(%rsi),%ymm2
    for(i = 0; i < 16; i++) {
        ymm2[i] = qdata[_ZETAS_EXP+224*off + 32 + i];
    }

    mul(ymm8, ymm9, ymm10, ymm11, ymm15, ymm15, ymm2, ymm2);

    //vmovdqa		(128*\off+  0)*2(%rdi),%ymm4
    for(i = 0; i < 16; i++) {
        ymm4[i] = coeffs[128*off + 0 + i];
    }
    //vmovdqa		(128*\off+ 16)*2(%rdi),%ymm5
    for(i = 0; i < 16; i++) {
        ymm5[i] = coeffs[128*off + 16 + i];
    }
    //vmovdqa		(128*\off+ 32)*2(%rdi),%ymm6
    for(i = 0; i < 16; i++) {
        ymm6[i] = coeffs[128*off + 32 + i];
    }
    //vmovdqa		(128*\off+ 48)*2(%rdi),%ymm7
    for(i = 0; i < 16; i++) {
        ymm7[i] = coeffs[128*off + 48 + i];
    }

    reduce();
    update(ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, ymm9, ymm10, ymm11);
    
/************************************************/

    /* level 2 */
    shuffle8(ymm5, ymm10, ymm7, ymm10);
    shuffle8(ymm6, ymm11, ymm5, ymm11);

    //vmovdqa		(_ZETAS_EXP+224*\off+48)*2(%rsi),%ymm15
    for(i = 0; i < 16; i++) {
        ymm15[i] = qdata[_ZETAS_EXP+224*off + 48 + i];
    }
    //vmovdqa		(_ZETAS_EXP+224*\off+64)*2(%rsi),%ymm2
    for(i = 0; i < 16; i++) {
        ymm2[i] = qdata[_ZETAS_EXP+224*off + 64 + i];
    }

    mul(ymm7, ymm10, ymm5, ymm11, ymm15, ymm15, ymm2, ymm2);

    shuffle8(ymm3, ymm8, ymm6, ymm8);
    shuffle8(ymm4, ymm9, ymm3, ymm9);

    reduce();
    update(ymm4, ymm6, ymm8, ymm3, ymm9, ymm7, ymm10, ymm5, ymm11);
    
/************************************************/

    /* level 3 */
    shuffle4(ymm8, ymm5, ymm9, ymm5);
    shuffle4(ymm3, ymm11, ymm8, ymm11);

    //vmovdqa		(_ZETAS_EXP+224*\off+80)*2(%rsi),%ymm15
    for(i = 0; i < 16; i++) {
        ymm15[i] = qdata[_ZETAS_EXP+224*off + 80 + i];
    }
    //vmovdqa		(_ZETAS_EXP+224*\off+96)*2(%rsi),%ymm2
    for(i = 0; i < 16; i++) {
        ymm2[i] = qdata[_ZETAS_EXP+224*off + 96 + i];
    }

    mul(ymm9, ymm5, ymm8, ymm11, ymm15, ymm15, ymm2, ymm2);

    shuffle4(ymm4, ymm7, ymm3, ymm7);
    shuffle4(ymm6, ymm10, ymm4, ymm10);

    reduce();
    update(ymm6, ymm3, ymm7, ymm4, ymm10, ymm9, ymm5, ymm8, ymm11);
    
/************************************************/

    /* level 4 */
    shuffle2(ymm7, ymm8, ymm10, ymm8);
    shuffle2(ymm4, ymm11, ymm7, ymm11);

    //vmovdqa		(_ZETAS_EXP+224*\off+112)*2(%rsi),%ymm15
    for(i = 0; i < 16; i++) {
        ymm15[i] = qdata[_ZETAS_EXP+224*off + 112 + i];
    }
    //vmovdqa		(_ZETAS_EXP+224*\off+128)*2(%rsi),%ymm2
    for(i = 0; i < 16; i++) {
        ymm2[i] = qdata[_ZETAS_EXP+224*off + 128 + i];
    }

    mul(ymm10, ymm8, ymm7, ymm11, ymm15, ymm15, ymm2, ymm2);

    shuffle2(ymm6, ymm9, ymm4, ymm9);
    shuffle2(ymm3, ymm5, ymm6, ymm5);

    reduce();
    update(ymm3, ymm4, ymm9, ymm6, ymm5, ymm10, ymm8, ymm7, ymm11);

/************************************************/

    /* level 5 */
    shuffle1(ymm9, ymm7, ymm5, ymm7);
    shuffle1(ymm6, ymm11, ymm9, ymm11);

    //vmovdqa		(_ZETAS_EXP+224*\off+144)*2(%rsi),%ymm15
    for(i = 0; i < 16; i++) {
        ymm15[i] = qdata[_ZETAS_EXP+224*off + 144 + i];
    }
    //vmovdqa		(_ZETAS_EXP+224*\off+160)*2(%rsi),%ymm2
    for(i = 0; i < 16; i++) {
        ymm2[i] = qdata[_ZETAS_EXP+224*off + 160 + i];
    }

    mul(ymm5, ymm7, ymm9, ymm11, ymm15, ymm15, ymm2, ymm2);

    shuffle1(ymm3, ymm10, ymm6, ymm10);
    shuffle1(ymm4, ymm8, ymm3, ymm8);

    reduce();
    update(ymm4, ymm6, ymm10, ymm3, ymm8, ymm5, ymm7, ymm9, ymm11);

/************************************************/

    /* level 6 */  
    //vmovdqa		(_ZETAS_EXP+224*\off+176)*2(%rsi),%ymm14
    for(i = 0; i < 16; i++) {
        ymm14[i] = qdata[_ZETAS_EXP+224*off + 176 + i];
    }
    //vmovdqa		(_ZETAS_EXP+224*\off+208)*2(%rsi),%ymm15
    for(i = 0; i < 16; i++) {
        ymm15[i] = qdata[_ZETAS_EXP+224*off + 208 + i];
    }
    //vmovdqa		(_ZETAS_EXP+224*\off+192)*2(%rsi),%ymm8
    for(i = 0; i < 16; i++) {
        ymm8[i] = qdata[_ZETAS_EXP+224*off + 192 + i];
    }
    //vmovdqa		(_ZETAS_EXP+224*\off+224)*2(%rsi),%ymm2
    for(i = 0; i < 16; i++) {
        ymm2[i] = qdata[_ZETAS_EXP+224*off + 224 + i];
    }

    mul(ymm10, ymm3, ymm9, ymm11, ymm14, ymm15, ymm8, ymm2);

    reduce();
    update(ymm8, ymm4, ymm6, ymm5, ymm7, ymm10, ymm3, ymm9, ymm11);

    //vmovdqa		%ymm8,(128*\off+  0)*2(%rdi)
    for(i = 0; i < 16; i++) {
        coeffs[128*off + 0 + i] = ymm8[i];
    }
    //vmovdqa		%ymm4,(128*\off+ 16)*2(%rdi)
    for(i = 0; i < 16; i++) {
        coeffs[128*off + 16 + i] = ymm4[i];
    }
    //vmovdqa		%ymm10,(128*\off+ 32)*2(%rdi)
    for(i = 0; i < 16; i++) {
        coeffs[128*off + 32 + i] = ymm10[i];
    }
    //vmovdqa		%ymm3,(128*\off+ 48)*2(%rdi)
    for(i = 0; i < 16; i++) {
        coeffs[128*off + 48 + i] = ymm3[i];
    }
    //vmovdqa		%ymm6,(128*\off+ 64)*2(%rdi)
    for(i = 0; i < 16; i++) {
        coeffs[128*off + 64 + i] = ymm6[i];
    }
    //vmovdqa		%ymm5,(128*\off+ 80)*2(%rdi)
    for(i = 0; i < 16; i++) {
        coeffs[128*off + 80 + i] = ymm5[i];
    }
    //vmovdqa		%ymm9,(128*\off+ 96)*2(%rdi)
    for(i = 0; i < 16; i++) {
        coeffs[128*off + 96 + i] = ymm9[i];
    }
    //vmovdqa		%ymm11,(128*\off+112)*2(%rdi)
    for(i = 0; i < 16; i++) {
        coeffs[128*off + 112 + i] = ymm11[i];
    }

}


void ntt_avx () {
    
    //vmovdqa		_16XQ*2(%rsi),%ymm0
    for(i = 0; i < 16; i++) {
        ymm0[i] = qdata[_16XQ+i];
    }

    level0(0);
    level0(1);

    levels1t6(0);
    levels1t6(1);

}


int main() {

    ntt_avx();

    return 0;
}