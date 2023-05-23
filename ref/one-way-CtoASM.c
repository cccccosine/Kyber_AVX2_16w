#include "16-way-ntt-const.h"

//coeffients of the polynomial
//这里的系数数组应为调用ntt时传进来的参数
//int16_t coeffs[16][256];
int16_t coeffs[256];

//Montgomery R
int R = 2<<15;

int i;

//16 ymm registers
    // int16_t ymm0[16];
    // int16_t ymm1[16];
    // int16_t ymm2[16];
    // int16_t ymm3[16];
    // int16_t ymm4[16];
    // int16_t ymm5[16];
    // int16_t ymm6[16];
    // int16_t ymm7[16];
    // int16_t ymm8[16];
    // int16_t ymm9[16];
    // int16_t ymm10[16];
    // int16_t ymm11[16];
    // int16_t ymm12[16];
    // int16_t ymm13[16];
    // int16_t ymm14[16];
    // int16_t ymm15[16];


//只看16个寄存器中的第一位
int16_t y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11, y12, y13, y14, y15;




void mul(int16_t rh0, int16_t rh1, int16_t rh2, int16_t rh3, int off) {

    //vpmullw		%ymm\zl0,%ymm\rh0,%ymm12
    y15 = qdata[off];
    y12 = (rh0*y15)%R;
    //vpmullw		%ymm\zl0,%ymm\rh1,%ymm13
    y15 = qdata[off + 1];
    y13 = (rh1*y15)%R;

/************************************************/

    //vpmullw		%ymm\zl1,%ymm\rh2,%ymm14
    y15 = qdata[off + 2];
    y14 = (rh2*y15)%R;
    //vpmullw		%ymm\zl1,%ymm\rh3,%ymm15
    y15 = qdata[off + 3];
    y15 = (rh3*y15)%R;
    
/************************************************/

    //vpmulhw		%ymm\zh0,%ymm\rh0,%ymm\rh0
    y2 = qdata[off + 4];
    rh0 = (rh0*y2)/R;
    //vpmulhw		%ymm\zh0,%ymm\rh1,%ymm\rh1
    y2 = qdata[off + 5];
    rh1 = (rh1*y2)/R;
    
/************************************************/

    //vpmulhw		%ymm\zh1,%ymm\rh2,%ymm\rh2
    y2 = qdata[off + 6];
    rh2 = (rh2*y2)/R;
    //vpmulhw		%ymm\zh1,%ymm\rh3,%ymm\rh3
    y2 = qdata[off + 7];
    rh3 = (rh3*y2)/R;

}


void reduce() {

    //vpmulhw		%ymm0,%ymm12,%ymm12
    y12 = (y12*y0)/R;
    //vpmulhw		%ymm0,%ymm13,%ymm13
    y13 = (y13*y0)/R;
    
/************************************************/

    //vpmulhw		%ymm0,%ymm14,%ymm14
    y14 = (y14*y0)/R;
    //vpmulhw		%ymm0,%ymm15,%ymm15
    y15 = (y15*y0)/R;

}


void update(int16_t rln, int16_t rl0, int16_t rl1, int16_t rl2, int16_t rl3,
            int16_t rh0, int16_t rh1, int16_t rh2, int16_t rh3) {

    //vpaddw		%ymm\rh0,%ymm\rl0,%ymm\rln
    rln = rl0+rh0;
    //vpsubw		%ymm\rh0,%ymm\rl0,%ymm\rh0
    rh0 = rl0-rh0;
    //vpaddw		%ymm\rh1,%ymm\rl1,%ymm\rl0
    rl0 = rl1+rh1;
    
/************************************************/

    //vpsubw		%ymm\rh1,%ymm\rl1,%ymm\rh1
    rh1 = rl1-rh1;
    //vpaddw		%ymm\rh2,%ymm\rl2,%ymm\rl1
    rl1 = rl2+rh2;
    //vpsubw		%ymm\rh2,%ymm\rl2,%ymm\rh2
    rh2 = rl2-rh2;
    
/************************************************/

    //vpaddw		%ymm\rh3,%ymm\rl3,%ymm\rl2
    rl2 = rl3+rh3;
    //vpsubw		%ymm\rh3,%ymm\rl3,%ymm\rh3
    rh3 = rl3-rh3;
    
/************************************************/
  
    //vpsubw		%ymm12,%ymm\rln,%ymm\rln
    rln = rln-y12;
    //vpaddw		%ymm12,%ymm\rh0,%ymm\rh0
    rh0 = rh0+y12;
    //vpsubw		%ymm13,%ymm\rl0,%ymm\rl0
    rl0 = rl0-y13;
    
/************************************************/

    //vpaddw		%ymm13,%ymm\rh1,%ymm\rh1
    rh1 = rh1+y13;
    //vpsubw		%ymm14,%ymm\rl1,%ymm\rl1
    rl1 = rl1-y14;
    //vpaddw		%ymm14,%ymm\rh2,%ymm\rh2
    rh2 = rh2+y14;
    
/************************************************/

    //vpsubw		%ymm15,%ymm\rl2,%ymm\rl2
    rl2 = rl2-y15;
    //vpaddw		%ymm15,%ymm\rh3,%ymm\rh3
    rh3 = rh3+y15;
}


void levels0t2() {
    for(i = 0; i < 32; i++) {
        //level0
        y8 = coeffs[128 + i];
        y9 = coeffs[160 + i];
        y10 = coeffs[192 + i];
        y11 = coeffs[224 + i];

        mul(y8, y9, y10, y11, 0);

        y4 = coeffs[i];
        y5 = coeffs[32 + i];
        y6 = coeffs[64 + i];
        y7 = coeffs[96 + i];

        reduce();//y12~y15在mul中计算过
        update(y3, y4, y5, y6, y7, y8, y9, y10, y11);

        //level1
        //可将vmov y15，y2 集成进mul函数中
        mul(y5, y10, y6, y11, 8);

        reduce();
        update(y7, y3, y8, y4, y9, y5, y10, y6, y11);

        //level2
        mul(y8, y6, y4, y11, 16);

        reduce();
        update(y9, y7, y5, y3, y10, y8, y6, y4, y11);
        
        coeffs[i] = y9;
        coeffs[i + 32] = y8;
        coeffs[i + 64] = y7;
        coeffs[i + 96] = y6;
        coeffs[i + 128] = y5;
        coeffs[i + 160] = y4;
        coeffs[i + 192] = y3;
        coeffs[i + 224] = y11;
        
    }
}


levels3t5() {
    int j;
    for(j = 0; j < 256; j = j + 32) {
        for(i = 0; i < 4; i = i + j) {
            //level3
            y8 = coeffs[16+ i];
            y9 = coeffs[20 + i];
            y10 = coeffs[24 + i];
            y11 = coeffs[28 + i];

            mul(y8, y9, y10, y11, 24*(j/32+1));//mul的off系数需要+i,即与i有关

            y4 = coeffs[i];
            y5 = coeffs[4 + i];
            y6 = coeffs[8 + i];
            y7 = coeffs[12 + i];

            reduce();
            update(y3, y4, y5, y6, y7, y8, y9, y10, y11);

            //level4
            mul(y5, y10, y6, y11, 24*(j/32+1)+8);

            reduce();
            update(y7, y3, y8, y4, y9, y5, y10, y6, y11);

            //level5
            mul(y8, y6, y4, y11, 24*(j/32+1)+16);

            reduce();
            update(y9, y7, y5, y3, y10, y8, y6, y4, y11);

            coeffs[i] = y9;
            coeffs[i + 4] = y8;
            coeffs[i + 8] = y7;
            coeffs[i + 12] = y6;
            coeffs[i + 16] = y5;
            coeffs[i + 20] = y4;
            coeffs[i + 24] = y3;
            coeffs[i + 28] = y11;

        }
    }
}


void level6() {
    for(i = 0; i < 256; i = i+8) {
        //level6
        y8 = coeffs[2 + i];
        y9 = coeffs[3 + i];
        y10 = coeffs[6 + i];
        y11 = coeffs[7 + i];

        mul(y8, y9, y10, y11, 216+i);

        y4 = coeffs[i];
        y5 = coeffs[1 + i];
        y6 = coeffs[4 + i];
        y7 = coeffs[5 + i];

        reduce();
        update(y3, y4, y5, y6, y7, y8, y9, y10, y11);

        coeffs[i] = y3;
        coeffs[i + 1] = y8;
        coeffs[i + 2] = y4;
        coeffs[i + 3] = y9;
        coeffs[i + 4] = y5;
        coeffs[i + 5] = y10;
        coeffs[i + 6] = y6;
        coeffs[i + 7] = y11;

    }
}



void ntt_avx () {
    
    //vmovdqa		_16XQ*2(%rsi),%y0
    y0 = KYBER_Q;

    levels0t2();
    
    levels3t5();

    level6();


}



int main() {

    ntt_avx();

    return 0;
}
