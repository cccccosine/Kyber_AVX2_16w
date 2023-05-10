#include "ntt_16_consts.h"



.macro mul1 rh0,rh1,rh2,rh3,qnum

vmovdqa		(\qnum    )*2(%rsi),%ymm15
vpmullw		%ymm15,%ymm\rh0,%ymm12
vpmullw		%ymm15,%ymm\rh1,%ymm13
vpmullw		%ymm15,%ymm\rh2,%ymm14
vpmullw		%ymm15,%ymm\rh3,%ymm15

vmovdqa		(\qnum+ 16)*2(%rsi),%ymm2
vpmulhw		%ymm2,%ymm\rh0,%ymm\rh0
vpmulhw		%ymm2,%ymm\rh1,%ymm\rh1
vpmulhw		%ymm2,%ymm\rh2,%ymm\rh2
vpmulhw		%ymm2,%ymm\rh3,%ymm\rh3
.endm


.macro mul2 rh0,rh1,rh2,rh3,qnum

vmovdqa		(\qnum    )*2(%rsi),%ymm15
vpmullw		%ymm15,%ymm\rh0,%ymm12
vmovdqa		(\qnum+ 16)*2(%rsi),%ymm2
vpmullw		%ymm2,%ymm\rh1,%ymm13
vpmullw		%ymm15,%ymm\rh2,%ymm14
vpmullw		%ymm2,%ymm\rh3,%ymm15

vmovdqa		(\qnum+ 32)*2(%rsi),%ymm2
vpmulhw		%ymm2,%ymm\rh0,%ymm\rh0
vmovdqa		(\qnum+ 48)*2(%rsi),%ymm1
vpmulhw		%ymm1,%ymm\rh1,%ymm\rh1
vpmulhw		%ymm2,%ymm\rh2,%ymm\rh2
vpmulhw		%ymm1,%ymm\rh3,%ymm\rh3
.endm


.macro mul3 rh0,rh1,rh2,rh3,qnum

vmovdqa		(\qnum    )*2(%rsi),%ymm15
vpmullw		%ymm15,%ymm\rh0,%ymm12

vmovdqa		(\qnum+ 16)*2(%rsi),%ymm15
vpmullw		%ymm15,%ymm\rh1,%ymm13

vmovdqa		(\qnum+ 32)*2(%rsi),%ymm15
vpmullw		%ymm15,%ymm\rh2,%ymm14

vmovdqa		(\qnum+ 48)*2(%rsi),%ymm15
vpmullw		%ymm15,%ymm\rh3,%ymm15

vmovdqa		(\qnum+ 64)*2(%rsi),%ymm2
vpmulhw		%ymm2,%ymm\rh0,%ymm\rh0

vmovdqa		(\qnum+ 80)*2(%rsi),%ymm2
vpmulhw		%ymm2,%ymm\rh1,%ymm\rh1

vmovdqa		(\qnum+ 96)*2(%rsi),%ymm2
vpmulhw		%ymm2,%ymm\rh2,%ymm\rh2

vmovdqa		(\qnum+112)*2(%rsi),%ymm2
vpmulhw		%ymm2,%ymm\rh3,%ymm\rh3
.endm


.macro mul rh0,rh1,rh2,rh3,qnum

vmovdqa		(\qnum    )*2(%rsi),%ymm15
vpmullw		%ymm15,%ymm\rh0,%ymm12
vpmullw		%ymm15,%ymm\rh1,%ymm13
vmovdqa		(\qnum+  16)*2(%rsi),%ymm2
vpmullw		%ymm2,%ymm\rh2,%ymm14
vpmullw		%ymm2,%ymm\rh3,%ymm15

vmovdqa		(\qnum+ 32)*2(%rsi),%ymm2
vpmulhw		%ymm2,%ymm\rh0,%ymm\rh0
vpmulhw		%ymm2,%ymm\rh1,%ymm\rh1
vmovdqa		(\qnum+ 48)*2(%rsi),%ymm1
vpmulhw		%ymm1,%ymm\rh2,%ymm\rh2
vpmulhw		%ymm1,%ymm\rh3,%ymm\rh3
.endm


.macro reduce
vpmulhw		%ymm0,%ymm12,%ymm12
vpmulhw		%ymm0,%ymm13,%ymm13

vpmulhw		%ymm0,%ymm14,%ymm14
vpmulhw		%ymm0,%ymm15,%ymm15
.endm

.macro update rln,rl0,rl1,rl2,rl3,rh0,rh1,rh2,rh3
vpaddw		%ymm\rh0,%ymm\rl0,%ymm\rln
vpsubw		%ymm\rh0,%ymm\rl0,%ymm\rh0
vpaddw		%ymm\rh1,%ymm\rl1,%ymm\rl0

vpsubw		%ymm\rh1,%ymm\rl1,%ymm\rh1
vpaddw		%ymm\rh2,%ymm\rl2,%ymm\rl1
vpsubw		%ymm\rh2,%ymm\rl2,%ymm\rh2

vpaddw		%ymm\rh3,%ymm\rl3,%ymm\rl2
vpsubw		%ymm\rh3,%ymm\rl3,%ymm\rh3

vpsubw		%ymm12,%ymm\rln,%ymm\rln
vpaddw		%ymm12,%ymm\rh0,%ymm\rh0
vpsubw		%ymm13,%ymm\rl0,%ymm\rl0

vpaddw		%ymm13,%ymm\rh1,%ymm\rh1
vpsubw		%ymm14,%ymm\rl1,%ymm\rl1
vpaddw		%ymm14,%ymm\rh2,%ymm\rh2

vpsubw		%ymm15,%ymm\rl2,%ymm\rl2
vpaddw		%ymm15,%ymm\rh3,%ymm\rh3
.endm

.macro levels0t2 off
/* not just from %rdi as it is 16-way */
/* level0 */
vmovdqa		(\off+128)*16*2(%rdi),%ymm8
vmovdqa		(\off+160)*16*2(%rdi),%ymm9
vmovdqa		(\off+192)*16*2(%rdi),%ymm10
vmovdqa		(\off+224)*16*2(%rdi),%ymm11

mul1		8,9,10,11,16

vmovdqa		(\off+  0)*16*2(%rdi),%ymm4
vmovdqa		(\off+ 32)*16*2(%rdi),%ymm5
vmovdqa		(\off+ 64)*16*2(%rdi),%ymm6
vmovdqa		(\off+ 96)*16*2(%rdi),%ymm7

reduce
update		3,4,5,6,7,8,9,10,11

/* level1 */
mul2        5,10,6,11,48

reduce
update		7,3,8,4,9,5,10,6,11

/* level2 */
mul3        8,6,4,11,112

reduce
update		9,7,5,3,10,8,6,4,11

vmovdqa		%ymm9,(\off+  0)*16*2(%rdi)
vmovdqa		%ymm8,(\off+ 32)*16*2(%rdi)
vmovdqa		%ymm7,(\off+ 64)*16*2(%rdi)
vmovdqa		%ymm6,(\off+ 96)*16*2(%rdi)
vmovdqa		%ymm5,(\off+128)*16*2(%rdi)
vmovdqa		%ymm4,(\off+160)*16*2(%rdi)
vmovdqa		%ymm3,(\off+192)*16*2(%rdi)
vmovdqa		%ymm11,(\off+224)*16*2(%rdi)
.endm


.macro levels3t5 off
/* level3 */
vmovdqa		(\off+ 16)*16*2(%rdi),%ymm8
vmovdqa		(\off+ 20)*16*2(%rdi),%ymm9
vmovdqa		(\off+ 24)*16*2(%rdi),%ymm10
vmovdqa		(\off+ 28)*16*2(%rdi),%ymm11

mul1		8,9,10,11,(240+(\off/32)*224)

vmovdqa		(\off+  0)*16*2(%rdi),%ymm4
vmovdqa		(\off+  4)*16*2(%rdi),%ymm5
vmovdqa		(\off+  8)*16*2(%rdi),%ymm6
vmovdqa		(\off+ 12)*16*2(%rdi),%ymm7

reduce
update		3,4,5,6,7,8,9,10,11

/* level4 */
mul2        5,10,6,11,(272+(\off/32)*224)

reduce
update		7,3,8,4,9,5,10,6,11

/* level5 */
mul3        8,6,4,11,(336+(\off/32)*224)

reduce
update		9,7,5,3,10,8,6,4,11

vmovdqa		%ymm9,(\off+  0)*16*2(%rdi)
vmovdqa		%ymm8,(\off+  4)*16*2(%rdi)
vmovdqa		%ymm7,(\off+  8)*16*2(%rdi)
vmovdqa		%ymm6,(\off+ 12)*16*2(%rdi)
vmovdqa		%ymm5,(\off+ 16)*16*2(%rdi)
vmovdqa		%ymm4,(\off+ 20)*16*2(%rdi)
vmovdqa		%ymm3,(\off+ 24)*16*2(%rdi)
vmovdqa		%ymm11,(\off+ 28)*16*2(%rdi)
.endm


.macro level6 off
vmovdqa		(\off+  2)*16*2(%rdi),%ymm8
vmovdqa		(\off+  3)*16*2(%rdi),%ymm9
vmovdqa		(\off+  6)*16*2(%rdi),%ymm10
vmovdqa		(\off+  7)*16*2(%rdi),%ymm11

mul		8,9,10,11,(2032+\off*8)

vmovdqa		(\off+  0)*16*2(%rdi),%ymm4
vmovdqa		(\off+  1)*16*2(%rdi),%ymm5
vmovdqa		(\off+  4)*16*2(%rdi),%ymm6
vmovdqa		(\off+  5)*16*2(%rdi),%ymm7

reduce
update		3,4,5,6,7,8,9,10,11

vmovdqa		%ymm3,(\off+  0)*16*2(%rdi)
vmovdqa		%ymm4,(\off+  1)*16*2(%rdi)
vmovdqa		%ymm8,(\off+  2)*16*2(%rdi)
vmovdqa		%ymm9,(\off+  3)*16*2(%rdi)
vmovdqa		%ymm5,(\off+  4)*16*2(%rdi)
vmovdqa		%ymm6,(\off+  5)*16*2(%rdi)
vmovdqa		%ymm10,(\off+  6)*16*2(%rdi)
vmovdqa		%ymm11,(\off+  7)*16*2(%rdi)
.endm





.text
.global cdecl(ntt_avx_16)
cdecl(ntt_avx_16):
vmovdqa		_16XQ_16*2(%rsi),%ymm0

levels0t2  0
levels0t2  1
levels0t2  2
levels0t2  3
levels0t2  4
levels0t2  5
levels0t2  6
levels0t2  7
levels0t2  8
levels0t2  9
levels0t2  10
levels0t2  11
levels0t2  12
levels0t2  13
levels0t2  14
levels0t2  15
levels0t2  16
levels0t2  17
levels0t2  18
levels0t2  19
levels0t2  20
levels0t2  21
levels0t2  22
levels0t2  23
levels0t2  24
levels0t2  25
levels0t2  26
levels0t2  27
levels0t2  28
levels0t2  29
levels0t2  30
levels0t2  31


levels3t5  0
levels3t5  1
levels3t5  2
levels3t5  3

levels3t5  32
levels3t5  33
levels3t5  34
levels3t5  35

levels3t5  64
levels3t5  65
levels3t5  66
levels3t5  67

levels3t5  96
levels3t5  97
levels3t5  98
levels3t5  99

levels3t5  128
levels3t5  129
levels3t5  130
levels3t5  131

levels3t5  160
levels3t5  161
levels3t5  162
levels3t5  163

levels3t5  192
levels3t5  193
levels3t5  194
levels3t5  195

levels3t5  224
levels3t5  225
levels3t5  226
levels3t5  227


level6     0
level6     8
level6     16
level6     24
level6     32
level6     40
level6     48
level6     56
level6     64
level6     72
level6     80
level6     88
level6     96
level6     104
level6     112
level6     120
level6     128
level6     136
level6     144
level6     152
level6     160
level6     168
level6     176
level6     184
level6     192
level6     200
level6     208
level6     216
level6     224
level6     232
level6     240
level6     248


ret
