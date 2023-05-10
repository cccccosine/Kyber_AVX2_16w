#include "ntt_16_consts.h"
.include "fq.inc"

.macro butterfly0 rl0,rl1,rl2,rl3,rh0,rh1,rh2,rh3,zl0=2,zl1=2,zh0=3,zh1=3,off
vpsubw		%ymm\rl0,%ymm\rh0,%ymm12
vpaddw		%ymm\rh0,%ymm\rl0,%ymm\rl0
vpsubw		%ymm\rl1,%ymm\rh1,%ymm13

vpmullw		%ymm\zl0,%ymm12,%ymm\rh0
vpaddw		%ymm\rh1,%ymm\rl1,%ymm\rl1
vpsubw		%ymm\rl2,%ymm\rh2,%ymm14

vpmullw		%ymm\zl1,%ymm13,%ymm\rh1
vpaddw		%ymm\rh2,%ymm\rl2,%ymm\rl2
vpsubw		%ymm\rl3,%ymm\rh3,%ymm15

vmovdqa     (_16XQINV_16-((\off/2)+7)*16)*2(%rsi), %ymm\zl1
vpmullw		%ymm\zl1,%ymm14,%ymm\rh2
vpaddw		%ymm\rh3,%ymm\rl3,%ymm\rl3
vmovdqa     (_16XQINV_16-((\off/2)+8)*16)*2(%rsi), %ymm\zl1
vpmullw		%ymm\zl1,%ymm15,%ymm\rh3

vpmulhw		%ymm\zh0,%ymm12,%ymm12
vpmulhw		%ymm\zh1,%ymm13,%ymm13

vmovdqa     (_16XQINV_16-((\off/2)+5)*16)*2(%rsi), %ymm\zh0
vmovdqa     (_16XQINV_16-((\off/2)+6)*16)*2(%rsi), %ymm\zh1
vpmulhw		%ymm\zh0,%ymm14,%ymm14
vpmulhw		%ymm\zh1,%ymm15,%ymm15

vpmulhw		%ymm0,%ymm\rh0,%ymm\rh0

vpmulhw		%ymm0,%ymm\rh1,%ymm\rh1

vpmulhw		%ymm0,%ymm\rh2,%ymm\rh2
vpmulhw		%ymm0,%ymm\rh3,%ymm\rh3

#

#

vpsubw		%ymm\rh0,%ymm12,%ymm\rh0

vpsubw		%ymm\rh1,%ymm13,%ymm\rh1

vpsubw		%ymm\rh2,%ymm14,%ymm\rh2
vpsubw		%ymm\rh3,%ymm15,%ymm\rh3
.endm


.macro butterfly3 rl0,rl1,rl2,rl3,rh0,rh1,rh2,rh3,zl0=2,zl1=2,zh0=3,zh1=3,off
vpsubw		%ymm\rl0,%ymm\rh0,%ymm12
vpaddw		%ymm\rh0,%ymm\rl0,%ymm\rl0
vpsubw		%ymm\rl1,%ymm\rh1,%ymm13

vpmullw		%ymm\zl0,%ymm12,%ymm\rh0
vpaddw		%ymm\rh1,%ymm\rl1,%ymm\rl1
vpsubw		%ymm\rl2,%ymm\rh2,%ymm14

vpmullw		%ymm\zl1,%ymm13,%ymm\rh1
vpaddw		%ymm\rh2,%ymm\rl2,%ymm\rl2
vpsubw		%ymm\rl3,%ymm\rh3,%ymm15

vmovdqa     (2032-(14+((\off/128)*4+2)*14)*16)*2(%rsi), %ymm\zl1
vpmullw		%ymm\zl1,%ymm14,%ymm\rh2
vpaddw		%ymm\rh3,%ymm\rl3,%ymm\rl3
vmovdqa     (2032-(14+((\off/128)*4+3)*14)*16)*2(%rsi), %ymm\zl1
vpmullw		%ymm\zl1,%ymm15,%ymm\rh3

vpmulhw		%ymm\zh0,%ymm12,%ymm12
vpmulhw		%ymm\zh1,%ymm13,%ymm13

vmovdqa     (2032-(13+((\off/128)*4+2)*14)*16)*2(%rsi), %ymm\zh0
vmovdqa     (2032-(13+((\off/128)*4+3)*14)*16)*2(%rsi), %ymm\zh1
vpmulhw		%ymm\zh0,%ymm14,%ymm14
vpmulhw		%ymm\zh1,%ymm15,%ymm15

vpmulhw		%ymm0,%ymm\rh0,%ymm\rh0

vpmulhw		%ymm0,%ymm\rh1,%ymm\rh1

vpmulhw		%ymm0,%ymm\rh2,%ymm\rh2
vpmulhw		%ymm0,%ymm\rh3,%ymm\rh3

#

#

vpsubw		%ymm\rh0,%ymm12,%ymm\rh0

vpsubw		%ymm\rh1,%ymm13,%ymm\rh1

vpsubw		%ymm\rh2,%ymm14,%ymm\rh2
vpsubw		%ymm\rh3,%ymm15,%ymm\rh3
.endm


.macro butterfly rl0,rl1,rl2,rl3,rh0,rh1,rh2,rh3,zl0=2,zl1=2,zh0=3,zh1=3
vpsubw		%ymm\rl0,%ymm\rh0,%ymm12
vpaddw		%ymm\rh0,%ymm\rl0,%ymm\rl0
vpsubw		%ymm\rl1,%ymm\rh1,%ymm13

vpmullw		%ymm\zl0,%ymm12,%ymm\rh0
vpaddw		%ymm\rh1,%ymm\rl1,%ymm\rl1
vpsubw		%ymm\rl2,%ymm\rh2,%ymm14

vpmullw		%ymm\zl0,%ymm13,%ymm\rh1
vpaddw		%ymm\rh2,%ymm\rl2,%ymm\rl2
vpsubw		%ymm\rl3,%ymm\rh3,%ymm15

vpmullw		%ymm\zl1,%ymm14,%ymm\rh2
vpaddw		%ymm\rh3,%ymm\rl3,%ymm\rl3
vpmullw		%ymm\zl1,%ymm15,%ymm\rh3

vpmulhw		%ymm\zh0,%ymm12,%ymm12
vpmulhw		%ymm\zh0,%ymm13,%ymm13

vpmulhw		%ymm\zh1,%ymm14,%ymm14
vpmulhw		%ymm\zh1,%ymm15,%ymm15

vpmulhw		%ymm0,%ymm\rh0,%ymm\rh0

vpmulhw		%ymm0,%ymm\rh1,%ymm\rh1

vpmulhw		%ymm0,%ymm\rh2,%ymm\rh2
vpmulhw		%ymm0,%ymm\rh3,%ymm\rh3

#

#

vpsubw		%ymm\rh0,%ymm12,%ymm\rh0

vpsubw		%ymm\rh1,%ymm13,%ymm\rh1

vpsubw		%ymm\rh2,%ymm14,%ymm\rh2
vpsubw		%ymm\rh3,%ymm15,%ymm\rh3
.endm

.macro intt_levels0t2 off
/* level 0 */
vmovdqa		_16XFLO_16*2(%rsi),%ymm2
vmovdqa		_16XFHI_16*2(%rsi),%ymm3

vmovdqa         (\off+  0)*16*2(%rdi),%ymm4
vmovdqa         (\off+  4)*16*2(%rdi),%ymm5
vmovdqa         (\off+  2)*16*2(%rdi),%ymm6
vmovdqa         (\off+  6)*16*2(%rdi),%ymm7

fqmulprecomp	2,3,4
fqmulprecomp	2,3,6
fqmulprecomp	2,3,5
fqmulprecomp	2,3,7

vmovdqa         (\off+  8)*16*2(%rdi),%ymm8
vmovdqa         (\off+ 12)*16*2(%rdi),%ymm9
vmovdqa         (\off+ 10)*16*2(%rdi),%ymm10
vmovdqa         (\off+ 14)*16*2(%rdi),%ymm11

fqmulprecomp	2,3,8
fqmulprecomp	2,3,10
fqmulprecomp	2,3,9
fqmulprecomp	2,3,11

vmovdqa     (_16XQINV_16-((\off/2)+1)*16)*2(%rsi), %ymm2
vmovdqa     (_16XQINV_16-((\off/2)+3)*16)*2(%rsi), %ymm15
vmovdqa     (_16XQINV_16-((\off/2)+2)*16)*2(%rsi), %ymm3
vmovdqa     (_16XQINV_16-((\off/2)+4)*16)*2(%rsi), %ymm1

butterfly0	4,5,8,9,6,7,10,11,15,1,2,3,\off

/* level 1 */
vmovdqa     (2032-(((\off/16)%2*2)+1+(\off/32)*14)*16)*2(%rsi), %ymm2
vmovdqa     (2032-(((\off/16)%2*2)+5+(\off/32)*14)*16)*2(%rsi), %ymm15
vmovdqa     (2032-(((\off/16)%2*2)+2+(\off/32)*14)*16)*2(%rsi), %ymm3
vmovdqa     (2032-(((\off/16)%2*2)+6+(\off/32)*14)*16)*2(%rsi), %ymm1

butterfly	4,6,8,10,5,7,9,11,15,1,2,3

/* level 2 */
vmovdqa     (2032-(((\off/16)%2)+9+(\off/32)*14)*16)*2(%rsi), %ymm2
vmovdqa     (2032-(((\off/16)%2)+11+(\off/32)*14)*16)*2(%rsi), %ymm1

butterfly	4,6,5,7,8,10,9,11,1,1,2,2

vmovdqa		_16XV_16*2(%rsi),%ymm1
red16		4     

vmovdqa         %ymm4,(\off+  0)*16*2(%rdi)
vmovdqa         %ymm5,(\off+  4)*16*2(%rdi)
vmovdqa         %ymm6,(\off+  2)*16*2(%rdi)
vmovdqa         %ymm7,(\off+  6)*16*2(%rdi)
vmovdqa         %ymm8,(\off+  8)*16*2(%rdi)
vmovdqa         %ymm9,(\off+ 12)*16*2(%rdi)
vmovdqa         %ymm10,(\off+ 10)*16*2(%rdi)
vmovdqa         %ymm11,(\off+ 14)*16*2(%rdi)

.endm


.macro intt_levels3t5 off
/* level 3 */

vmovdqa         (\off+  0)*16*2(%rdi),%ymm4
vmovdqa         (\off+ 32)*16*2(%rdi),%ymm5
vmovdqa         (\off+ 16)*16*2(%rdi),%ymm6
vmovdqa         (\off+ 48)*16*2(%rdi),%ymm7
vmovdqa         (\off+ 64)*16*2(%rdi),%ymm8
vmovdqa         (\off+ 96)*16*2(%rdi),%ymm9
vmovdqa         (\off+ 80)*16*2(%rdi),%ymm10
vmovdqa         (\off+112)*16*2(%rdi),%ymm11

vmovdqa     (2032-(13+(\off/128)*4*14)*16)*2(%rsi), %ymm2
vmovdqa     (2032-(14+(\off/128)*4*14)*16)*2(%rsi), %ymm15
vmovdqa     (2032-(13+((\off/128)*4+1)*14)*16)*2(%rsi), %ymm3
vmovdqa     (2032-(14+((\off/128)*4+1)*14)*16)*2(%rsi), %ymm1

butterfly3	4,5,8,9,6,7,10,11,15,1,2,3,\off

vmovdqa		_16XV_16*2(%rsi),%ymm1
.if (\off%128) == 2
red16		4
red16		5
red16		8
red16		9
.endif

/* level 4 */
vmovdqa     (240-((\off/128)*2+1)*16)*2(%rsi), %ymm2
vmovdqa     (240-((\off/128)*2+5)*16)*2(%rsi), %ymm15
vmovdqa     (240-((\off/128)*2+2)*16)*2(%rsi), %ymm3
vmovdqa     (240-((\off/128)*2+6)*16)*2(%rsi), %ymm1

butterfly	4,6,8,10,5,7,9,11,15,1,2,3

.if (\off%128) == 4
red16		4
.endif
.if (\off%128) == 5
red16		4
.endif
.if (\off%128) == 6
red16		4
.endif
.if (\off%128) == 7
red16		4
.endif
/* level 5 */
vmovdqa     (112-((\off/128)+1)*16)*2(%rsi), %ymm2
vmovdqa     (112-((\off/128)+3)*16)*2(%rsi), %ymm1

butterfly	4,6,5,7,8,10,9,11,1,1,2,2

.if (\off%128) == 0 
red16		4
.endif
.if (\off%128) == 1 
red16		4
.endif
.if (\off%128) == 8 
red16		4
.endif
.if (\off%128) == 10
red16		4
.endif
.if (\off%128) == 12
red16		4
.endif
.if (\off%128) == 14
red16		4
.endif

vmovdqa         %ymm4,(\off+  0)*16*2(%rdi)
vmovdqa         %ymm5,(\off+ 32)*16*2(%rdi)
vmovdqa         %ymm6,(\off+ 16)*16*2(%rdi)
vmovdqa         %ymm7,(\off+ 48)*16*2(%rdi)
vmovdqa         %ymm8,(\off+ 64)*16*2(%rdi)
vmovdqa         %ymm9,(\off+ 96)*16*2(%rdi)
vmovdqa         %ymm10,(\off+ 80)*16*2(%rdi)
vmovdqa         %ymm11,(\off+112)*16*2(%rdi)
.endm

.macro intt_level6 off
/* level 6 */

vmovdqa         (\off+  0)*16*2(%rdi),%ymm4
vmovdqa         (\off+  1)*16*2(%rdi),%ymm5
vmovdqa         (\off+  2)*16*2(%rdi),%ymm6
vmovdqa         (\off+  3)*16*2(%rdi),%ymm7
vmovdqa         (\off+128)*16*2(%rdi),%ymm8
vmovdqa         (\off+129)*16*2(%rdi),%ymm9
vmovdqa         (\off+130)*16*2(%rdi),%ymm10
vmovdqa         (\off+131)*16*2(%rdi),%ymm11

vmovdqa     (_ZETAS_EXP_16+16)*2(%rsi), %ymm2
vmovdqa     (_ZETAS_EXP_16)*2(%rsi), %ymm1

butterfly	4,5,6,7,8,9,10,11,1,1,2,2

vmovdqa         %ymm4,(\off+  0)*16*2(%rdi)
vmovdqa         %ymm5,(\off+  1)*16*2(%rdi)
vmovdqa         %ymm6,(\off+  2)*16*2(%rdi)
vmovdqa         %ymm7,(\off+  3)*16*2(%rdi)
vmovdqa         %ymm8,(\off+128)*16*2(%rdi)
vmovdqa         %ymm9,(\off+129)*16*2(%rdi)
vmovdqa         %ymm10,(\off+130)*16*2(%rdi)
vmovdqa         %ymm11,(\off+131)*16*2(%rdi)
.endm

.text
.global cdecl(invntt_avx_16)
cdecl(invntt_avx_16):
vmovdqa         _16XQ_16*2(%rsi),%ymm0

intt_levels0t2	0
intt_levels0t2	1

intt_levels0t2	16
intt_levels0t2	17

intt_levels0t2	32
intt_levels0t2	33

intt_levels0t2	48
intt_levels0t2	49

intt_levels0t2	64
intt_levels0t2	65

intt_levels0t2	80
intt_levels0t2	81

intt_levels0t2	96
intt_levels0t2	97

intt_levels0t2	112
intt_levels0t2	113

intt_levels0t2	128
intt_levels0t2	129

intt_levels0t2	144
intt_levels0t2	145

intt_levels0t2	160
intt_levels0t2	161

intt_levels0t2	176
intt_levels0t2	177

intt_levels0t2	192
intt_levels0t2	193

intt_levels0t2	208
intt_levels0t2	209

intt_levels0t2	224
intt_levels0t2	225

intt_levels0t2	240
intt_levels0t2	241

#########################

intt_levels3t5	0
intt_levels3t5	1
intt_levels3t5	2
intt_levels3t5	3
intt_levels3t5	4
intt_levels3t5	5
intt_levels3t5	6
intt_levels3t5	7
intt_levels3t5	8
intt_levels3t5	9
intt_levels3t5	10
intt_levels3t5	11
intt_levels3t5	12
intt_levels3t5	13
intt_levels3t5	14
intt_levels3t5	15

intt_levels3t5	128
intt_levels3t5	129
intt_levels3t5	130
intt_levels3t5	131
intt_levels3t5	132
intt_levels3t5	133
intt_levels3t5	134
intt_levels3t5	135
intt_levels3t5	136
intt_levels3t5	137
intt_levels3t5	138
intt_levels3t5	139
intt_levels3t5	140
intt_levels3t5	141
intt_levels3t5	142
intt_levels3t5	143

#########################

intt_level6	0
intt_level6	4
intt_level6	8
intt_level6	12
intt_level6	16
intt_level6	20
intt_level6	24
intt_level6	28
intt_level6	32
intt_level6	36
intt_level6	40
intt_level6	44
intt_level6	48
intt_level6	52
intt_level6	56
intt_level6	60
intt_level6	64
intt_level6	68
intt_level6	72
intt_level6	76
intt_level6	80
intt_level6	84
intt_level6	88
intt_level6	92
intt_level6	96
intt_level6	100
intt_level6	104
intt_level6	108
intt_level6	112
intt_level6	116
intt_level6	120
intt_level6	124


ret


