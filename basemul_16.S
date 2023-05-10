#include "ntt_16_consts.h"

.macro schoolbook off
vmovdqa		_16XQINV_16*2(%rcx),%ymm0
vmovdqa		(64*\off+ 0)*2(%rsi),%ymm1		// a0   
vmovdqa		(64*\off+16)*2(%rsi),%ymm2		// b0
vmovdqa		(64*\off+32)*2(%rsi),%ymm3		// a1
vmovdqa		(64*\off+48)*2(%rsi),%ymm4		// b1

vpmullw		%ymm0,%ymm1,%ymm9			// a0.lo
vpmullw		%ymm0,%ymm2,%ymm10			// b0.lo
vpmullw		%ymm0,%ymm3,%ymm11			// a1.lo
vpmullw		%ymm0,%ymm4,%ymm12			// b1.lo

vmovdqa		(64*\off+ 0)*2(%rdx),%ymm5		// c0
vmovdqa		(64*\off+16)*2(%rdx),%ymm6		// d0

vpmulhw		%ymm5,%ymm1,%ymm13			// a0c0.hi
vpmulhw		%ymm6,%ymm1,%ymm1			// a0d0.hi
vpmulhw		%ymm5,%ymm2,%ymm14			// b0c0.hi
vpmulhw		%ymm6,%ymm2,%ymm2			// b0d0.hi

vmovdqa		(64*\off+32)*2(%rdx),%ymm7		// c1
vmovdqa		(64*\off+48)*2(%rdx),%ymm8		// d1

vpmulhw		%ymm7,%ymm3,%ymm15			// a1c1.hi
vpmulhw		%ymm8,%ymm3,%ymm3			// a1d1.hi
vpmulhw		%ymm7,%ymm4,%ymm0			// b1c1.hi
vpmulhw		%ymm8,%ymm4,%ymm4			// b1d1.hi

vmovdqa		%ymm13,(%rsp)

vpmullw		%ymm5,%ymm9,%ymm13			// a0c0.lo
vpmullw		%ymm6,%ymm9,%ymm9			// a0d0.lo
vpmullw		%ymm5,%ymm10,%ymm5			// b0c0.lo
vpmullw		%ymm6,%ymm10,%ymm10			// b0d0.lo

vpmullw		%ymm7,%ymm11,%ymm6			// a1c1.lo
vpmullw		%ymm8,%ymm11,%ymm11			// a1d1.lo
vpmullw		%ymm7,%ymm12,%ymm7			// b1c1.lo
vpmullw		%ymm8,%ymm12,%ymm12			// b1d1.lo

vmovdqa		_16XQ_16*2(%rcx),%ymm8
vpmulhw		%ymm8,%ymm13,%ymm13
vpmulhw		%ymm8,%ymm9,%ymm9
vpmulhw		%ymm8,%ymm5,%ymm5
vpmulhw		%ymm8,%ymm10,%ymm10
vpmulhw		%ymm8,%ymm6,%ymm6
vpmulhw		%ymm8,%ymm11,%ymm11
vpmulhw		%ymm8,%ymm7,%ymm7
vpmulhw		%ymm8,%ymm12,%ymm12

vpsubw		(%rsp),%ymm13,%ymm13			// -a0c0
vpsubw		%ymm9,%ymm1,%ymm9			// a0d0
vpsubw		%ymm5,%ymm14,%ymm5			// b0c0
vpsubw		%ymm10,%ymm2,%ymm10			// b0d0

vpsubw		%ymm6,%ymm15,%ymm6			// a1c1
vpsubw		%ymm11,%ymm3,%ymm11			// a1d1
vpsubw		%ymm7,%ymm0,%ymm7			// b1c1
vpsubw		%ymm12,%ymm4,%ymm12			// b1d1

vmovdqa		(%r9),%ymm0
vmovdqa		32(%r9),%ymm1
vpmullw		%ymm0,%ymm10,%ymm2
vpmullw		%ymm0,%ymm12,%ymm3
vpmulhw		%ymm1,%ymm10,%ymm10
vpmulhw		%ymm1,%ymm12,%ymm12
vpmulhw		%ymm8,%ymm2,%ymm2
vpmulhw		%ymm8,%ymm3,%ymm3
vpsubw		%ymm2,%ymm10,%ymm10			// rb0d0
vpsubw		%ymm3,%ymm12,%ymm12			// rb1d1

vpaddw		%ymm5,%ymm9,%ymm9
vpaddw		%ymm7,%ymm11,%ymm11
vpsubw		%ymm13,%ymm10,%ymm13
vpsubw		%ymm12,%ymm6,%ymm6

vmovdqa		%ymm13,(64*\off+ 0)*2(%rdi)
vmovdqa		%ymm9,(64*\off+16)*2(%rdi)
vmovdqa		%ymm6,(64*\off+32)*2(%rdi)
vmovdqa		%ymm11,(64*\off+48)*2(%rdi)
.endm

.text
.global cdecl(basemul_avx_16)
cdecl(basemul_avx_16):
mov		%rsp,%r8
and		$-32,%rsp
sub		$32,%rsp

lea		(_ZETAS_BASEMUL+   0)*2(%rcx),%r9
schoolbook	0

lea		(_ZETAS_BASEMUL+  32)*2(%rcx),%r9
schoolbook	1

lea		(_ZETAS_BASEMUL+  64)*2(%rcx),%r9
schoolbook	2

lea		(_ZETAS_BASEMUL+  96)*2(%rcx),%r9
schoolbook	3

lea		(_ZETAS_BASEMUL+ 128)*2(%rcx),%r9
schoolbook	4

lea		(_ZETAS_BASEMUL+ 160)*2(%rcx),%r9
schoolbook	5

lea		(_ZETAS_BASEMUL+ 192)*2(%rcx),%r9
schoolbook	6

lea		(_ZETAS_BASEMUL+ 224)*2(%rcx),%r9
schoolbook	7

lea		(_ZETAS_BASEMUL+ 256)*2(%rcx),%r9
schoolbook	8

lea		(_ZETAS_BASEMUL+ 288)*2(%rcx),%r9
schoolbook	9

lea		(_ZETAS_BASEMUL+ 320)*2(%rcx),%r9
schoolbook	10

lea		(_ZETAS_BASEMUL+ 352)*2(%rcx),%r9
schoolbook	11

lea		(_ZETAS_BASEMUL+ 384)*2(%rcx),%r9
schoolbook	12

lea		(_ZETAS_BASEMUL+ 416)*2(%rcx),%r9
schoolbook	13

lea		(_ZETAS_BASEMUL+ 448)*2(%rcx),%r9
schoolbook	14

lea		(_ZETAS_BASEMUL+ 480)*2(%rcx),%r9
schoolbook	15

lea		(_ZETAS_BASEMUL+ 512)*2(%rcx),%r9
schoolbook	16

lea		(_ZETAS_BASEMUL+ 544)*2(%rcx),%r9
schoolbook	17

lea		(_ZETAS_BASEMUL+ 576)*2(%rcx),%r9
schoolbook	18

lea		(_ZETAS_BASEMUL+ 608)*2(%rcx),%r9
schoolbook	19

lea		(_ZETAS_BASEMUL+ 640)*2(%rcx),%r9
schoolbook	20

lea		(_ZETAS_BASEMUL+ 672)*2(%rcx),%r9
schoolbook	21

lea		(_ZETAS_BASEMUL+ 704)*2(%rcx),%r9
schoolbook	22

lea		(_ZETAS_BASEMUL+ 736)*2(%rcx),%r9
schoolbook	23

lea		(_ZETAS_BASEMUL+ 768)*2(%rcx),%r9
schoolbook	24

lea		(_ZETAS_BASEMUL+ 800)*2(%rcx),%r9
schoolbook	25

lea		(_ZETAS_BASEMUL+ 832)*2(%rcx),%r9
schoolbook	26

lea		(_ZETAS_BASEMUL+ 864)*2(%rcx),%r9
schoolbook	27

lea		(_ZETAS_BASEMUL+ 896)*2(%rcx),%r9
schoolbook	28

lea		(_ZETAS_BASEMUL+ 928)*2(%rcx),%r9
schoolbook	29

lea		(_ZETAS_BASEMUL+ 960)*2(%rcx),%r9
schoolbook	30

lea		(_ZETAS_BASEMUL+ 992)*2(%rcx),%r9
schoolbook	31

lea		(_ZETAS_BASEMUL+1024)*2(%rcx),%r9
schoolbook	32

lea		(_ZETAS_BASEMUL+1056)*2(%rcx),%r9
schoolbook	33

lea		(_ZETAS_BASEMUL+1088)*2(%rcx),%r9
schoolbook	34

lea		(_ZETAS_BASEMUL+1120)*2(%rcx),%r9
schoolbook	35

lea		(_ZETAS_BASEMUL+1152)*2(%rcx),%r9
schoolbook	36

lea		(_ZETAS_BASEMUL+1184)*2(%rcx),%r9
schoolbook	37

lea		(_ZETAS_BASEMUL+1216)*2(%rcx),%r9
schoolbook	38

lea		(_ZETAS_BASEMUL+1248)*2(%rcx),%r9
schoolbook	39

lea		(_ZETAS_BASEMUL+1280)*2(%rcx),%r9
schoolbook	40

lea		(_ZETAS_BASEMUL+1312)*2(%rcx),%r9
schoolbook	41

lea		(_ZETAS_BASEMUL+1344)*2(%rcx),%r9
schoolbook	42

lea		(_ZETAS_BASEMUL+1376)*2(%rcx),%r9
schoolbook	43

lea		(_ZETAS_BASEMUL+1408)*2(%rcx),%r9
schoolbook	44

lea		(_ZETAS_BASEMUL+1440)*2(%rcx),%r9
schoolbook	45

lea		(_ZETAS_BASEMUL+1472)*2(%rcx),%r9
schoolbook	46

lea		(_ZETAS_BASEMUL+1504)*2(%rcx),%r9
schoolbook	47

lea		(_ZETAS_BASEMUL+1536)*2(%rcx),%r9
schoolbook	48

lea		(_ZETAS_BASEMUL+1568)*2(%rcx),%r9
schoolbook	49

lea		(_ZETAS_BASEMUL+1600)*2(%rcx),%r9
schoolbook	50

lea		(_ZETAS_BASEMUL+1632)*2(%rcx),%r9
schoolbook	51

lea		(_ZETAS_BASEMUL+1664)*2(%rcx),%r9
schoolbook	52

lea		(_ZETAS_BASEMUL+1696)*2(%rcx),%r9
schoolbook	53

lea		(_ZETAS_BASEMUL+1728)*2(%rcx),%r9
schoolbook	54

lea		(_ZETAS_BASEMUL+1760)*2(%rcx),%r9
schoolbook	55

lea		(_ZETAS_BASEMUL+1792)*2(%rcx),%r9
schoolbook	56

lea		(_ZETAS_BASEMUL+1824)*2(%rcx),%r9
schoolbook	57

lea		(_ZETAS_BASEMUL+1856)*2(%rcx),%r9
schoolbook	58

lea		(_ZETAS_BASEMUL+1888)*2(%rcx),%r9
schoolbook	59

lea		(_ZETAS_BASEMUL+1920)*2(%rcx),%r9
schoolbook	60

lea		(_ZETAS_BASEMUL+1952)*2(%rcx),%r9
schoolbook	61

lea		(_ZETAS_BASEMUL+1984)*2(%rcx),%r9
schoolbook	62

lea		(_ZETAS_BASEMUL+2016)*2(%rcx),%r9
schoolbook	63




mov		%r8,%rsp
ret























