#include "consts_16.h"
.include "shuffle.inc"

.macro matrix_formseqto16_avx2_256 p q

vmovdqu		(\p     )*2(%rdi),%ymm4  #使用vmovdqa需要先将数据对齐，polyvec_16等是OK，注意uint8_t类型的参数
vmovdqu		(\p+ 256)*2(%rdi),%ymm5  #使用vmovdqu就不用考虑对齐
vmovdqu		(\p+ 512)*2(%rdi),%ymm6
vmovdqu		(\p+ 768)*2(%rdi),%ymm7
vmovdqu		(\p+1024)*2(%rdi),%ymm8
vmovdqu		(\p+1280)*2(%rdi),%ymm9
vmovdqu		(\p+1536)*2(%rdi),%ymm10
vmovdqu		(\p+1792)*2(%rdi),%ymm11

vmovdqa     SEQ_SHUFIDX_16*2(%rsi),%ymm0

shuffle8    4,8,3,8
shuffle8	5,9,4,9
shuffle8	6,10,5,10
shuffle8	7,11,6,11

shuffle4	3,5,7,5
shuffle4	8,10,3,10
shuffle4	4,6,8,6
shuffle4	9,11,4,11

shuffle2	7,8,9,8
shuffle2	5,6,7,6
shuffle2	3,4,5,4
shuffle2	10,11,3,11

shuffle1	9,5,10,5
shuffle1	8,4,9,4
shuffle1	7,3,8,3
shuffle1	6,11,7,11

vpshufb     %ymm0, %ymm10, %ymm10
vpshufb     %ymm0, %ymm5, %ymm5
vpshufb     %ymm0, %ymm9, %ymm9
vpshufb     %ymm0, %ymm4, %ymm4
vpshufb     %ymm0, %ymm8, %ymm8
vpshufb     %ymm0, %ymm3, %ymm3
vpshufb     %ymm0, %ymm7, %ymm7
vpshufb     %ymm0, %ymm11, %ymm11

shuffle8    10,5,6,5
shuffle8    9,4,10,4
shuffle8    8,3,9,3
shuffle8    7,11,8,11

vmovdqu		%ymm6,(\q     )*2(%rsi)
vmovdqu		%ymm10,(\q+  32)*2(%rsi)
vmovdqu		%ymm9,(\q+  64)*2(%rsi)
vmovdqu		%ymm8,(\q+  96)*2(%rsi)
vmovdqu		%ymm5,(\q+ 128)*2(%rsi)
vmovdqu		%ymm4,(\q+ 160)*2(%rsi)
vmovdqu		%ymm3,(\q+ 192)*2(%rsi)
vmovdqu		%ymm11,(\q+ 224)*2(%rsi)

.endm

.text
.global cdecl(matrix_formseqto16)
cdecl(matrix_formseqto16):
# mov     %rdx, %ebx
matrix_formseqto16_avx2_256 %rdx %rdx  # using %rdx as the parameter is wrong

ret


.global cdecl(matrix_formseqfrom16)
cdecl(matrix_formseqfrom16):

#matrix_formseqfrom16_avx2_256 0 0  //not written

ret