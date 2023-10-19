#include "consts_16.h"
.include "shuffle.inc"

.macro formseqto16_AVX2_128b p q r # param1表示输入的位置，param2表示输出的位置，param3表示该多项式有多少系数

vmovdqu		(\p     )*2(%rdi),%ymm4  #使用vmovdqa需要先将数据对齐，polyvec_16等是OK，注意uint8_t类型的参数
vmovdqu		(\p+  \r)*2(%rdi),%ymm5  #使用vmovdqu就不用考虑对齐
vmovdqu		(\p+ \r*2)*2(%rdi),%ymm6
vmovdqu		(\p+ \r*3)*2(%rdi),%ymm7
vmovdqu		(\p+\r*4)*2(%rdi),%ymm8
vmovdqu		(\p+\r*5)*2(%rdi),%ymm9
vmovdqu		(\p+\r*6)*2(%rdi),%ymm10
vmovdqu		(\p+\r*7)*2(%rdi),%ymm11

vmovdqa     SEQ_SHUFIDX_16*2(%rcx),%ymm0

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

vpermq      $0xD8,%ymm10,%ymm10
vpermq      $0xD8,%ymm5,%ymm5
vpermq      $0xD8,%ymm9,%ymm9
vpermq      $0xD8,%ymm4,%ymm4
vpermq      $0xD8,%ymm8,%ymm8
vpermq      $0xD8,%ymm3,%ymm3
vpermq      $0xD8,%ymm7,%ymm7
vpermq      $0xD8,%ymm11,%ymm11

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

.macro formseq_supp p q #补充的位置调换函数，每次调换16*14个系数的位置，对于to16/from16通用，因为使用两次formseq_supp就会相互抵消

vmovdqu		(\p     )*2(%rsi),%ymm1
vmovdqu		(\p+  16)*2(%rsi),%ymm2
vmovdqu		(\p+  32)*2(%rsi),%ymm3
vmovdqu		(\p+  48)*2(%rsi),%ymm4
vmovdqu		(\p+  64)*2(%rsi),%ymm5
vmovdqu		(\p+  80)*2(%rsi),%ymm6
vmovdqu		(\p+  96)*2(%rsi),%ymm7
vmovdqu		(\p+ 112)*2(%rsi),%ymm8
vmovdqu		(\p+ 128)*2(%rsi),%ymm9
vmovdqu		(\p+ 144)*2(%rsi),%ymm10
vmovdqu		(\p+ 160)*2(%rsi),%ymm11
vmovdqu		(\p+ 176)*2(%rsi),%ymm12
vmovdqu		(\p+ 192)*2(%rsi),%ymm13
vmovdqu		(\p+ 208)*2(%rsi),%ymm14

shuffle8    1,2,0,1
shuffle8    3,4,2,3
shuffle8    5,6,4,5
shuffle8    7,8,6,7
shuffle8    9,10,8,9
shuffle8    11,12,10,11
shuffle8    13,14,12,13

vmovdqu		%ymm0,(\q     )*2(%rdx)
vmovdqu		%ymm1,(\q+  16)*2(%rdx)
vmovdqu		%ymm2,(\q+  32)*2(%rdx)
vmovdqu		%ymm3,(\q+  48)*2(%rdx)
vmovdqu		%ymm4,(\q+  64)*2(%rdx)
vmovdqu		%ymm5,(\q+  80)*2(%rdx)
vmovdqu		%ymm6,(\q+  96)*2(%rdx)
vmovdqu		%ymm7,(\q+ 112)*2(%rdx)
vmovdqu		%ymm8,(\q+ 128)*2(%rdx)
vmovdqu		%ymm9,(\q+ 144)*2(%rdx)
vmovdqu		%ymm10,(\q+ 160)*2(%rdx)
vmovdqu		%ymm11,(\q+ 176)*2(%rdx)
vmovdqu		%ymm12,(\q+ 192)*2(%rdx)
vmovdqu		%ymm13,(\q+ 208)*2(%rdx)

.endm

.macro formseqfrom16_AVX2_128b p q r

vmovdqu		(\p     )*2(%rdx),%ymm6  # 使用vmovdqu就不用考虑对齐
vmovdqu		(\p+  32)*2(%rdx),%ymm10
vmovdqu		(\p+  64)*2(%rdx),%ymm9
vmovdqu		(\p+  96)*2(%rdx),%ymm8
vmovdqu		(\p+ 128)*2(%rdx),%ymm5
vmovdqu		(\p+ 160)*2(%rdx),%ymm4
vmovdqu		(\p+ 192)*2(%rdx),%ymm3
vmovdqu		(\p+ 224)*2(%rdx),%ymm11

vmovdqa     SEQ_INVSHUFIDX_16*2(%rcx),%ymm0  # 注意使用的是哪个参数

shuffle8    8,11,7,11
shuffle8    9,3,8,3
shuffle8    10,4,9,4
shuffle8    6,5,10,5

vpermq      $0xD8,%ymm10,%ymm10
vpermq      $0xD8,%ymm5,%ymm5
vpermq      $0xD8,%ymm9,%ymm9
vpermq      $0xD8,%ymm4,%ymm4
vpermq      $0xD8,%ymm8,%ymm8
vpermq      $0xD8,%ymm3,%ymm3
vpermq      $0xD8,%ymm7,%ymm7
vpermq      $0xD8,%ymm11,%ymm11

vpshufb     %ymm0, %ymm10, %ymm10
vpshufb     %ymm0, %ymm5, %ymm5
vpshufb     %ymm0, %ymm9, %ymm9
vpshufb     %ymm0, %ymm4, %ymm4
vpshufb     %ymm0, %ymm8, %ymm8
vpshufb     %ymm0, %ymm3, %ymm3
vpshufb     %ymm0, %ymm7, %ymm7
vpshufb     %ymm0, %ymm11, %ymm11

shuffle1	7,11,6,11
shuffle1	8,3,7,3
shuffle1	9,4,8,4
shuffle1	10,5,9,5

shuffle2	3,11,10,11
shuffle2	5,4,3,4
shuffle2	7,6,5,6
shuffle2	9,8,7,8

shuffle4	4,11,9,11
shuffle4	8,6,4,6
shuffle4	3,10,8,10
shuffle4	7,5,3,5

shuffle8	6,11,7,11
shuffle8	5,10,6,10
shuffle8	4,9,5,9
shuffle8    3,8,4,8

vmovdqu		%ymm4,(\q     )*2(%rdi)
vmovdqu		%ymm5,(\q+   \r)*2(%rdi)
vmovdqu		%ymm6,(\q+ \r*2)*2(%rdi)
vmovdqu		%ymm7,(\q+ \r*3)*2(%rdi)
vmovdqu		%ymm8,(\q+ \r*4)*2(%rdi)
vmovdqu		%ymm9,(\q+ \r*5)*2(%rdi)
vmovdqu		%ymm10,(\q+ \r*6)*2(%rdi)
vmovdqu		%ymm11,(\q+ \r*7)*2(%rdi)

.endm


.text

.global cdecl(poly_formseqto16_AVX2)
cdecl(poly_formseqto16_AVX2):
# the first part of to16 transformation
/* */
formseqto16_AVX2_128b 0 0 256
formseqto16_AVX2_128b 2048 16 256 # 因为AVX2寄存器不够，不能16个全部用来存储数据，所以每次只能完成一半的转换。因此，宏后面的数字要这样写，即两行为一组。此外，这个宏运行完，并没有完全变成16-way格式，而是a0~h0,a1~h1,i0~p0, i1~p1,...,a254~h254,a255~h255,i254~p254,i255~p255,还需要额外的一个宏定义才可以完成整体转换。
formseqto16_AVX2_128b 16 256 256
formseqto16_AVX2_128b 2064 272 256
formseqto16_AVX2_128b 32 512 256
formseqto16_AVX2_128b 2080 528 256
formseqto16_AVX2_128b 48 768 256
formseqto16_AVX2_128b 2096 784 256

formseqto16_AVX2_128b 64 1024 256
formseqto16_AVX2_128b 2112 1040 256
formseqto16_AVX2_128b 80 1280 256
formseqto16_AVX2_128b 2128 1296 256
formseqto16_AVX2_128b 96 1536 256
formseqto16_AVX2_128b 2144 1552 256
formseqto16_AVX2_128b 112 1792 256
formseqto16_AVX2_128b 2160 1808 256

formseqto16_AVX2_128b 128 2048 256
formseqto16_AVX2_128b 2176 2064 256
formseqto16_AVX2_128b 144 2304 256
formseqto16_AVX2_128b 2192 2320 256
formseqto16_AVX2_128b 160 2560 256
formseqto16_AVX2_128b 2208 2576 256
formseqto16_AVX2_128b 176 2816 256
formseqto16_AVX2_128b 2224 2832 256

formseqto16_AVX2_128b 192 3072 256
formseqto16_AVX2_128b 2240 3088 256
formseqto16_AVX2_128b 208 3328 256
formseqto16_AVX2_128b 2256 3344 256
formseqto16_AVX2_128b 224 3584 256
formseqto16_AVX2_128b 2272 3600 256
formseqto16_AVX2_128b 240 3840 256
formseqto16_AVX2_128b 2288 3856 256

# the second part of to16 transformation
formseq_supp 0 0
formseq_supp 224 224
formseq_supp 448 448
formseq_supp 672 672
formseq_supp 896 896
formseq_supp 1120 1120
formseq_supp 1344 1344
formseq_supp 1568 1568
formseq_supp 1792 1792
formseq_supp 2016 2016
formseq_supp 2240 2240
formseq_supp 2464 2464
formseq_supp 2688 2688
formseq_supp 2912 2912
formseq_supp 3136 3136
formseq_supp 3360 3360
formseq_supp 3584 3584
formseq_supp 3808 3808

vmovdqu		(4032     )*2(%rsi),%ymm1 # 剩下的4*16个系数不够再调用一次formseq_supp，所以直接单独写
vmovdqu		(4032+  16)*2(%rsi),%ymm2
vmovdqu		(4032+  32)*2(%rsi),%ymm3
vmovdqu		(4032+  48)*2(%rsi),%ymm4

shuffle8    1,2,0,1
shuffle8    3,4,2,3

vmovdqu		%ymm0,(4032     )*2(%rdx)
vmovdqu		%ymm1,(4032+  16)*2(%rdx)
vmovdqu		%ymm2,(4032+  32)*2(%rdx)
vmovdqu		%ymm3,(4032+  48)*2(%rdx)

ret


.global cdecl(keypair_formseqfrom16_AVX2)
cdecl(keypair_formseqfrom16_AVX2):
# the first part of from16 transformation
formseq_supp 0 0
formseq_supp 224 224
formseq_supp 448 448
formseq_supp 672 672
formseq_supp 896 896
formseq_supp 1120 1120
formseq_supp 1344 1344
formseq_supp 1568 1568
formseq_supp 1792 1792
formseq_supp 2016 2016

formseq_supp 2240 2240
formseq_supp 2464 2464
formseq_supp 2688 2688
formseq_supp 2912 2912
formseq_supp 3136 3136
formseq_supp 3360 3360
formseq_supp 3584 3584
formseq_supp 3808 3808
formseq_supp 4032 4032
formseq_supp 4256 4256

formseq_supp 4480 4480
formseq_supp 4704 4704
formseq_supp 4928 4928
formseq_supp 5152 5152
formseq_supp 5376 5376
formseq_supp 5600 5600
formseq_supp 5824 5824
formseq_supp 6048 6048
formseq_supp 6272 6272
formseq_supp 6496 6496

formseq_supp 6720 6720
formseq_supp 6944 6944 
formseq_supp 7168 7168
formseq_supp 7392 7392
formseq_supp 7616 7616
formseq_supp 7840 7840
formseq_supp 8064 8064
formseq_supp 8288 8288
formseq_supp 8512 8512
formseq_supp 8736 8736

formseq_supp 8960 8960

vmovdqu		(9184     )*2(%rsi),%ymm1 # 剩下的2*16个系数不够再调用一次formseq_supp，所以直接单独写
vmovdqu		(9184+  16)*2(%rsi),%ymm2

shuffle8    1,2,0,1

vmovdqu		%ymm0,(9184     )*2(%rdx)
vmovdqu		%ymm1,(9184+  16)*2(%rdx)

# the second part of from16 transformation
formseqfrom16_AVX2_128b 0 0 576
formseqfrom16_AVX2_128b 16 4608 576
formseqfrom16_AVX2_128b 256 16 576
formseqfrom16_AVX2_128b 272 4624 576
formseqfrom16_AVX2_128b 512 32 576
formseqfrom16_AVX2_128b 528 4640 576
formseqfrom16_AVX2_128b 768 48 576
formseqfrom16_AVX2_128b 784 4656 576

formseqfrom16_AVX2_128b 1024 64 576
formseqfrom16_AVX2_128b 1040 4672 576
formseqfrom16_AVX2_128b 1280 80 576
formseqfrom16_AVX2_128b 1296 4688 576
formseqfrom16_AVX2_128b 1536 96 576
formseqfrom16_AVX2_128b 1552 4704 576
formseqfrom16_AVX2_128b 1792 112 576
formseqfrom16_AVX2_128b 1808 4720 576

formseqfrom16_AVX2_128b 2048 128 576
formseqfrom16_AVX2_128b 2064 4736 576
formseqfrom16_AVX2_128b 2304 144 576
formseqfrom16_AVX2_128b 2320 4752 576
formseqfrom16_AVX2_128b 2560 160 576
formseqfrom16_AVX2_128b 2576 4768 576
formseqfrom16_AVX2_128b 2816 176 576
formseqfrom16_AVX2_128b 2832 4784 576

########################################

formseqfrom16_AVX2_128b  3072 192 576
formseqfrom16_AVX2_128b  3088 4800 576
formseqfrom16_AVX2_128b  3328 208 576
formseqfrom16_AVX2_128b  3344 4816 576
formseqfrom16_AVX2_128b  3584 224 576
formseqfrom16_AVX2_128b  3600 4832 576
formseqfrom16_AVX2_128b  3840 240 576
formseqfrom16_AVX2_128b  3856 4848 576

formseqfrom16_AVX2_128b  4096 256 576
formseqfrom16_AVX2_128b  4112 4864 576
formseqfrom16_AVX2_128b  4352 272 576
formseqfrom16_AVX2_128b  4368 4880 576
formseqfrom16_AVX2_128b  4608 288 576
formseqfrom16_AVX2_128b  4624 4896 576
formseqfrom16_AVX2_128b  4864 304 576
formseqfrom16_AVX2_128b  4880 4912 576

formseqfrom16_AVX2_128b  5120 320 576
formseqfrom16_AVX2_128b  5136 4928 576
formseqfrom16_AVX2_128b  5376 336 576
formseqfrom16_AVX2_128b  5392 4944 576
formseqfrom16_AVX2_128b  5632 352 576
formseqfrom16_AVX2_128b  5648 4960 576
formseqfrom16_AVX2_128b  5888 368 576
formseqfrom16_AVX2_128b  5904 4976 576

########################################

formseqfrom16_AVX2_128b  6144 384 576
formseqfrom16_AVX2_128b  6160 4992 576
formseqfrom16_AVX2_128b  6400 400 576
formseqfrom16_AVX2_128b  6416 5008 576
formseqfrom16_AVX2_128b  6656 416 576
formseqfrom16_AVX2_128b  6672 5024 576
formseqfrom16_AVX2_128b  6912 432 576
formseqfrom16_AVX2_128b  6928 5040 576

formseqfrom16_AVX2_128b  7168 448 576
formseqfrom16_AVX2_128b  7184 5056 576
formseqfrom16_AVX2_128b  7424 464 576
formseqfrom16_AVX2_128b  7440 5072 576
formseqfrom16_AVX2_128b  7680 480 576
formseqfrom16_AVX2_128b  7696 5088 576
formseqfrom16_AVX2_128b  7936 496 576
formseqfrom16_AVX2_128b  7952 5104 576

formseqfrom16_AVX2_128b  8192 512 576
formseqfrom16_AVX2_128b  8208 5120 576
formseqfrom16_AVX2_128b  8448 528 576
formseqfrom16_AVX2_128b  8464 5136 576
formseqfrom16_AVX2_128b  8704 544 576
formseqfrom16_AVX2_128b  8720 5152 576
formseqfrom16_AVX2_128b  8960 560 576
formseqfrom16_AVX2_128b  8976 5168 576

ret


.global cdecl(keypair_formseqto16_AVX2)
cdecl(keypair_formseqto16_AVX2):
# the first part of to16 transformation
formseqto16_AVX2_128b 0 0 576
formseqto16_AVX2_128b 4608 16 576
formseqto16_AVX2_128b 16 256 576
formseqto16_AVX2_128b 4624 272 576
formseqto16_AVX2_128b 32 512 576
formseqto16_AVX2_128b 4640 528 576
formseqto16_AVX2_128b 48 768 576
formseqto16_AVX2_128b 4656 784 576

formseqto16_AVX2_128b 64 1024 576
formseqto16_AVX2_128b 4672 1040 576
formseqto16_AVX2_128b 80 1280 576
formseqto16_AVX2_128b 4688 1296 576
formseqto16_AVX2_128b 96 1536 576
formseqto16_AVX2_128b 4704 1552 576
formseqto16_AVX2_128b 112 1792 576
formseqto16_AVX2_128b 4720 1808 576

formseqto16_AVX2_128b 128 2048 576
formseqto16_AVX2_128b 4736 2064 576
formseqto16_AVX2_128b 144 2304 576
formseqto16_AVX2_128b 4752 2320 576
formseqto16_AVX2_128b 160 2560 576
formseqto16_AVX2_128b 4768 2576 576
formseqto16_AVX2_128b 176 2816 576
formseqto16_AVX2_128b 4784 2832 576

########################################

formseqto16_AVX2_128b 192 3072 576
formseqto16_AVX2_128b 4800 3088 576
formseqto16_AVX2_128b 208 3328 576
formseqto16_AVX2_128b 4816 3344 576
formseqto16_AVX2_128b 224 3584 576
formseqto16_AVX2_128b 4832 3600 576
formseqto16_AVX2_128b 240 3840 576
formseqto16_AVX2_128b 4848 3856 576

formseqto16_AVX2_128b 256 4096 576
formseqto16_AVX2_128b 4864 4112 576
formseqto16_AVX2_128b 272 4352 576
formseqto16_AVX2_128b 4880 4368 576
formseqto16_AVX2_128b 288 4608 576
formseqto16_AVX2_128b 4896 4624 576
formseqto16_AVX2_128b 304 4864 576
formseqto16_AVX2_128b 4912 4880 576

formseqto16_AVX2_128b 320 5120 576
formseqto16_AVX2_128b 4928 5136 576
formseqto16_AVX2_128b 336 5376 576
formseqto16_AVX2_128b 4944 5392 576
formseqto16_AVX2_128b 352 5632 576
formseqto16_AVX2_128b 4960 5648 576
formseqto16_AVX2_128b 368 5888 576
formseqto16_AVX2_128b 4976 5904 576

########################################

formseqto16_AVX2_128b 384 6144 576
formseqto16_AVX2_128b 4992 6160 576
formseqto16_AVX2_128b 400 6400 576
formseqto16_AVX2_128b 5008 6416 576
formseqto16_AVX2_128b 416 6656 576
formseqto16_AVX2_128b 5024 6672 576
formseqto16_AVX2_128b 432 6912 576
formseqto16_AVX2_128b 5040 6928 576

formseqto16_AVX2_128b 448 7168 576
formseqto16_AVX2_128b 5056 7184 576
formseqto16_AVX2_128b 464 7424 576
formseqto16_AVX2_128b 5072 7440 576
formseqto16_AVX2_128b 480 7680 576
formseqto16_AVX2_128b 5088 7696 576
formseqto16_AVX2_128b 496 7936 576
formseqto16_AVX2_128b 5104 7952 576

formseqto16_AVX2_128b 512 8192 576
formseqto16_AVX2_128b 5120 8208 576
formseqto16_AVX2_128b 528 8448 576
formseqto16_AVX2_128b 5136 8464 576
formseqto16_AVX2_128b 544 8704 576
formseqto16_AVX2_128b 5152 8720 576
formseqto16_AVX2_128b 560 8960 576
formseqto16_AVX2_128b 5168 8976 576

# the second part of to16 transformation
formseq_supp 0 0
formseq_supp 224 224
formseq_supp 448 448
formseq_supp 672 672
formseq_supp 896 896
formseq_supp 1120 1120
formseq_supp 1344 1344
formseq_supp 1568 1568
formseq_supp 1792 1792
formseq_supp 2016 2016

formseq_supp 2240 2240
formseq_supp 2464 2464
formseq_supp 2688 2688
formseq_supp 2912 2912
formseq_supp 3136 3136
formseq_supp 3360 3360
formseq_supp 3584 3584
formseq_supp 3808 3808
formseq_supp 4032 4032
formseq_supp 4256 4256

formseq_supp 4480 4480
formseq_supp 4704 4704
formseq_supp 4928 4928
formseq_supp 5152 5152
formseq_supp 5376 5376
formseq_supp 5600 5600
formseq_supp 5824 5824
formseq_supp 6048 6048
formseq_supp 6272 6272
formseq_supp 6496 6496

formseq_supp 6720 6720
formseq_supp 6944 6944 
formseq_supp 7168 7168
formseq_supp 7392 7392
formseq_supp 7616 7616
formseq_supp 7840 7840
formseq_supp 8064 8064
formseq_supp 8288 8288
formseq_supp 8512 8512
formseq_supp 8736 8736

formseq_supp 8960 8960

vmovdqu		(9184     )*2(%rsi),%ymm1 # 剩下的2*16个系数不够再调用一次formseq_supp，所以直接单独写
vmovdqu		(9184+  16)*2(%rsi),%ymm2

shuffle8    1,2,0,1

vmovdqu		%ymm0,(9184     )*2(%rdx)
vmovdqu		%ymm1,(9184+  16)*2(%rdx)

ret


.global cdecl(cipher_formseqto16_AVX2)
cdecl(cipher_formseqto16_AVX2):
# the first part of to16 transformation
formseqto16_AVX2_128b 0 0 544  # 544 = (3*320+128)/2
formseqto16_AVX2_128b 4352 16 544  # 4352 = 544*8
formseqto16_AVX2_128b 16 256 544
formseqto16_AVX2_128b 4368 272 544
formseqto16_AVX2_128b 32 512 544
formseqto16_AVX2_128b 4384 528 544
formseqto16_AVX2_128b 48 768 544
formseqto16_AVX2_128b 4400 784 544
formseqto16_AVX2_128b 64 1024 544
formseqto16_AVX2_128b 4416 1040 544

formseqto16_AVX2_128b 80 1280 544
formseqto16_AVX2_128b 4432 1296 544
formseqto16_AVX2_128b 96 1536 544
formseqto16_AVX2_128b 4448 1552 544
formseqto16_AVX2_128b 112 1792 544
formseqto16_AVX2_128b 4464 1808 544
formseqto16_AVX2_128b 128 2048 544
formseqto16_AVX2_128b 4480 2064 544
formseqto16_AVX2_128b 144 2304 544
formseqto16_AVX2_128b 4496 2320 544

########################################

formseqto16_AVX2_128b 160 2560 544
formseqto16_AVX2_128b 4512 2576 544
formseqto16_AVX2_128b 176 2816 544
formseqto16_AVX2_128b 4528 2832 544
formseqto16_AVX2_128b 192 3072 544
formseqto16_AVX2_128b 4544 3088 544
formseqto16_AVX2_128b 208 3328 544
formseqto16_AVX2_128b 4560 3344 544
formseqto16_AVX2_128b 224 3584 544
formseqto16_AVX2_128b 4576 3600 544

formseqto16_AVX2_128b 240 3840 544
formseqto16_AVX2_128b 4592 3856 544
formseqto16_AVX2_128b 256 4096 544
formseqto16_AVX2_128b 4608 4112 544
formseqto16_AVX2_128b 272 4352 544
formseqto16_AVX2_128b 4624 4368 544
formseqto16_AVX2_128b 288 4608 544
formseqto16_AVX2_128b 4640 4624 544
formseqto16_AVX2_128b 304 4864 544
formseqto16_AVX2_128b 4656 4880 544

########################################

formseqto16_AVX2_128b 320 5120 544
formseqto16_AVX2_128b 4672 5136 544
formseqto16_AVX2_128b 336 5376 544
formseqto16_AVX2_128b 4688 5392 544
formseqto16_AVX2_128b 352 5632 544
formseqto16_AVX2_128b 4704 5648 544
formseqto16_AVX2_128b 368 5888 544
formseqto16_AVX2_128b 4720 5904 544
formseqto16_AVX2_128b 384 6144 544
formseqto16_AVX2_128b 4736 6160 544

formseqto16_AVX2_128b 400 6400 544
formseqto16_AVX2_128b 4752 6416 544
formseqto16_AVX2_128b 416 6656 544
formseqto16_AVX2_128b 4768 6672 544
formseqto16_AVX2_128b 432 6912 544
formseqto16_AVX2_128b 4784 6928 544
formseqto16_AVX2_128b 448 7168 544
formseqto16_AVX2_128b 4800 7184 544
formseqto16_AVX2_128b 464 7424 544
formseqto16_AVX2_128b 4816 7440 544  # 3*160*16*2*8B结束

########################################

formseqto16_AVX2_128b 480 7680 544
formseqto16_AVX2_128b 4832 7696 544
formseqto16_AVX2_128b 496 7936 544
formseqto16_AVX2_128b 4848 7952 544
formseqto16_AVX2_128b 512 8192 544
formseqto16_AVX2_128b 4864 8208 544
formseqto16_AVX2_128b 528 8448 544
formseqto16_AVX2_128b 4880 8464 544  # 64*16*2*8B结束

# the second part of to16 transformation
formseq_supp 0 0
formseq_supp 224 224
formseq_supp 448 448
formseq_supp 672 672
formseq_supp 896 896
formseq_supp 1120 1120
formseq_supp 1344 1344
formseq_supp 1568 1568
formseq_supp 1792 1792
formseq_supp 2016 2016

formseq_supp 2240 2240
formseq_supp 2464 2464
formseq_supp 2688 2688
formseq_supp 2912 2912
formseq_supp 3136 3136
formseq_supp 3360 3360
formseq_supp 3584 3584
formseq_supp 3808 3808
formseq_supp 4032 4032
formseq_supp 4256 4256

formseq_supp 4480 4480
formseq_supp 4704 4704
formseq_supp 4928 4928
formseq_supp 5152 5152
formseq_supp 5376 5376
formseq_supp 5600 5600
formseq_supp 5824 5824
formseq_supp 6048 6048
formseq_supp 6272 6272
formseq_supp 6496 6496

formseq_supp 6720 6720
formseq_supp 6944 6944 
formseq_supp 7168 7168
formseq_supp 7392 7392
formseq_supp 7616 7616
formseq_supp 7840 7840
formseq_supp 8064 8064
formseq_supp 8288 8288

vmovdqu		(8512     )*2(%rsi),%ymm1
vmovdqu		(8512+  16)*2(%rsi),%ymm2
vmovdqu		(8512+  32)*2(%rsi),%ymm3
vmovdqu		(8512+  48)*2(%rsi),%ymm4
vmovdqu		(8512+  64)*2(%rsi),%ymm5
vmovdqu		(8512+  80)*2(%rsi),%ymm6
vmovdqu		(8512+  96)*2(%rsi),%ymm7
vmovdqu		(8512+ 112)*2(%rsi),%ymm8
vmovdqu		(8512+ 128)*2(%rsi),%ymm9
vmovdqu		(8512+ 144)*2(%rsi),%ymm10
vmovdqu		(8512+ 160)*2(%rsi),%ymm11
vmovdqu		(8512+ 176)*2(%rsi),%ymm12

shuffle8    1,2,0,1
shuffle8    3,4,2,3
shuffle8    5,6,4,5
shuffle8    7,8,6,7
shuffle8    9,10,8,9
shuffle8    11,12,10,11

vmovdqu		%ymm0,(8512     )*2(%rdx)
vmovdqu		%ymm1,(8512+  16)*2(%rdx)
vmovdqu		%ymm2,(8512+  32)*2(%rdx)
vmovdqu		%ymm3,(8512+  48)*2(%rdx)
vmovdqu		%ymm4,(8512+  64)*2(%rdx)
vmovdqu		%ymm5,(8512+  80)*2(%rdx)
vmovdqu		%ymm6,(8512+  96)*2(%rdx)
vmovdqu		%ymm7,(8512+ 112)*2(%rdx)
vmovdqu		%ymm8,(8512+ 128)*2(%rdx)
vmovdqu		%ymm9,(8512+ 144)*2(%rdx)
vmovdqu		%ymm10,(8512+ 160)*2(%rdx)
vmovdqu		%ymm11,(8512+ 176)*2(%rdx)

ret


.global cdecl(cipher_formseqfrom16_AVX2)
cdecl(cipher_formseqfrom16_AVX2):
# the first part of from16 transformation
formseq_supp 0 0
formseq_supp 224 224
formseq_supp 448 448
formseq_supp 672 672
formseq_supp 896 896
formseq_supp 1120 1120
formseq_supp 1344 1344
formseq_supp 1568 1568
formseq_supp 1792 1792
formseq_supp 2016 2016

formseq_supp 2240 2240
formseq_supp 2464 2464
formseq_supp 2688 2688
formseq_supp 2912 2912
formseq_supp 3136 3136
formseq_supp 3360 3360
formseq_supp 3584 3584
formseq_supp 3808 3808
formseq_supp 4032 4032
formseq_supp 4256 4256

formseq_supp 4480 4480
formseq_supp 4704 4704
formseq_supp 4928 4928
formseq_supp 5152 5152
formseq_supp 5376 5376
formseq_supp 5600 5600
formseq_supp 5824 5824
formseq_supp 6048 6048
formseq_supp 6272 6272
formseq_supp 6496 6496

formseq_supp 6720 6720
formseq_supp 6944 6944 
formseq_supp 7168 7168
formseq_supp 7392 7392
formseq_supp 7616 7616
formseq_supp 7840 7840
formseq_supp 8064 8064
formseq_supp 8288 8288

vmovdqu		(8512     )*2(%rsi),%ymm1
vmovdqu		(8512+  16)*2(%rsi),%ymm2
vmovdqu		(8512+  32)*2(%rsi),%ymm3
vmovdqu		(8512+  48)*2(%rsi),%ymm4
vmovdqu		(8512+  64)*2(%rsi),%ymm5
vmovdqu		(8512+  80)*2(%rsi),%ymm6
vmovdqu		(8512+  96)*2(%rsi),%ymm7
vmovdqu		(8512+ 112)*2(%rsi),%ymm8
vmovdqu		(8512+ 128)*2(%rsi),%ymm9
vmovdqu		(8512+ 144)*2(%rsi),%ymm10
vmovdqu		(8512+ 160)*2(%rsi),%ymm11
vmovdqu		(8512+ 176)*2(%rsi),%ymm12

shuffle8    1,2,0,1
shuffle8    3,4,2,3
shuffle8    5,6,4,5
shuffle8    7,8,6,7
shuffle8    9,10,8,9
shuffle8    11,12,10,11

vmovdqu		%ymm0,(8512     )*2(%rdx)
vmovdqu		%ymm1,(8512+  16)*2(%rdx)
vmovdqu		%ymm2,(8512+  32)*2(%rdx)
vmovdqu		%ymm3,(8512+  48)*2(%rdx)
vmovdqu		%ymm4,(8512+  64)*2(%rdx)
vmovdqu		%ymm5,(8512+  80)*2(%rdx)
vmovdqu		%ymm6,(8512+  96)*2(%rdx)
vmovdqu		%ymm7,(8512+ 112)*2(%rdx)
vmovdqu		%ymm8,(8512+ 128)*2(%rdx)
vmovdqu		%ymm9,(8512+ 144)*2(%rdx)
vmovdqu		%ymm10,(8512+ 160)*2(%rdx)
vmovdqu		%ymm11,(8512+ 176)*2(%rdx)

# the second part of from16 transformation
formseqfrom16_AVX2_128b 0 0 544
formseqfrom16_AVX2_128b 16 4352 544
formseqfrom16_AVX2_128b 256 16 544
formseqfrom16_AVX2_128b 272 4368 544
formseqfrom16_AVX2_128b 512 32 544
formseqfrom16_AVX2_128b 528 4384 544
formseqfrom16_AVX2_128b 768 48 544
formseqfrom16_AVX2_128b 784 4400 544
formseqfrom16_AVX2_128b 1024 64 544
formseqfrom16_AVX2_128b 1040 4416 544

formseqfrom16_AVX2_128b 1280 80 544
formseqfrom16_AVX2_128b 1296 4432 544
formseqfrom16_AVX2_128b 1536 96 544
formseqfrom16_AVX2_128b 1552 4448 544
formseqfrom16_AVX2_128b 1792 112 544
formseqfrom16_AVX2_128b 1808 4464 544
formseqfrom16_AVX2_128b 2048 128 544
formseqfrom16_AVX2_128b 2064 4480 544
formseqfrom16_AVX2_128b 2304 144 544
formseqfrom16_AVX2_128b 2320 4496 544

########################################

formseqfrom16_AVX2_128b 2560 160 544
formseqfrom16_AVX2_128b 2576 4512 544
formseqfrom16_AVX2_128b 2816 176 544
formseqfrom16_AVX2_128b 2832 4528 544
formseqfrom16_AVX2_128b 3072 192 544
formseqfrom16_AVX2_128b 3088 4544 544
formseqfrom16_AVX2_128b 3328 208 544
formseqfrom16_AVX2_128b 3344 4560 544
formseqfrom16_AVX2_128b 3584 224 544
formseqfrom16_AVX2_128b 3600 4576 544

formseqfrom16_AVX2_128b 3840 240 544
formseqfrom16_AVX2_128b 3856 4592 544
formseqfrom16_AVX2_128b 4096 256 544
formseqfrom16_AVX2_128b 4112 4608 544
formseqfrom16_AVX2_128b 4352 272 544
formseqfrom16_AVX2_128b 4368 4624 544
formseqfrom16_AVX2_128b 4608 288 544
formseqfrom16_AVX2_128b 4624 4640 544
formseqfrom16_AVX2_128b 4864 304 544
formseqfrom16_AVX2_128b 4880 4656 544

########################################

formseqfrom16_AVX2_128b 5120 320 544
formseqfrom16_AVX2_128b 5136 4672 544
formseqfrom16_AVX2_128b 5376 336 544
formseqfrom16_AVX2_128b 5392 4688 544
formseqfrom16_AVX2_128b 5632 352 544
formseqfrom16_AVX2_128b 5648 4704 544
formseqfrom16_AVX2_128b 5888 368 544
formseqfrom16_AVX2_128b 5904 4720 544
formseqfrom16_AVX2_128b 6144 384 544
formseqfrom16_AVX2_128b 6160 4736 544

formseqfrom16_AVX2_128b 6400 400 544
formseqfrom16_AVX2_128b 6416 4752 544
formseqfrom16_AVX2_128b 6656 416 544
formseqfrom16_AVX2_128b 6672 4768 544
formseqfrom16_AVX2_128b 6912 432 544
formseqfrom16_AVX2_128b 6928 4784 544
formseqfrom16_AVX2_128b 7168 448 544
formseqfrom16_AVX2_128b 7184 4800 544
formseqfrom16_AVX2_128b 7424 464 544
formseqfrom16_AVX2_128b 7440 4816 544  # 3*160*16*2*8B结束

########################################

formseqfrom16_AVX2_128b 7680 480 544
formseqfrom16_AVX2_128b 7696 4832 544
formseqfrom16_AVX2_128b 7936 496 544
formseqfrom16_AVX2_128b 7952 4848 544
formseqfrom16_AVX2_128b 8192 512 544
formseqfrom16_AVX2_128b 8208 4864 544
formseqfrom16_AVX2_128b 8448 528 544
formseqfrom16_AVX2_128b 8464 4880 544

ret