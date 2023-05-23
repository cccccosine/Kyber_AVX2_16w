#include "ntt_16_consts.h"
.include "fq.inc"


.text
nttunpack256_avx:
#load 1
vmovdqa		32(%rdi),%ymm1     #a1
vmovdqa		256(%rdi),%ymm2    #a8
vmovdqa		2048(%rdi),%ymm3   #a64
vmovdqa		128(%rdi),%ymm4    #a4
vmovdqa		1024(%rdi),%ymm5   #a32
vmovdqa		64(%rdi),%ymm6     #a2
vmovdqa		512(%rdi),%ymm7    #a16

vmovdqa		96(%rdi),%ymm8     #a3
vmovdqa		768(%rdi),%ymm9    #a24
vmovdqa		2080(%rdi),%ymm10  #a65
vmovdqa		384(%rdi),%ymm11   #a12
vmovdqa		3072(%rdi),%ymm12  #a96
vmovdqa		192(%rdi),%ymm13   #a6
vmovdqa		1536(%rdi),%ymm14  #a48

#store 
vmovdqa		%ymm2,32(%rdi)
vmovdqa		%ymm3,256(%rdi)
vmovdqa		%ymm4,2048(%rdi)
vmovdqa		%ymm5,128(%rdi)
vmovdqa		%ymm6,1024(%rdi)
vmovdqa		%ymm7,64(%rdi)
vmovdqa		%ymm1,512(%rdi)

vmovdqa		%ymm9,96(%rdi)
vmovdqa		%ymm10,768(%rdi)
vmovdqa		%ymm11,2080(%rdi)
vmovdqa		%ymm12,384(%rdi)
vmovdqa		%ymm13,3072(%rdi)
vmovdqa		%ymm14,192(%rdi)
vmovdqa		%ymm8,1536(%rdi)

######################################

#load 2
vmovdqa		160(%rdi),%ymm1    #a5
vmovdqa		1280(%rdi),%ymm2   #a40
vmovdqa		2112(%rdi),%ymm3   #a66
vmovdqa		640(%rdi),%ymm4    #a20
vmovdqa		1056(%rdi),%ymm5   #a33
vmovdqa		320(%rdi),%ymm6    #a10
vmovdqa		2560(%rdi),%ymm7   #a80

vmovdqa		224(%rdi),%ymm8    #a7
vmovdqa		1792(%rdi),%ymm9   #a56
vmovdqa		2144(%rdi),%ymm10  #a67
vmovdqa		896(%rdi),%ymm11   #a28
vmovdqa		3104(%rdi),%ymm12  #a97
vmovdqa		448(%rdi),%ymm13   #a14
vmovdqa		3584(%rdi),%ymm14  #a112

#store 
vmovdqa		%ymm2,160(%rdi)
vmovdqa		%ymm3,1280(%rdi)
vmovdqa		%ymm4,2112(%rdi)
vmovdqa		%ymm5,640(%rdi)
vmovdqa		%ymm6,1056(%rdi)
vmovdqa		%ymm7,320(%rdi)
vmovdqa		%ymm1,2560(%rdi)

vmovdqa		%ymm9,224(%rdi)
vmovdqa		%ymm10,1792(%rdi)
vmovdqa		%ymm11,2144(%rdi)
vmovdqa		%ymm12,896(%rdi)
vmovdqa		%ymm13,3104(%rdi)
vmovdqa		%ymm14,448(%rdi)
vmovdqa		%ymm8,3584(%rdi)

######################################

#load 3
vmovdqa		288(%rdi),%ymm1    #a9
vmovdqa		2304(%rdi),%ymm2   #a72
vmovdqa		2176(%rdi),%ymm3   #a68
vmovdqa		1152(%rdi),%ymm4   #a36
vmovdqa		1088(%rdi),%ymm5   #a34
vmovdqa		576(%rdi),%ymm6    #a18
vmovdqa		544(%rdi),%ymm7    #a17

vmovdqa		352(%rdi),%ymm8    #a11
vmovdqa		2816(%rdi),%ymm9   #a88
vmovdqa		2208(%rdi),%ymm10  #a69
vmovdqa		1408(%rdi),%ymm11  #a44
vmovdqa		3136(%rdi),%ymm12  #a98
vmovdqa		704(%rdi),%ymm13   #a22
vmovdqa		1568(%rdi),%ymm14  #a49

#store 
vmovdqa		%ymm2,288(%rdi)
vmovdqa		%ymm3,2304(%rdi)
vmovdqa		%ymm4,2176(%rdi)
vmovdqa		%ymm5,1152(%rdi)
vmovdqa		%ymm6,1088(%rdi)
vmovdqa		%ymm7,576(%rdi)
vmovdqa		%ymm1,544(%rdi)

vmovdqa		%ymm9,352(%rdi)
vmovdqa		%ymm10,2816(%rdi)
vmovdqa		%ymm11,2208(%rdi)
vmovdqa		%ymm12,1408(%rdi)
vmovdqa		%ymm13,3136(%rdi)
vmovdqa		%ymm14,704(%rdi)
vmovdqa		%ymm8,1568(%rdi)

######################################

#load 4
vmovdqa		416(%rdi),%ymm1    #a13
vmovdqa		3328(%rdi),%ymm2   #a104
vmovdqa		2240(%rdi),%ymm3   #a70
vmovdqa		1664(%rdi),%ymm4   #a52
vmovdqa		1120(%rdi),%ymm5   #a35
vmovdqa		832(%rdi),%ymm6    #a26
vmovdqa		2592(%rdi),%ymm7   #a81

vmovdqa		480(%rdi),%ymm8    #a15
vmovdqa		3840(%rdi),%ymm9   #a120
vmovdqa		2272(%rdi),%ymm10  #a71
vmovdqa		1920(%rdi),%ymm11  #a60
vmovdqa		3168(%rdi),%ymm12  #a99
vmovdqa		960(%rdi),%ymm13   #a30
vmovdqa		3616(%rdi),%ymm14  #a113

#store 
vmovdqa		%ymm2,416(%rdi)
vmovdqa		%ymm3,3328(%rdi)
vmovdqa		%ymm4,2240(%rdi)
vmovdqa		%ymm5,1664(%rdi)
vmovdqa		%ymm6,1120(%rdi)
vmovdqa		%ymm7,832(%rdi)
vmovdqa		%ymm1,2592(%rdi)

vmovdqa		%ymm9,480(%rdi)
vmovdqa		%ymm10,3840(%rdi)
vmovdqa		%ymm11,2272(%rdi)
vmovdqa		%ymm12,1920(%rdi)
vmovdqa		%ymm13,3168(%rdi)
vmovdqa		%ymm14,960(%rdi)
vmovdqa		%ymm8,3616(%rdi)

######################################

#load 5
vmovdqa		608(%rdi),%ymm1    #a19
vmovdqa		800(%rdi),%ymm2    #a25
vmovdqa		2336(%rdi),%ymm3   #a73
vmovdqa		2432(%rdi),%ymm4   #a76
vmovdqa		3200(%rdi),%ymm5   #a100
vmovdqa		1216(%rdi),%ymm6   #a38
vmovdqa		1600(%rdi),%ymm7   #a50

vmovdqa		672(%rdi),%ymm8    #a21
vmovdqa		1312(%rdi),%ymm9   #a41
vmovdqa		2368(%rdi),%ymm10  #a74
vmovdqa		2688(%rdi),%ymm11  #a84
vmovdqa		1184(%rdi),%ymm12  #a37
vmovdqa		1344(%rdi),%ymm13  #a42
vmovdqa		2624(%rdi),%ymm14  #a82

#store 
vmovdqa		%ymm2,608(%rdi)
vmovdqa		%ymm3,800(%rdi)
vmovdqa		%ymm4,2336(%rdi)
vmovdqa		%ymm5,2432(%rdi)
vmovdqa		%ymm6,3200(%rdi)
vmovdqa		%ymm7,1216(%rdi)
vmovdqa		%ymm1,1600(%rdi)

vmovdqa		%ymm9,672(%rdi)
vmovdqa		%ymm10,1312(%rdi)
vmovdqa		%ymm11,2368(%rdi)
vmovdqa		%ymm12,2688(%rdi)
vmovdqa		%ymm13,1184(%rdi)
vmovdqa		%ymm14,1344(%rdi)
vmovdqa		%ymm8,2624(%rdi)

######################################

#load 6
vmovdqa		736(%rdi),%ymm1    #a23
vmovdqa		1824(%rdi),%ymm2   #a57
vmovdqa		2400(%rdi),%ymm3   #a75
vmovdqa		2944(%rdi),%ymm4   #a92
vmovdqa		3232(%rdi),%ymm5   #a101
vmovdqa		1472(%rdi),%ymm6   #a46
vmovdqa		3648(%rdi),%ymm7   #a114

vmovdqa		864(%rdi),%ymm8    #a27
vmovdqa		2848(%rdi),%ymm9   #a89
vmovdqa		2464(%rdi),%ymm10  #a77
vmovdqa		3456(%rdi),%ymm11  #a108
vmovdqa		3264(%rdi),%ymm12  #a102
vmovdqa		1728(%rdi),%ymm13  #a54
vmovdqa		1632(%rdi),%ymm14  #a51

#store 
vmovdqa		%ymm2,736(%rdi)
vmovdqa		%ymm3,1824(%rdi)
vmovdqa		%ymm4,2400(%rdi)
vmovdqa		%ymm5,2944(%rdi)
vmovdqa		%ymm6,3232(%rdi)
vmovdqa		%ymm7,1472(%rdi)
vmovdqa		%ymm1,3648(%rdi)

vmovdqa		%ymm9,864(%rdi)
vmovdqa		%ymm10,2848(%rdi)
vmovdqa		%ymm11,2464(%rdi)
vmovdqa		%ymm12,3456(%rdi)
vmovdqa		%ymm13,3264(%rdi)
vmovdqa		%ymm14,1728(%rdi)
vmovdqa		%ymm8,1632(%rdi)

######################################

#load 7
vmovdqa		928(%rdi),%ymm1    #a29
vmovdqa		3360(%rdi),%ymm2   #a105
vmovdqa		2496(%rdi),%ymm3   #a78
vmovdqa		3712(%rdi),%ymm4   #a116
vmovdqa		1248(%rdi),%ymm5   #a39
vmovdqa		1856(%rdi),%ymm6   #a58
vmovdqa		2656(%rdi),%ymm7   #a83

vmovdqa		992(%rdi),%ymm8    #a31
vmovdqa		3872(%rdi),%ymm9   #a121
vmovdqa		2528(%rdi),%ymm10  #a79
vmovdqa		3968(%rdi),%ymm11  #a124
vmovdqa		3296(%rdi),%ymm12  #a103
vmovdqa		1984(%rdi),%ymm13  #a62
vmovdqa		3680(%rdi),%ymm14  #a115

#store 
vmovdqa		%ymm2,928(%rdi)
vmovdqa		%ymm3,3360(%rdi)
vmovdqa		%ymm4,2496(%rdi)
vmovdqa		%ymm5,3712(%rdi)
vmovdqa		%ymm6,1248(%rdi)
vmovdqa		%ymm7,1856(%rdi)
vmovdqa		%ymm1,2656(%rdi)

vmovdqa		%ymm9,992(%rdi)
vmovdqa		%ymm10,3872(%rdi)
vmovdqa		%ymm11,2528(%rdi)
vmovdqa		%ymm12,3968(%rdi)
vmovdqa		%ymm13,3296(%rdi)
vmovdqa		%ymm14,1984(%rdi)
vmovdqa		%ymm8,3680(%rdi)

######################################

#load 8
vmovdqa		1376(%rdi),%ymm1   #a43
vmovdqa		2880(%rdi),%ymm2   #a90
vmovdqa		2720(%rdi),%ymm3   #a85
vmovdqa		1440(%rdi),%ymm4   #a45
vmovdqa		3392(%rdi),%ymm5   #a106
vmovdqa		2752(%rdi),%ymm6   #a86
vmovdqa		1696(%rdi),%ymm7   #a53

vmovdqa		1504(%rdi),%ymm8   #a47
vmovdqa		3904(%rdi),%ymm9   #a122
vmovdqa		2784(%rdi),%ymm10  #a87
vmovdqa		1952(%rdi),%ymm11  #a61
vmovdqa		3424(%rdi),%ymm12  #a107
vmovdqa		3008(%rdi),%ymm13  #a94
vmovdqa		3744(%rdi),%ymm14  #a117

#store 
vmovdqa		%ymm2,1376(%rdi)
vmovdqa		%ymm3,2880(%rdi)
vmovdqa		%ymm4,2720(%rdi)
vmovdqa		%ymm5,1440(%rdi)
vmovdqa		%ymm6,3392(%rdi)
vmovdqa		%ymm7,2752(%rdi)
vmovdqa		%ymm1,1696(%rdi)

vmovdqa		%ymm9,1504(%rdi)
vmovdqa		%ymm10,3904(%rdi)
vmovdqa		%ymm11,2784(%rdi)
vmovdqa		%ymm12,1952(%rdi)
vmovdqa		%ymm13,3424(%rdi)
vmovdqa		%ymm14,3008(%rdi)
vmovdqa		%ymm8,3744(%rdi)

######################################

#load 9
vmovdqa		1760(%rdi),%ymm1   #a55
vmovdqa		1888(%rdi),%ymm2   #a59
vmovdqa		2912(%rdi),%ymm3   #a91
vmovdqa		2976(%rdi),%ymm4   #a93
vmovdqa		3488(%rdi),%ymm5   #a109
vmovdqa		3520(%rdi),%ymm6   #a110
vmovdqa		3776(%rdi),%ymm7   #a118

vmovdqa		2016(%rdi),%ymm8   #a63
vmovdqa		3936(%rdi),%ymm9   #a123
vmovdqa		3040(%rdi),%ymm10  #a95
vmovdqa		4000(%rdi),%ymm11  #a125
vmovdqa		3552(%rdi),%ymm12  #a111
vmovdqa		4032(%rdi),%ymm13  #a126
vmovdqa		3808(%rdi),%ymm14  #a119

#store 
vmovdqa		%ymm2,1760(%rdi)
vmovdqa		%ymm3,1888(%rdi)
vmovdqa		%ymm4,2912(%rdi)
vmovdqa		%ymm5,2976(%rdi)
vmovdqa		%ymm6,3488(%rdi)
vmovdqa		%ymm7,3520(%rdi)
vmovdqa		%ymm1,3776(%rdi)

vmovdqa		%ymm9,2016(%rdi)
vmovdqa		%ymm10,3936(%rdi)
vmovdqa		%ymm11,3040(%rdi)
vmovdqa		%ymm12,4000(%rdi)
vmovdqa		%ymm13,3552(%rdi)
vmovdqa		%ymm14,4032(%rdi)
vmovdqa		%ymm8,3808(%rdi)

ret


.global cdecl(nttunpack_avx_16)
cdecl(nttunpack_avx_16):
call		nttunpack256_avx

ret





