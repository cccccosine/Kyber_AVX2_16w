CC ?= /usr/bin/cc
CFLAGS += -g -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith -mavx2 -mbmi2 -mpopcnt -maes -march=native -mtune=native -O3 -fomit-frame-pointer
# LDFLAGS=-lcrypto

SOURCES= consts_16.c ntt_16.S basemul_16.S cpucycles.c speed_print.c invntt_16.S \
		 cbd.c fips202.c fips202x4.c fq_16.S indcpa_16.c poly_16.c polyvec_16.c \
		 rejsample.c keccak4x/KeccakP-1600-times4-SIMD256.c symmetric-shake.c shuffle_16.S \
		 clocks.c kem_16.c verify_16.c formseq.S
		 

HEADERS= consts_16.h ntt_16.h params.h align.h cpucycles.h speed_print.h fq.inc shuffle.inc \
		 reduce.h cbd.h fips202.h fips202x4.h indcpa_16.h poly_16.h polyvec_16.h \
		 randombytes.h reduce.h rejsample.h symmetric.h clocks.h kem_16.h verify_16.h
		 
all: $(HEADERS) $(SOURCES) main.c randombytes.c
	$(CC) $(CFLAGS) $(SOURCES) main.c randombytes.c -o main

test_vectors: $(HEADERS) $(SOURCES) test_vectors.c
	$(CC) $(CFLAGS) $(SOURCES) test_vectors.c -o test_vectors

.PHONY: clean

clean:
	-rm all



# ntt : ntt.o
# 	gcc -o ntt ntt.o

# ntt.o : ntt.c
# 	gcc -c ntt.c

# clean : 
# 	rm *.o ntt 