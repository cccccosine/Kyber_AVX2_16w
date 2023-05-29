CC ?= /usr/bin/cc
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith -mavx2 -mbmi2 -mpopcnt -maes -march=native -mtune=native -O3 -fomit-frame-pointer
# LDFLAGS=-lcrypto

SOURCES= consts_16.c poly.c ntt_16.S basemul_16.S basemul.S cpucycles.c speed_print.c ntt.S consts_16.c invntt_16.S invntt.S Kyber_ntt.c Kyber_poly.c reduce.c

HEADERS= consts_16.h ntt_16.h params.h poly.h align.h cpucycles.h speed_print.h ntt.h consts_16.h fq.inc shuffle.inc Kyber_ntt.h Kyber_poly.h reduce.h

all: $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o $@

.PHONY: clean

clean:
	-rm all



# ntt : ntt.o
# 	gcc -o ntt ntt.o

# ntt.o : ntt.c
# 	gcc -c ntt.c

# clean : 
# 	rm *.o ntt 