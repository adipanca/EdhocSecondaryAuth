# Makefile for the shared EAP-EDHOC method 4 (SIGMA XWING) core.
#
#   libsodium : X25519, SHA-256, HKDF(HMAC-SHA256), ChaCha20-Poly1305 AEAD
#   PQClean   : ML-KEM-768 + ML-DSA-44 (clean reference)
#
# Targets:
#   libedhoc4.a   static core linked by FreeRADIUS (C) and UERANSIM (C++)
#   edhoc4_selftest   in-process initiator<->responder handshake test

ROOT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
PQCLEAN  := $(ROOT_DIR)/PQClean

MLKEM_DIR := $(PQCLEAN)/crypto_kem/ml-kem-768/clean
MLDSA_DIR := $(PQCLEAN)/crypto_sign/ml-dsa-44/clean
PQCOMMON  := $(PQCLEAN)/common

MLKEM_LIB := $(MLKEM_DIR)/libml-kem-768_clean.a
MLDSA_LIB := $(MLDSA_DIR)/libml-dsa-44_clean.a
PQ_COMMON_OBJ := $(PQCOMMON)/fips202.o $(PQCOMMON)/randombytes.o

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11 -fPIC
LDLIBS  += -lsodium -lm

PQ_OBJS := $(MLKEM_LIB) $(MLDSA_LIB) $(PQ_COMMON_OBJ)

all: libedhoc4.a edhoc4_selftest edhoc4_keygen edhoc03_selftest edhoc03_keygen

$(PQCOMMON)/%.o: $(PQCOMMON)/%.c
	$(CC) -O3 -fPIC -I$(PQCOMMON) -c -o $@ $<

$(MLKEM_LIB):
	$(MAKE) -C $(MLKEM_DIR) EXTRAFLAGS=-fPIC

$(MLDSA_LIB):
	$(MAKE) -C $(MLDSA_DIR) EXTRAFLAGS=-fPIC

edhoc4.o: edhoc4.c edhoc4.h
	$(CC) $(CFLAGS) -c -o $@ edhoc4.c

edhoc03.o: edhoc03.c edhoc03.h
	$(CC) $(CFLAGS) -c -o $@ edhoc03.c

# Bundle the edhoc4 core together with the PQClean object code so a single
# archive is self-contained for the FreeRADIUS / UERANSIM builds. Each PQClean
# archive is unpacked into its own dir to avoid object-name collisions
# (both schemes ship ntt.o / poly.o / reduce.o etc.).
libedhoc4.a: edhoc4.o edhoc03.o $(PQ_OBJS)
	rm -f $@
	rm -rf .arobj && mkdir -p .arobj/mlkem .arobj/mldsa
	cd .arobj/mlkem && ar x $(MLKEM_LIB)
	cd .arobj/mldsa && ar x $(MLDSA_LIB)
	ar rcs $@ edhoc4.o edhoc03.o $(PQ_COMMON_OBJ) .arobj/mlkem/*.o .arobj/mldsa/*.o
	rm -rf .arobj

edhoc4_selftest: selftest.c libedhoc4.a
	$(CC) $(CFLAGS) -o $@ selftest.c libedhoc4.a $(LDLIBS)

edhoc4_keygen: keygen.c libedhoc4.a
	$(CC) $(CFLAGS) -o $@ keygen.c libedhoc4.a $(LDLIBS)

edhoc03_selftest: selftest03.c libedhoc4.a
	$(CC) $(CFLAGS) -o $@ selftest03.c libedhoc4.a $(LDLIBS)

edhoc03_keygen: keygen03.c libedhoc4.a
	$(CC) $(CFLAGS) -o $@ keygen03.c libedhoc4.a $(LDLIBS)

test: edhoc4_selftest
	./edhoc4_selftest

clean:
	rm -f edhoc4.o edhoc03.o libedhoc4.a edhoc4_selftest edhoc4_keygen edhoc03_selftest edhoc03_keygen
	rm -rf .arobj

.PHONY: all test clean
