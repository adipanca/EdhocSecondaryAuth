# Makefile for the EAP-EDHOC crypto micro-benchmark.
#
# Library usage (per spesifikasi.md):
#   libsodium : X25519, Ed25519, SHA-256, HKDF        (system, -lsodium)
#   mbedTLS   : AES-128-GCM                            (system, -lmbedcrypto)
#   PQClean   : ML-KEM-768, ML-DSA-44 (clean ref)      (built under ../PQClean)

ROOT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
PQCLEAN  := $(ROOT_DIR)/PQClean

MLKEM_DIR := $(PQCLEAN)/crypto_kem/ml-kem-768/clean
MLDSA_DIR := $(PQCLEAN)/crypto_sign/ml-dsa-44/clean
PQCOMMON  := $(PQCLEAN)/common

MLKEM_LIB := $(MLKEM_DIR)/libml-kem-768_clean.a
MLDSA_LIB := $(MLDSA_DIR)/libml-dsa-44_clean.a

# PQClean shared support code (Keccak / SHAKE + RNG) needed by both schemes.
PQ_COMMON_OBJ := $(PQCOMMON)/fips202.o $(PQCOMMON)/randombytes.o

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
LDLIBS  += -lsodium -lmbedcrypto -lm

BIN := crypto_bench interop_vec

all: $(BIN)

$(PQCOMMON)/%.o: $(PQCOMMON)/%.c
	$(CC) -O3 -I$(PQCOMMON) -c -o $@ $<

$(MLKEM_LIB):
	$(MAKE) -C $(MLKEM_DIR)

$(MLDSA_LIB):
	$(MAKE) -C $(MLDSA_DIR)

crypto_bench: crypto_bench.c $(MLKEM_LIB) $(MLDSA_LIB) $(PQ_COMMON_OBJ)
	$(CC) $(CFLAGS) -o $@ crypto_bench.c $(MLKEM_LIB) $(MLDSA_LIB) $(PQ_COMMON_OBJ) $(LDLIBS)

interop_vec: interop_vec.c $(MLKEM_LIB) $(PQ_COMMON_OBJ)
	$(CC) $(CFLAGS) -o $@ interop_vec.c $(MLKEM_LIB) $(PQ_COMMON_OBJ) $(LDLIBS)

clean:
	rm -f $(BIN) $(PQ_COMMON_OBJ)

.PHONY: all clean
