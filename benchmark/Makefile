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

EDHOC4_DIR := $(ROOT_DIR)/edhoc4
EDHOC4_LIB := $(EDHOC4_DIR)/libedhoc4.a

BIN := crypto_bench interop_vec m4_inproc_bench e2e_radius_bench eap_tls_bench eap_tls_hybrid_bench

# Method 6 (EAP-TLS Hybrid PQC) needs OpenSSL >= 3.2 headers/libs for
# oqs-provider's TLS1.3 provider-based signature-algorithm support (ML-DSA-44
# certs) -- system OpenSSL here is 3.0.13, so this links against the private
# OpenSSL 3.2.6 built from source under pqc-tls/openssl32-install/ (see
# benchmark/switch_tls_config.sh header comment / final report for why).
# Running eap_tls_hybrid_bench requires the matching runtime libs on
# LD_LIBRARY_PATH -- switch_tls_config.sh sets this up.
PQC_ROOT     := $(ROOT_DIR)/pqc-tls
OSSL32_INC   := $(PQC_ROOT)/openssl32-install/include
OSSL32_LIB   := $(PQC_ROOT)/openssl32-install/lib64

all: $(BIN)

$(PQCOMMON)/%.o: $(PQCOMMON)/%.c
	$(CC) -O3 -I$(PQCOMMON) -c -o $@ $<

$(MLKEM_LIB):
	$(MAKE) -C $(MLKEM_DIR)

$(MLDSA_LIB):
	$(MAKE) -C $(MLDSA_DIR)

$(EDHOC4_LIB):
	$(MAKE) -C $(EDHOC4_DIR) libedhoc4.a

crypto_bench: crypto_bench.c $(MLKEM_LIB) $(MLDSA_LIB) $(PQ_COMMON_OBJ)
	$(CC) $(CFLAGS) -o $@ crypto_bench.c $(MLKEM_LIB) $(MLDSA_LIB) $(PQ_COMMON_OBJ) $(LDLIBS)

interop_vec: interop_vec.c $(MLKEM_LIB) $(PQ_COMMON_OBJ)
	$(CC) $(CFLAGS) -o $@ interop_vec.c $(MLKEM_LIB) $(PQ_COMMON_OBJ) $(LDLIBS)

# Live end-to-end EAP-over-RADIUS harnesses (methods 0..4 EDHOC / method 5 TLS).
# Not part of `all` PQClean bootstrap chain requirements beyond libedhoc4.a;
# link convention mirrors how the already-built e2e_radius_bench binary in
# this tree was produced (-lsodium -lcrypto -lm, -I../edhoc4).
m4_inproc_bench: m4_inproc_bench.c $(EDHOC4_LIB)
	$(CC) $(CFLAGS) -I$(EDHOC4_DIR) -o $@ m4_inproc_bench.c $(EDHOC4_LIB) -lsodium -lmbedcrypto -lm -pthread

e2e_radius_bench: e2e_radius_bench.c $(EDHOC4_LIB)
	$(CC) $(CFLAGS) -I$(EDHOC4_DIR) -o $@ e2e_radius_bench.c $(EDHOC4_LIB) -lsodium -lmbedcrypto -lcrypto -lm -pthread

eap_tls_bench: eap_tls_bench.c
	$(CC) $(CFLAGS) -o $@ eap_tls_bench.c -lssl -lcrypto -lm

eap_tls_hybrid_bench: eap_tls_hybrid_bench.c
	$(CC) $(CFLAGS) -I$(OSSL32_INC) -o $@ eap_tls_hybrid_bench.c \
		-L$(OSSL32_LIB) -Wl,-rpath,$(OSSL32_LIB) -lssl -lcrypto -lm

clean:
	rm -f $(BIN) $(PQ_COMMON_OBJ)

.PHONY: all clean
