# Makefile — C parity module for Key Bootstrapping (bootstrap.c).
#
# Builds:
#   libbootstrap.a       static lib to link into rlm_eap_edhoc / UERANSIM
#   bootstrap_selftest   standalone self-test / parity-vector emitter
#
# Dependency: libsodium (same as ../edhoc4/libedhoc4.a). On the FreeRADIUS /
# UERANSIM build host the dev headers are already present.

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
LDLIBS  := -lsodium

all: libbootstrap.a bootstrap_selftest

bootstrap.o: bootstrap.c bootstrap.h
	$(CC) $(CFLAGS) -c bootstrap.c -o bootstrap.o

libbootstrap.a: bootstrap.o
	$(AR) rcs $@ $^

bootstrap_selftest: selftest.c libbootstrap.a
	$(CC) $(CFLAGS) selftest.c libbootstrap.a -o $@ $(LDLIBS)

# Cross-check the C schedule against the Python reference (keyschedule.py).
interop: bootstrap_selftest
	python3 bootstrap_interop.py

clean:
	rm -f bootstrap.o libbootstrap.a bootstrap_selftest

.PHONY: all interop clean
