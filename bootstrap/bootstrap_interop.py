#!/usr/bin/env python3
"""
bootstrap_interop.py — assert the C module (bootstrap.c) and the Python
reference (keyschedule.py) derive byte-for-byte identical key material.

Mirrors benchmark/interop_check.py: it feeds one deterministic EMSK to the C
``bootstrap_selftest`` binary and to keyschedule.py, then diffs USRK, DSRK,
OSCORE Master Secret/Salt, the UE Sender/Recipient keys and the Common IV.

Requires ``make bootstrap_selftest`` to have been built (needs libsodium dev
headers). Skips gracefully with a clear message if the binary is absent.
"""
import os
import subprocess
import sys

from keyschedule import (derive_usrk, derive_dsrk, derive_oscore_master_secret,
                         derive_oscore_master_salt, oscore_context_from_dsrk,
                         USRK_KEY_LABEL, DSRK_DOMAIN_LABEL)

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "bootstrap_selftest")

# Deterministic test EMSK (64 bytes).
EMSK_HEX = ("00112233445566778899aabbccddeeff"
            "0102030405060708090a0b0c0d0e0f10"
            "202122232425262728292a2b2c2d2e2f"
            "303132333435363738393a3b3c3d3e3f")


def c_vectors(emsk_hex):
    out = subprocess.check_output([BIN, emsk_hex], text=True)
    vec = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            vec[k.strip()] = v.strip()
    return vec


def main():
    if not os.path.exists(BIN):
        print(f"[interop] {BIN} not built — run `make bootstrap_selftest` first "
              "(needs libsodium dev headers). Skipping C/Python cross-check.")
        return 0

    emsk = bytes.fromhex(EMSK_HEX)
    usrk = derive_usrk(emsk, USRK_KEY_LABEL)
    dsrk = derive_dsrk(usrk, DSRK_DOMAIN_LABEL)
    ms = derive_oscore_master_secret(dsrk)
    salt = derive_oscore_master_salt(dsrk)
    ue = oscore_context_from_dsrk(dsrk, b"\x01", b"\x00")

    py = {
        "USRK": usrk.hex(),
        "DSRK": dsrk.hex(),
        "OSCORE_MS": ms.hex(),
        "OSCORE_SALT": salt.hex(),
        "UE_SENDER_KEY": ue.sender_key.hex(),
        "UE_RECIPIENT_KEY": ue.recipient_key.hex(),
        "COMMON_IV": ue.common_iv.hex(),
    }
    c = c_vectors(EMSK_HEX)

    all_ok = True
    for k, v in py.items():
        cv = c.get(k, "<missing>")
        ok = (cv == v)
        all_ok = all_ok and ok
        print(f"  {k:<18} {'PASS' if ok else 'FAIL'}")
        if not ok:
            print(f"      python: {v}")
            print(f"      c     : {cv}")
    print(f"[interop] C/Python parity: {'ALL PASS' if all_ok else 'MISMATCH'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
