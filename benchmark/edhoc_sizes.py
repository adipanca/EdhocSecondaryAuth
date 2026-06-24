#!/usr/bin/env python3
"""
edhoc_sizes.py — EDHOC (RFC 9528) message-size model for EAP-EDHOC methods 0..4.

Computes the on-wire size of message_1 / message_2 / message_3 for each method
from real cryptographic element sizes, so the MTU/fragmentation and lossy-network
benchmarks operate on realistic payloads.

Element sizes (bytes):
  X25519 public key (G_X/G_Y)      : 32
  Ed25519 signature                : 64
  ML-KEM-768 encapsulation key      : 1184
  ML-KEM-768 ciphertext             : 1088
  MAC (AES-CCM-16-64-128, mac_len)  : 8
  AEAD tag (message_3)              : 8
  ID_CRED (kid form)                : 3
  Connection identifier (C_I/C_R)   : 1
  METHOD                            : 1
  SUITES                            : 2

Methods 0..3 use an ephemeral X25519 exchange; method 4 uses an XWING hybrid
(X25519 + ML-KEM-768), which makes message_1/message_2 large enough to require
both EAP-layer fragmentation (RFC 3579, 253-byte chunks) and IP fragmentation.
"""

# crypto element sizes
X25519_PK = 32
ED25519_SIG = 64
MLKEM768_EK = 1184          # encapsulation (public) key
MLKEM768_CT = 1088          # ciphertext
MAC_LEN = 8                 # AES-CCM-16-64-128 MAC
AEAD_TAG = 8
ID_CRED = 3
CONN_ID = 1
METHOD_F = 1
SUITES_F = 2


def _cbor_bstr_overhead(n: int) -> int:
    """CBOR byte-string header overhead for a payload of n bytes."""
    if n <= 23:
        return 1
    if n <= 255:
        return 2
    return 3


def _bstr(n: int) -> int:
    return n + _cbor_bstr_overhead(n)


# Per-method authentication field sizes (the Signature_or_MAC value).
# (init_auth, resp_auth): SIG -> Ed25519 signature (64), MAC -> 8.
_AUTH = {
    0: (ED25519_SIG, ED25519_SIG),   # SIG / SIG
    1: (ED25519_SIG, MAC_LEN),       # SIG / MAC
    2: (MAC_LEN, ED25519_SIG),       # MAC / SIG
    3: (MAC_LEN, MAC_LEN),           # MAC / MAC
    4: (MAC_LEN, MAC_LEN),           # MAC / MAC (XWING)
}

PROFILE = {
    0: "SIG/SIG Ed25519",
    1: "SIG-Ed25519 / MAC-X25519",
    2: "MAC-X25519 / SIG-Ed25519",
    3: "MAC/MAC static-DH X25519",
    4: "MAC/MAC XWING (X25519+ML-KEM-768)",
}


def message_sizes(method: int) -> dict:
    """Return {'message_1','message_2','message_3'} sizes in bytes."""
    init_auth, resp_auth = _AUTH[method]

    if method == 4:
        # XWING hybrid ephemeral: G_X carries X25519 pk + ML-KEM-768 ek;
        # message_2 carries G_Y (X25519 pk) + ML-KEM-768 ciphertext.
        g_x = _bstr(X25519_PK + MLKEM768_EK)
        g_y = _bstr(X25519_PK + MLKEM768_CT)
    else:
        g_x = _bstr(X25519_PK)
        g_y = _bstr(X25519_PK)

    # message_1 = METHOD, SUITES, G_X, C_I
    m1 = METHOD_F + SUITES_F + g_x + CONN_ID

    # message_2 = G_Y, CIPHERTEXT_2 ; plaintext_2 = ID_CRED_R + Sig_or_MAC_2
    cipher2 = _bstr(ID_CRED + resp_auth)
    m2 = g_y + cipher2

    # message_3 = CIPHERTEXT_3 (AEAD) ; plaintext_3 = ID_CRED_I + Sig_or_MAC_3
    cipher3 = _bstr(ID_CRED + init_auth + AEAD_TAG)
    m3 = cipher3

    return {"message_1": m1, "message_2": m2, "message_3": m3}


METHODS = [0, 1, 2, 3, 4]


if __name__ == "__main__":
    for m in METHODS:
        s = message_sizes(m)
        print(f"method {m} [{PROFILE[m]}]: "
              f"msg1={s['message_1']}  msg2={s['message_2']}  msg3={s['message_3']}  "
              f"total={sum(s.values())}")
