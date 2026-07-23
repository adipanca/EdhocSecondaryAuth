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

Methods 0..3 use an ephemeral X25519 exchange; method 4 is the SIGMA XWING
profile: an XWING hybrid KEM (X25519 + ML-KEM-768) for key establishment plus
ML-DSA-44 signatures on BOTH sides (SIGMA). The large ML-KEM ciphertexts/keys
and ML-DSA signatures/verification keys make message_1/2/3 big enough to
require both EAP-layer fragmentation (RFC 3579, 253-byte chunks) and IP
fragmentation.
"""

# crypto element sizes
X25519_PK = 32
ED25519_SIG = 64
MLKEM768_EK = 1184          # encapsulation (public) key
MLKEM768_CT = 1088          # ciphertext
MLDSA44_PK = 1312           # ML-DSA-44 verification key (VK)
MLDSA44_SIG = 2420          # ML-DSA-44 signature
MAC_LEN = 8                 # AES-CCM-16-64-128 MAC
AEAD_TAG = 8
ID_CRED = 3
CONN_ID = 1
METHOD_F = 1
SUITES_F = 2

# XWING hybrid element sizes (X-Wing = X25519 || ML-KEM-768)
XWING_PK = X25519_PK + MLKEM768_EK   # 1216: hybrid public key
XWING_CT = X25519_PK + MLKEM768_CT   # 1120: hybrid ciphertext


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
    4: (MAC_LEN, MAC_LEN),           # SIGMA: MAC + ML-DSA-44 sig (sized below)
}

PROFILE = {
    0: "SIG/SIG Ed25519",
    1: "SIG-Ed25519 / MAC-X25519",
    2: "MAC-X25519 / SIG-Ed25519",
    3: "MAC/MAC static-DH X25519",
    4: "SIGMA XWING+ML-DSA-44 (X25519+ML-KEM-768)",
}


def _message_sizes_sigma_xwing() -> dict:
    """Method 4: EAP-EDHOC Hybrid PQC (XWING) — SIGMA (mermaid.md §5).

    message_1 = (ctB, pkX, AEAD.enc(K1, Plaintext1))
    message_2 = (cte, AEAD.enc(K2, Plaintext2))
        Plaintext2 = (ctA, C_R, ID_CRED_R, VK_R, MAC2, sigma_R)
    message_3 = AEAD.enc(K3, Plaintext3)
        Plaintext3 = (EAD3=NpkA, MAC3, VK_I, sigma_I)
    message_4 = AEAD.enc(K4, EAD4)   (carried in EAP-Success)
        EAD4 = NpkB (responder's next static XWING public key)
    """
    # message_1: static-key encaps ct to responder + ephemeral XWING public key
    ct_b = _bstr(XWING_CT)
    pk_x = _bstr(XWING_PK)
    plaintext1 = METHOD_F + SUITES_F + CONN_ID
    m1 = ct_b + pk_x + _bstr(plaintext1 + AEAD_TAG)

    # message_2: ephemeral encaps ct back + encrypted Plaintext2 (signed by R)
    cte = _bstr(XWING_CT)
    plaintext2 = (XWING_CT + CONN_ID + ID_CRED + MLDSA44_PK
                  + MAC_LEN + MLDSA44_SIG)
    m2 = cte + _bstr(plaintext2 + AEAD_TAG)

    # message_3: encrypted Plaintext3 (signed by I), EAD3 carries next XWING pk
    plaintext3 = XWING_PK + MAC_LEN + MLDSA44_PK + MLDSA44_SIG
    m3 = _bstr(plaintext3 + AEAD_TAG)

    # message_4: EAP-Success carrying EAD4 = NpkB (responder's next XWING pk)
    plaintext4 = XWING_PK
    m4 = _bstr(plaintext4 + AEAD_TAG)

    return {"message_1": m1, "message_2": m2, "message_3": m3, "message_4": m4}


def message_sizes(method: int) -> dict:
    """Return {'message_1','message_2','message_3'} sizes in bytes."""
    if method == 4:
        return _message_sizes_sigma_xwing()

    init_auth, resp_auth = _AUTH[method]

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
        msgs = "  ".join(f"{k.replace('message_', 'msg')}={v}"
                         for k, v in s.items())
        print(f"method {m} [{PROFILE[m]}]: {msgs}  total={sum(s.values())}")
