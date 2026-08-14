#!/usr/bin/env python3
"""
keyschedule.py — Single source of truth for the Key Bootstrapping key schedule.

This module is imported by all three roles so that the UE (UERANSIM side), the
AAA server (FreeRADIUS side) and the Application Server (AS) run byte-for-byte
identical key derivation — exactly the same design principle used by the shared
``libedhoc4`` core in the EAP-EDHOC handshake.

Chain implemented (see bootstrappingkey.md §1):

    EMSK  --RFC 5295 §3.2-->  USRK  --RFC 5295 (domain)-->  DSRK
    DSRK  -->  OSCORE Master Secret / Master Salt  (RFC 8613 §3.2 style)
    (Master Secret, Master Salt)  --RFC 8613 §3.2.1-->  Sender/Recipient keys + Common IV

All KDFs are HKDF-SHA-256 (RFC 5869), identical to the HKDF used inside
``edhoc4.c`` (libsodium HMAC-SHA256), so the values chain cleanly from the EMSK
produced by the EAP-EDHOC handshake.

Nothing here is a new security protocol: the confidentiality of the DSRK on the
AAA->AS hop is an *architecture assumption* (co-located / mTLS / closed network),
the same trust-domain model as ERP in RFC 6696. See README.md.
"""
from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass

HASH_LEN = 32  # SHA-256

# ---- default label strings (explicit, per bootstrappingkey.md §1.1) ----
USRK_KEY_LABEL = b"usrk@example.org,ekeylabel=EAP-EDHOC"
DSRK_DOMAIN_LABEL = b"dsrk@app-domain.example.org"
OSCORE_MASTER_SECRET_LABEL = b"OSCORE Master Secret"
OSCORE_MASTER_SALT_LABEL = b"OSCORE Master Salt"

# ---- OSCORE default cipher suite (RFC 8613 §3.2): AES-CCM-16-64-128 ----
OSCORE_AEAD_ALG = 10          # COSE alg id for AES-CCM-16-64-128
OSCORE_KEY_LEN = 16           # 128-bit key
OSCORE_IV_LEN = 13            # nonce length for AES-CCM-16-64-128
OSCORE_TAG_LEN = 8            # 64-bit tag
OSCORE_MASTER_SECRET_LEN = 16
OSCORE_MASTER_SALT_LEN = 8


# ======================================================================== #
# HKDF-SHA-256 (RFC 5869) — identical to edhoc4.c                           #
# ======================================================================== #
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract(salt, IKM) -> PRK (32 bytes)."""
    if salt is None:
        salt = b"\x00" * HASH_LEN
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand(PRK, info, L) -> OKM (L bytes)."""
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


# ======================================================================== #
# RFC 5295 §3.1 KDF (PRF+) used for USRK / DSRK derivation                  #
# ======================================================================== #
def _rfc5295_prf_plus(key: bytes, label: bytes, optional_data: bytes,
                      length: int) -> bytes:
    """
    RFC 5295 §3.1 default KDF:

        KDF(K, S)   where  S = label | 0x00 | optional data | length
        PRF+(K, S)  = T1 | T2 | T3 | ...
        T1 = PRF(K, S | 0x01)
        Ti = PRF(K, T(i-1) | S | i)

    PRF is HMAC-SHA-256; ``length`` is a 2-octet unsigned big-endian integer of
    the desired output length in octets.
    """
    s = label + b"\x00" + optional_data + struct.pack(">H", length)
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(key, t + s + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def derive_usrk(emsk: bytes, key_label: bytes = USRK_KEY_LABEL,
                key_length: int = 64, optional_data: bytes = b"") -> bytes:
    """RFC 5295 §3.2: USRK = KDF(EMSK, key_label | 0x00 | optional | length)."""
    if not emsk or len(emsk) < 32:
        raise ValueError("EMSK too short")
    return _rfc5295_prf_plus(emsk, key_label, optional_data, key_length)


def derive_dsrk(parent_key: bytes, domain_label: bytes = DSRK_DOMAIN_LABEL,
                key_length: int = 64, optional_data: bytes = b"") -> bytes:
    """
    Domain-Specific Root Key.

    Per bootstrappingkey.md §1.1 the DSRK is derived from the USRK with a
    per-application domain label (RFC 5295 uses the same KDF; RFC 5295 §4
    derives DSRK directly from the EMSK — this module accepts either parent).
    """
    if not parent_key or len(parent_key) < 32:
        raise ValueError("parent key too short")
    return _rfc5295_prf_plus(parent_key, domain_label, optional_data, key_length)


# ======================================================================== #
# OSCORE Master Secret / Master Salt from DSRK                              #
# ======================================================================== #
def derive_oscore_master_secret(dsrk: bytes) -> bytes:
    """OSCORE Master Secret from the per-application DSRK (RFC 8613 input)."""
    return hkdf_expand(dsrk, OSCORE_MASTER_SECRET_LABEL, OSCORE_MASTER_SECRET_LEN)


def derive_oscore_master_salt(dsrk: bytes) -> bytes:
    """OSCORE Master Salt from the per-application DSRK (RFC 8613 input)."""
    return hkdf_expand(dsrk, OSCORE_MASTER_SALT_LABEL, OSCORE_MASTER_SALT_LEN)


# ======================================================================== #
# RFC 8613 §3.2.1 — OSCORE Security Context derivation                      #
# ======================================================================== #
def _cbor_bstr(b: bytes) -> bytes:
    n = len(b)
    if n < 24:
        return bytes([0x40 | n]) + b
    if n < 256:
        return bytes([0x58, n]) + b
    raise ValueError("bstr too long for this helper")


def _cbor_tstr(s: bytes) -> bytes:
    n = len(s)
    if n < 24:
        return bytes([0x60 | n]) + s
    raise ValueError("tstr too long for this helper")


def _cbor_uint(n: int) -> bytes:
    if n < 24:
        return bytes([n])
    if n < 256:
        return bytes([0x18, n])
    raise ValueError("uint too big for this helper")


def _oscore_info(id_bytes: bytes, id_context: bytes, alg: int,
                 type_str: bytes, length: int) -> bytes:
    """RFC 8613 §3.2.1 info = [ id, id_context, alg_aead, type, L ] (CBOR array)."""
    return (b"\x85"  # array(5)
            + _cbor_bstr(id_bytes)
            + _cbor_bstr(id_context)
            + _cbor_uint(alg)
            + _cbor_tstr(type_str)
            + _cbor_uint(length))


@dataclass
class OscoreContext:
    """Derived OSCORE security context for one party (RFC 8613 §3.1)."""
    master_secret: bytes
    master_salt: bytes
    sender_id: bytes
    recipient_id: bytes
    id_context: bytes
    sender_key: bytes
    recipient_key: bytes
    common_iv: bytes
    alg_aead: int = OSCORE_AEAD_ALG
    tag_len: int = OSCORE_TAG_LEN


def derive_oscore_context(master_secret: bytes, master_salt: bytes,
                          sender_id: bytes, recipient_id: bytes,
                          id_context: bytes = b"") -> OscoreContext:
    """
    RFC 8613 §3.2.1 derivation of Sender Key, Recipient Key and Common IV.

        PRK        = HKDF-Extract(Master Salt, Master Secret)
        Sender Key = HKDF-Expand(PRK, info(sender_id,   "Key"), 16)
        Recip Key  = HKDF-Expand(PRK, info(recipient_id,"Key"), 16)
        Common IV  = HKDF-Expand(PRK, info(h'',         "IV"),  13)
    """
    prk = hkdf_extract(master_salt, master_secret)
    sender_key = hkdf_expand(
        prk, _oscore_info(sender_id, id_context, OSCORE_AEAD_ALG, b"Key",
                          OSCORE_KEY_LEN), OSCORE_KEY_LEN)
    recipient_key = hkdf_expand(
        prk, _oscore_info(recipient_id, id_context, OSCORE_AEAD_ALG, b"Key",
                          OSCORE_KEY_LEN), OSCORE_KEY_LEN)
    common_iv = hkdf_expand(
        prk, _oscore_info(b"", id_context, OSCORE_AEAD_ALG, b"IV",
                          OSCORE_IV_LEN), OSCORE_IV_LEN)
    return OscoreContext(
        master_secret=master_secret, master_salt=master_salt,
        sender_id=sender_id, recipient_id=recipient_id, id_context=id_context,
        sender_key=sender_key, recipient_key=recipient_key, common_iv=common_iv)


def oscore_context_from_dsrk(dsrk: bytes, sender_id: bytes, recipient_id: bytes,
                             id_context: bytes = b"") -> OscoreContext:
    """Convenience: DSRK -> Master Secret/Salt -> full OSCORE context."""
    ms = derive_oscore_master_secret(dsrk)
    salt = derive_oscore_master_salt(dsrk)
    return derive_oscore_context(ms, salt, sender_id, recipient_id, id_context)


# ======================================================================== #
# Debug fingerprints (test-only, per bootstrappingkey.md §1.5)             #
# ======================================================================== #
def fingerprint(key: bytes) -> str:
    """SHA-256 hash (hex, truncated) of a key — for correctness checks only.

    Exposes a hash so the UE and AS sides can prove they derived the SAME key
    during testing, WITHOUT leaking the raw key material into logs.
    """
    return hashlib.sha256(b"bootstrap-fp|" + key).hexdigest()[:16]


if __name__ == "__main__":
    # Tiny self-check: identical EMSK on both sides yields identical OSCORE keys.
    import os
    emsk = os.urandom(64)
    usrk = derive_usrk(emsk)
    dsrk = derive_dsrk(usrk)
    ue = oscore_context_from_dsrk(dsrk, sender_id=b"\x01", recipient_id=b"\x00")
    as_ = oscore_context_from_dsrk(dsrk, sender_id=b"\x00", recipient_id=b"\x01")
    assert ue.sender_key == as_.recipient_key
    assert ue.recipient_key == as_.sender_key
    assert ue.common_iv == as_.common_iv
    print("keyschedule self-check OK")
    print("  USRK  fp:", fingerprint(usrk))
    print("  DSRK  fp:", fingerprint(dsrk))
    print("  OSCORE master secret fp:", fingerprint(ue.master_secret))
