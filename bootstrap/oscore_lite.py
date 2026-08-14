#!/usr/bin/env python3
"""
oscore_lite.py — minimal OSCORE-style protection for the first-contact message.

This is NOT a full RFC 8613 / CoAP implementation (the workspace has no aiocoap).
It reuses the *real* OSCORE key schedule from ``keyschedule.py`` (RFC 8613
§3.2.1 Sender/Recipient keys + Common IV) and the *real* OSCORE AEAD nonce
construction (RFC 8613 §5.2), then protects an application payload with
AES-CCM-16-64-128 — the OSCORE mandatory-to-implement AEAD.

Because both parties derive an identical security context from the shared DSRK,
a successful decrypt/verify on the receiver is a cryptographic proof that the
bootstrapped keys match. That is exactly what the "first OSCORE contact" step in
bootstrappingkey.md §1.4 needs to demonstrate.
"""
from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from keyschedule import OscoreContext, OSCORE_TAG_LEN, OSCORE_IV_LEN


def _oscore_nonce(common_iv: bytes, id_piv: bytes, partial_iv: int) -> bytes:
    """
    RFC 8613 §5.2 AEAD nonce construction.

        1. PIV     = partial IV, left-padded with zeros to 5 bytes
        2. ID_PIV  = sender id, left-padded with zeros to (nonce_len - 6) bytes
        3. nonce   = ( len(id_piv) | ID_PIV | PIV ) XOR Common IV
    """
    piv = partial_iv.to_bytes(5, "big")
    pad_id_len = OSCORE_IV_LEN - 6
    if len(id_piv) > pad_id_len:
        raise ValueError("sender id too long for OSCORE nonce")
    id_padded = (b"\x00" * (pad_id_len - len(id_piv))) + id_piv
    partial = bytes([len(id_piv)]) + id_padded + piv
    return bytes(a ^ b for a, b in zip(partial, common_iv))


def _external_aad(alg: int, request_kid: bytes, partial_iv: int) -> bytes:
    """A small, deterministic external AAD binding alg + sender id + PIV.

    (A faithful subset of the OSCORE external_aad of RFC 8613 §5.4 — enough to
    bind the ciphertext to the sender identity and replay counter.)
    """
    return b"oscore-lite|" + bytes([alg]) + b"|" + request_kid + b"|" + \
        partial_iv.to_bytes(5, "big")


def protect(ctx: OscoreContext, payload: bytes, partial_iv: int) -> bytes:
    """Encrypt ``payload`` with the Sender Key -> OSCORE-lite message bytes.

    Wire layout (self-describing, big-endian):
        1 byte  : len(sender_id)
        n bytes : sender_id (request kid)
        5 bytes : partial IV
        rest    : AES-CCM ciphertext+tag
    """
    nonce = _oscore_nonce(ctx.common_iv, ctx.sender_id, partial_iv)
    aad = _external_aad(ctx.alg_aead, ctx.sender_id, partial_iv)
    aead = AESCCM(ctx.sender_key, tag_length=OSCORE_TAG_LEN)
    ct = aead.encrypt(nonce, payload, aad)
    header = bytes([len(ctx.sender_id)]) + ctx.sender_id + \
        partial_iv.to_bytes(5, "big")
    return header + ct


def unprotect(ctx: OscoreContext, message: bytes) -> bytes:
    """Verify+decrypt an OSCORE-lite message with the Recipient Key.

    Raises ``cryptography.exceptions.InvalidTag`` (or ValueError) if the keys
    do not match — i.e. if the bootstrap did not produce identical contexts.
    """
    if not message:
        raise ValueError("empty OSCORE message")
    id_len = message[0]
    off = 1
    request_kid = message[off:off + id_len]
    off += id_len
    partial_iv = int.from_bytes(message[off:off + 5], "big")
    off += 5
    ct = message[off:]

    # The peer's Sender Id is our Recipient Id; verify it matches expectation.
    if request_kid != ctx.recipient_id:
        raise ValueError("unexpected OSCORE sender id (kid mismatch)")

    nonce = _oscore_nonce(ctx.common_iv, request_kid, partial_iv)
    aad = _external_aad(ctx.alg_aead, request_kid, partial_iv)
    aead = AESCCM(ctx.recipient_key, tag_length=OSCORE_TAG_LEN)
    return aead.decrypt(nonce, ct, aad)


if __name__ == "__main__":
    import os
    from keyschedule import (derive_usrk, derive_dsrk, oscore_context_from_dsrk)

    emsk = os.urandom(64)
    dsrk = derive_dsrk(derive_usrk(emsk))
    ue = oscore_context_from_dsrk(dsrk, sender_id=b"\x01", recipient_id=b"\x00")
    as_ = oscore_context_from_dsrk(dsrk, sender_id=b"\x00", recipient_id=b"\x01")

    msg = protect(ue, b"GET /temperature (first contact)", partial_iv=1)
    recovered = unprotect(as_, msg)
    assert recovered == b"GET /temperature (first contact)"
    reply = protect(as_, b"2.05 Content 21.4C", partial_iv=1)
    assert unprotect(ue, reply) == b"2.05 Content 21.4C"
    print("oscore_lite round-trip OK (UE <-> AS, %d B on wire)" % len(msg))
