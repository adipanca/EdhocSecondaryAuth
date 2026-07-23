#!/usr/bin/env python3
"""
interop_check.py — Point 3: interoperability with an independent EDHOC crypto
implementation.

The EDHOC cipher-suite primitives produced by this project's libsodium/PQClean
core are cross-validated against an independent implementation (pyca
cryptography, OpenSSL backend) — representative of a peer EDHOC/FreeRADIUS
responder stack. It also checks the RFC 9528 / RFC 9529 element sizes our wire
model relies on.

Checks:
  1. X25519 ECDH agreement: libsodium <-> OpenSSL derive the SAME shared secret.
  2. Ed25519: signature made by libsodium VERIFIES under OpenSSL.
  3. Ed25519: signature made by OpenSSL VERIFIES under libsodium.
  4. ML-KEM-768 (PQClean) encaps/decaps round-trip + registry sizes.
  5. RFC element-size conformance (G_X, signature, MAC, ML-KEM sizes).

Writes <outdir>/interop.csv
"""
import csv
import os
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = os.path.join(HERE, "interop_vec")


def raw_pub_x25519(pub):
    return pub.public_bytes(serialization.Encoding.Raw,
                            serialization.PublicFormat.Raw)


def raw_pub_ed25519(pub):
    return pub.public_bytes(serialization.Encoding.Raw,
                            serialization.PublicFormat.Raw)


def check_x25519(tmp):
    # OpenSSL side generates first
    py_priv = x25519.X25519PrivateKey.generate()
    py_pub = raw_pub_x25519(py_priv.public_key())
    p_pub = os.path.join(tmp, "py_pub.bin")
    c_pub = os.path.join(tmp, "c_pub.bin")
    c_shared = os.path.join(tmp, "c_shared.bin")
    with open(p_pub, "wb") as f:
        f.write(py_pub)

    rc = subprocess.run([VEC, "x25519", p_pub, c_pub, c_shared]).returncode
    if rc != 0:
        return False, "C x25519 failed"

    with open(c_pub, "rb") as f:
        c_pub_raw = f.read()
    with open(c_shared, "rb") as f:
        c_shared_raw = f.read()

    c_pub_key = x25519.X25519PublicKey.from_public_bytes(c_pub_raw)
    py_shared = py_priv.exchange(c_pub_key)
    return (py_shared == c_shared_raw), ("shared secrets match" if py_shared == c_shared_raw
                                         else "shared secret mismatch")


def check_ed25519_c_signs(tmp):
    msg = os.path.join(tmp, "msg.bin")
    pub = os.path.join(tmp, "ed_pub.bin")
    sig = os.path.join(tmp, "ed_sig.bin")
    with open(msg, "wb") as f:
        f.write(b"EDHOC-EAP-INTEROP/message_3")
    rc = subprocess.run([VEC, "ed25519_sign", msg, pub, sig]).returncode
    if rc != 0:
        return False, "C ed25519 sign failed"
    with open(pub, "rb") as f:
        pub_raw = f.read()
    with open(sig, "rb") as f:
        sig_raw = f.read()
    with open(msg, "rb") as f:
        msg_raw = f.read()
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig_raw, msg_raw)
        return True, "OpenSSL verified libsodium signature"
    except Exception as e:  # noqa
        return False, f"OpenSSL verify failed: {e}"


def check_ed25519_openssl_signs(tmp):
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = raw_pub_ed25519(priv.public_key())
    msg_b = b"EDHOC-EAP-INTEROP/message_2"
    sig = priv.sign(msg_b)
    msg = os.path.join(tmp, "msg2.bin")
    pubf = os.path.join(tmp, "ed_pub2.bin")
    sigf = os.path.join(tmp, "ed_sig2.bin")
    with open(msg, "wb") as f:
        f.write(msg_b)
    with open(pubf, "wb") as f:
        f.write(pub)
    with open(sigf, "wb") as f:
        f.write(sig)
    rc = subprocess.run([VEC, "ed25519_verify", msg, pubf, sigf]).returncode
    return (rc == 0), ("libsodium verified OpenSSL signature" if rc == 0
                       else "libsodium verify failed")


def check_mlkem():
    r = subprocess.run([VEC, "mlkem"], capture_output=True, text=True)
    detail = r.stdout.strip() or r.stderr.strip()
    return (r.returncode == 0), detail


def check_sizes():
    # RFC 9528/9529 + ML-KEM-768 registry expectations vs our model constants
    import edhoc_sizes as es
    rows = [
        ("X25519_public_key", 32, es.X25519_PK),
        ("Ed25519_signature", 64, es.ED25519_SIG),
        ("MAC_AES_CCM_16_64", 8, es.MAC_LEN),
        ("MLKEM768_encap_key", 1184, es.MLKEM768_EK),
        ("MLKEM768_ciphertext", 1088, es.MLKEM768_CT),
        ("MLDSA44_verify_key", 1312, es.MLDSA44_PK),
        ("MLDSA44_signature", 2420, es.MLDSA44_SIG),
    ]
    return rows


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(outdir, exist_ok=True)
    if not os.path.exists(VEC):
        print(f"[interop] {VEC} not built; run make first", file=sys.stderr)
        sys.exit(1)

    path = os.path.join(outdir, "interop.csv")
    results = []

    with tempfile.TemporaryDirectory() as tmp:
        for name, fn in [
            ("X25519_ECDH_libsodium_vs_OpenSSL", lambda: check_x25519(tmp)),
            ("Ed25519_libsodium_sign_OpenSSL_verify", lambda: check_ed25519_c_signs(tmp)),
            ("Ed25519_OpenSSL_sign_libsodium_verify", lambda: check_ed25519_openssl_signs(tmp)),
            ("MLKEM768_PQClean_roundtrip", check_mlkem),
        ]:
            ok, detail = fn()
            results.append((name, "PASS" if ok else "FAIL", detail))

    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["check", "result", "detail"])
        for name, res, detail in results:
            w.writerow([name, res, detail])
        # size conformance
        for cname, expected, actual in check_sizes():
            res = "PASS" if expected == actual else "FAIL"
            w.writerow([f"size_{cname}", res, f"expected={expected} actual={actual}"])

    print(f"[interop_check] wrote {path}")
    for name, res, detail in results:
        print(f"  {res:4}  {name}: {detail}")
    n_fail = sum(1 for _, r, _ in results if r == "FAIL")
    sys.exit(1 if n_fail else 0)


if __name__ == "__main__":
    main()
