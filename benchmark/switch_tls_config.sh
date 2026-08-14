#!/usr/bin/env bash
#
# switch_tls_config.sh — point the live FreeRADIUS EAP-Type=13 "tls {}"
# method block at either the classical (method 5, RSA-2048) or hybrid-PQC
# (method 6, ML-DSA-44 + X25519MLKEM768) tls-config, then restart radiusd.
#
# A single rlm_eap_tls / "tls {}" instance can only hold ONE certificate/key
# pair (and, since the hybrid group is selected process-wide via
# OPENSSL_CONF/OPENSSL_MODULES env vars, one KEM-group posture) at a time.
# Method 5 and method 6 are therefore measured sequentially, not
# concurrently — both are still fully live, just not against the same
# radiusd process. This script makes that swap reproducible.
#
# Usage:
#   sudo benchmark/switch_tls_config.sh classic   # tls = tls-common, plain env
#   sudo benchmark/switch_tls_config.sh hybrid    # tls = tls-hybrid-pqc, oqs-provider env
#   sudo benchmark/switch_tls_config.sh status    # show current mode + radiusd state
#
# Both modes (re)start radiusd in QUIET foreground mode (-f, NOT -X), log to
# /tmp/radiusd-<mode>.log, backgrounded, and wait until it is listening on
# UDP/1812 before returning.
#
# IMPORTANT (found via a real benchmark bug, fixed here): radiusd -X (full
# debug logging, every attribute/policy branch printed per request) was used
# here originally. Under the sustained high-throughput load a statistical
# benchmark needs (thousands of iterations/method), -X's logging overhead
# made radiusd intermittently fall behind, causing real (not
# harness-simulated) UDP packet delay/loss -- which the harness's 2-second
# SO_RCVTIMEO then turned into massive ~2000ms outliers, at a rate high
# enough (tens of samples per 5000 iterations) to distort mean/ranking
# comparisons between methods. Confirmed by A/B test: same 5000-iter sweep,
# -X had 14-63 outliers >5ms per method (up to ~2123ms); -f (this script) had
# zero such outliers across 20000 combined samples (max ~23ms). -f keeps
# radiusd's own request-handling code path identical (same modules, same
# policy evaluation) -- only the verbose per-attribute debug printf calls are
# skipped, so this does not change what is being measured, only removes a
# logging-induced measurement artifact.
#
set -uo pipefail

EAP_CONF=/usr/local/etc/raddb/mods-available/eap
RADIUSD=/usr/local/sbin/radiusd
HERE="$(cd "$(dirname "$0")" && pwd)"
PQC_ROOT="$(cd "$HERE/../pqc-tls" && pwd)"

export OQS_OPENSSL_CONF="$PQC_ROOT/openssl-hybrid.cnf"
export OQS_OPENSSL_MODULES="$PQC_ROOT/oqs-provider-install/lib"
# NOTE: system OpenSSL (3.0.13) cannot do provider-based TLS1.3 signature
# algorithms (oqs-provider README: "not supported until 3.2"; confirmed here
# via a live repro: SSL_CTX_use_certificate -> "unknown certificate type"
# because ctx->sigalg_list_len stays 0 -- oqs-provider's TLS-SIGALG capability
# code is compiled out entirely when built against pre-3.2 headers, see
# oqsprov_capabilities.c's #ifdef OSSL_CAPABILITY_TLS_SIGALG_NAME). A private
# OpenSSL 3.2.6 was built from source (pqc-tls/openssl32/) purely to supply a
# newer libssl.so.3/libcrypto.so.3 at runtime via LD_LIBRARY_PATH -- radiusd
# and rlm_eap_tls.so are unmodified/unrebuilt; the dynamic linker just
# resolves their libssl.so.3/libcrypto.so.3 DT_NEEDED entries against this
# newer, ABI-compatible build instead of the system one. oqs-provider was
# rebuilt against these 3.2.6 headers (liboqs did not need rebuilding: it
# only declares libcrypto.so.3 by SONAME and picks up whichever is found via
# LD_LIBRARY_PATH at runtime too). Verified end-to-end with a raw
# s_server/s_client ML-DSA-44 mutual handshake before wiring into radiusd:
# "Peer signature type: mldsa44", "Shared groups: X25519MLKEM768:x25519".
export OQS_OPENSSL32_LIB="$PQC_ROOT/openssl32-install/lib64"
export OQS_LD_LIBRARY_PATH="$OQS_OPENSSL32_LIB:$PQC_ROOT/liboqs-install/lib"

mode="${1:-status}"

stop_radiusd() {
    if pgrep -x radiusd >/dev/null 2>&1; then
        pkill -x radiusd 2>/dev/null
        for i in $(seq 1 20); do
            pgrep -x radiusd >/dev/null 2>&1 || break
            sleep 0.3
        done
    fi
}

wait_listening() {
    for i in $(seq 1 30); do
        if ss -uln 2>/dev/null | grep -q ':1812 '; then
            return 0
        fi
        sleep 0.3
    done
    return 1
}

case "$mode" in
  classic)
    sed -i 's/^\(\t\ttls = \)tls-hybrid-pqc/\1tls-common/' "$EAP_CONF"
    grep -n "tls = tls-" "$EAP_CONF" | head -1
    stop_radiusd
    ( unset OPENSSL_CONF OPENSSL_MODULES
      "$RADIUSD" -f > /tmp/radiusd-classic.log 2>&1 & )
    if wait_listening; then
        echo "[switch_tls_config] radiusd (classic / tls-common) listening on :1812"
    else
        echo "[switch_tls_config] ERROR: radiusd did not come up; see /tmp/radiusd-classic.log" >&2
        exit 1
    fi
    ;;
  hybrid)
    sed -i 's/^\(\t\ttls = \)tls-common/\1tls-hybrid-pqc/' "$EAP_CONF"
    grep -n "tls = tls-" "$EAP_CONF" | head -1
    stop_radiusd
    ( export OPENSSL_CONF="$OQS_OPENSSL_CONF"
      export OPENSSL_MODULES="$OQS_OPENSSL_MODULES"
      export LD_LIBRARY_PATH="$OQS_LD_LIBRARY_PATH:${LD_LIBRARY_PATH:-}"
      "$RADIUSD" -f > /tmp/radiusd-hybrid.log 2>&1 & )
    if wait_listening; then
        echo "[switch_tls_config] radiusd (hybrid-pqc / tls-hybrid-pqc, oqs-provider env) listening on :1812"
    else
        echo "[switch_tls_config] ERROR: radiusd did not come up; see /tmp/radiusd-hybrid.log" >&2
        exit 1
    fi
    ;;
  stop)
    stop_radiusd
    echo "[switch_tls_config] radiusd stopped"
    ;;
  status)
    grep -n "tls = tls-" "$EAP_CONF" | head -1
    if pgrep -x radiusd >/dev/null 2>&1; then
        echo "radiusd: running (pid $(pgrep -x radiusd | tr '\n' ' '))"
    else
        echo "radiusd: not running"
    fi
    ;;
  *)
    echo "usage: $0 classic|hybrid|stop|status" >&2
    exit 2
    ;;
esac
