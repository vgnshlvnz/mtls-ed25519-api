#!/usr/bin/env bash
# negative_tests.sh — TLS-layer negative-path tests for the mTLS server.
#
# Narrow-focus companion to curl_tests.sh: exercises ONLY the scenarios
# that must be rejected at the TLS handshake (not at the HTTP/authz
# layer). A PASS means curl exited non-zero because the ssl module
# refused the handshake; a FAIL means curl somehow got an HTTP response
# back (which would indicate the TLS stack is misconfigured).
#
# Scenarios:
#   1. No client cert presented.
#   2. Self-signed rogue cert (signed by a CA the server does not trust).
#
# The Phase-3 authz failure (valid cert but CN not in allowlist) is NOT
# tested here — that's an HTTP-layer 403, not a TLS-layer reject, and
# belongs in curl_tests.sh.
#
# Exit 0 if both tests pass, 1 otherwise.

set -euo pipefail

# --- Paths ------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CA_CRT="${REPO_ROOT}/pki/ca/ca.crt"
CNF="${REPO_ROOT}/pki/openssl.cnf"
BASE_URL="https://localhost:8443"

# --- Colors -----------------------------------------------------------------
if [[ -t 1 ]]; then
    GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'
    BOLD=$'\033[1m'; NC=$'\033[0m'
else
    GREEN=""; RED=""; YELLOW=""; BOLD=""; NC=""
fi

# --- Tmp for rogue material -------------------------------------------------
TMP_DIR="$(mktemp -d -t mtls-neg-XXXXXX)"
trap 'rm -rf "${TMP_DIR}"' EXIT

# --- Helpers ----------------------------------------------------------------
info()  { printf '%s[INFO]%s %s\n' "${YELLOW}" "${NC}" "$*"; }
pass()  { printf '%s[PASS]%s %s\n' "${GREEN}"  "${NC}" "$*"; }
fail()  { printf '%s[FAIL]%s %s\n' "${RED}"    "${NC}" "$*"; }

FAILURES=0

assert_handshake_rejected() {
    # Runs curl with the supplied args. Test passes iff curl exits non-zero,
    # i.e. the TLS handshake was refused. If curl succeeds (exit 0) that
    # means the server accepted a client it should NOT have accepted — a
    # critical bug.
    local name="$1"; shift
    set +e
    curl --silent --show-error --output /dev/null --max-time 5 "$@" >/dev/null 2>&1
    local ec=$?
    set -e
    if [[ ${ec} -ne 0 ]]; then
        pass "${name} (curl exit=${ec})"
    else
        fail "${name} — curl exit=0: server accepted an invalid connection!"
        FAILURES=$((FAILURES + 1))
    fi
}

# --- Pre-flight: server must be up ------------------------------------------
info "preflight: server reachability check"
if ! curl --silent --show-error --output /dev/null --max-time 3 \
          --cacert "${CA_CRT}" \
          --cert "${REPO_ROOT}/pki/client/client.crt" \
          --key  "${REPO_ROOT}/pki/client/client.key" \
          -w '' "${BASE_URL}/health" 2>/dev/null; then
    printf '%s[SETUP-FAIL]%s Server not reachable at %s.\n' \
        "${RED}" "${NC}" "${BASE_URL}" >&2
    printf '             Start it with: python server.py\n' >&2
    exit 2
fi

# --- Generate a throwaway self-signed rogue cert ----------------------------
# Same Ed25519 key type as the real CA, but completely outside our trust
# chain. The server's ssl.SSLContext has ONLY pki/ca/ca.crt as the trust
# anchor, so this cert cannot verify.
info "generating throwaway self-signed rogue cert in ${TMP_DIR}"
openssl genpkey -algorithm ed25519 -out "${TMP_DIR}/rogue.key" 2>/dev/null
openssl req -new -x509 -key "${TMP_DIR}/rogue.key" \
    -out "${TMP_DIR}/rogue.crt" -days 1 \
    -subj "/CN=client-01/O=Rogue/C=XX" \
    -config "${CNF}" -extensions v3_client 2>/dev/null

# --- Test 1 — no client cert ------------------------------------------------
# TLS handshake must fail because the server uses ssl.CERT_REQUIRED. curl
# should exit non-zero (typically 56 on Linux: "Recv failure: Connection
# reset by peer" or similar) before any HTTP bytes flow.
assert_handshake_rejected "no client cert" \
    --cacert "${CA_CRT}" \
    "${BASE_URL}/health"

# --- Test 2 — rogue self-signed cert ----------------------------------------
# Server will reject at verify-peer-cert step because the issuer is not in
# the trust store. Again, no HTTP layer involved.
assert_handshake_rejected "rogue self-signed cert" \
    --cacert "${CA_CRT}" \
    --cert "${TMP_DIR}/rogue.crt" \
    --key  "${TMP_DIR}/rogue.key" \
    "${BASE_URL}/health"

# --- Summary ----------------------------------------------------------------
printf '\n'
if [[ ${FAILURES} -eq 0 ]]; then
    printf '%s%sAll negative tests passed — TLS layer is locked down.%s\n' \
        "${BOLD}" "${GREEN}" "${NC}"
    exit 0
else
    printf '%s%s%d negative test(s) failed — server accepted something it should not.%s\n' \
        "${BOLD}" "${RED}" "${FAILURES}" "${NC}"
    exit 1
fi
