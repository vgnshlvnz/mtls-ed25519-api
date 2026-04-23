#!/usr/bin/env bash
# curl_tests.sh — end-to-end mTLS matrix against https://127.0.0.1:8443.
#
# Runs all six scenarios (3 positive, 3 negative), prints a per-test
# PASS/FAIL line with the exact command that was run, and finishes with a
# Markdown-style summary table. Exits 0 if every test passes, 1 otherwise.
#
# Prerequisites:
#   * The server must already be running. Start it in another terminal:
#         source venv/bin/activate && python server.py
#   * pki/ must contain the Phase-1 CA and client material.
#
# Throwaway "rogue" certs needed for the negative scenarios are generated
# inline into a tmpdir that is removed on exit — nothing is persisted.
#
# Idempotent: safe to run repeatedly.

set -euo pipefail

# --- Paths ------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PKI_DIR="${REPO_ROOT}/pki"

CA_CRT="${PKI_DIR}/ca/ca.crt"
CA_KEY="${PKI_DIR}/ca/ca.key"
CLI_CRT="${PKI_DIR}/client/client.crt"
CLI_KEY="${PKI_DIR}/client/client.key"
CNF="${PKI_DIR}/openssl.cnf"

BASE_URL="https://localhost:8443"

# --- Colors (TTY only) ------------------------------------------------------
if [[ -t 1 ]]; then
    GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'
    BOLD=$'\033[1m'; NC=$'\033[0m'
else
    GREEN=""; RED=""; YELLOW=""; BOLD=""; NC=""
fi

# --- Tmp dir for rogue certs -----------------------------------------------
TMP_DIR="$(mktemp -d -t mtls-phase4-XXXXXX)"
trap 'rm -rf "${TMP_DIR}"' EXIT

# --- Helpers ----------------------------------------------------------------
info() { printf '%s[INFO]%s %s\n' "${YELLOW}" "${NC}" "$*"; }
fail_setup() {
    printf '%s[SETUP-FAIL]%s %s\n' "${RED}" "${NC}" "$*" >&2
    exit 2
}

# Pre-flight: is the mTLS server reachable with the valid client cert?
check_server_up() {
    local http
    if ! http=$(curl --silent --show-error --output /dev/null \
                     --max-time 3 \
                     --cacert "${CA_CRT}" --cert "${CLI_CRT}" --key "${CLI_KEY}" \
                     -w '%{http_code}' "${BASE_URL}/health" 2>/dev/null); then
        fail_setup "Server not reachable at ${BASE_URL}. Start it with: python server.py"
    fi
    if [[ "${http}" != "200" ]]; then
        fail_setup "Server reachable but /health returned HTTP ${http} (expected 200)."
    fi
}

# Generate a cert signed by OUR CA but with CN=rogue-99 (valid chain, but
# the middleware allowlist should reject it with 403).
gen_rogue_cn_cert() {
    openssl genpkey -algorithm ed25519 -out "${TMP_DIR}/rogue-cn.key" 2>/dev/null
    openssl req -new -key "${TMP_DIR}/rogue-cn.key" \
        -out "${TMP_DIR}/rogue-cn.csr" \
        -subj "/CN=rogue-99/O=Lab/C=MY" \
        -config "${CNF}" 2>/dev/null
    openssl x509 -req -in "${TMP_DIR}/rogue-cn.csr" \
        -CA "${CA_CRT}" -CAkey "${CA_KEY}" -CAcreateserial \
        -CAserial "${TMP_DIR}/ca.srl" \
        -out "${TMP_DIR}/rogue-cn.crt" -days 1 \
        -extfile "${CNF}" -extensions v3_client 2>/dev/null
}

# Generate a brand-new rogue CA and a client cert signed by it — for the
# "cert signed by unknown CA" scenario (TLS handshake must fail).
gen_rogue_ca_cert() {
    openssl genpkey -algorithm ed25519 -out "${TMP_DIR}/rogue-ca.key" 2>/dev/null
    openssl req -new -x509 -key "${TMP_DIR}/rogue-ca.key" \
        -out "${TMP_DIR}/rogue-ca.crt" -days 1 \
        -subj "/CN=rogue-CA/O=Rogue/C=XX" \
        -config "${CNF}" -extensions v3_ca 2>/dev/null

    openssl genpkey -algorithm ed25519 -out "${TMP_DIR}/rogue-chain.key" 2>/dev/null
    openssl req -new -key "${TMP_DIR}/rogue-chain.key" \
        -out "${TMP_DIR}/rogue-chain.csr" \
        -subj "/CN=client-01/O=Rogue/C=XX" \
        -config "${CNF}" 2>/dev/null
    openssl x509 -req -in "${TMP_DIR}/rogue-chain.csr" \
        -CA "${TMP_DIR}/rogue-ca.crt" -CAkey "${TMP_DIR}/rogue-ca.key" -CAcreateserial \
        -CAserial "${TMP_DIR}/rogue-ca.srl" \
        -out "${TMP_DIR}/rogue-chain.crt" -days 1 \
        -extfile "${CNF}" -extensions v3_client 2>/dev/null
}

# Results accumulator. Each entry is "name|expected|actual|verdict".
declare -a RESULTS

record() {
    RESULTS+=("$1|$2|$3|$4")
}

print_pass() { printf '%s[PASS]%s %s\n' "${GREEN}" "${NC}" "$*"; }
print_fail() { printf '%s[FAIL]%s %s\n' "${RED}"   "${NC}" "$*"; }

# --- Test helpers -----------------------------------------------------------
# Assert that an HTTP response with the supplied curl args yields the
# expected status code.
#
# Usage: assert_http <name> <expected_code> <curl args...>
assert_http() {
    local name="$1"; shift
    local expected="$1"; shift
    local actual
    actual=$(curl --silent --show-error --output /dev/null \
                  --max-time 5 \
                  -w '%{http_code}' "$@" 2>/dev/null || echo "000")
    if [[ "${actual}" == "${expected}" ]]; then
        print_pass "${name}: HTTP ${actual}"
        record "${name}" "HTTP ${expected}" "HTTP ${actual}" "PASS"
    else
        print_fail "${name}: expected HTTP ${expected}, got HTTP ${actual}"
        record "${name}" "HTTP ${expected}" "HTTP ${actual}" "FAIL"
    fi
}

# Assert that curl EXITS non-zero (TLS handshake failure).
#
# Usage: assert_tls_reject <name> <curl args...>
assert_tls_reject() {
    local name="$1"; shift
    set +e
    curl --silent --show-error --output /dev/null --max-time 5 "$@" >/dev/null 2>&1
    local exit_code=$?
    set -e
    if [[ ${exit_code} -ne 0 ]]; then
        print_pass "${name}: curl exit=${exit_code} (handshake rejected)"
        record "${name}" "TLS reject" "curl exit=${exit_code}" "PASS"
    else
        print_fail "${name}: curl succeeded — TLS handshake should have failed"
        record "${name}" "TLS reject" "curl exit=0" "FAIL"
    fi
}

# --- Main -------------------------------------------------------------------
info "preflight: checking server at ${BASE_URL}"
check_server_up

info "generating throwaway rogue certs in ${TMP_DIR}"
gen_rogue_cn_cert
gen_rogue_ca_cert

printf '\n%s--- Positive tests (expect HTTP 2xx) ---%s\n' "${BOLD}" "${NC}"

# -----------------------------------------------------------------------------
# Test 1 — GET /health with valid client cert.
# What it proves: happy-path mTLS — TLS handshake succeeds, CN is on the
# allowlist, app returns liveness payload.
# -----------------------------------------------------------------------------
assert_http "GET /health (valid cert)" "200" \
    --cacert "${CA_CRT}" --cert "${CLI_CRT}" --key "${CLI_KEY}" \
    "${BASE_URL}/health"

# -----------------------------------------------------------------------------
# Test 2 — GET /data with valid client cert.
# What it proves: route handlers besides /health work under the same
# identity/middleware pipeline.
# -----------------------------------------------------------------------------
assert_http "GET /data (valid cert)" "200" \
    --cacert "${CA_CRT}" --cert "${CLI_CRT}" --key "${CLI_KEY}" \
    "${BASE_URL}/data"

# -----------------------------------------------------------------------------
# Test 3 — POST /data with valid client cert + JSON body.
# What it proves: request-body parsing, Pydantic round-trip, echo+timestamp.
# -----------------------------------------------------------------------------
assert_http "POST /data (valid cert + JSON)" "200" \
    --cacert "${CA_CRT}" --cert "${CLI_CRT}" --key "${CLI_KEY}" \
    -H 'Content-Type: application/json' \
    -d '{"sensor_id":"temp-test","value":42.0,"unit":"C"}' \
    "${BASE_URL}/data"

printf '\n%s--- Negative tests (expect TLS reject or HTTP 4xx) ---%s\n' "${BOLD}" "${NC}"

# -----------------------------------------------------------------------------
# Test 4 — No client cert presented.
# What it proves: ssl.CERT_REQUIRED on the server rejects the handshake
# before any HTTP bytes are exchanged. curl should exit non-zero.
# -----------------------------------------------------------------------------
assert_tls_reject "no client cert (TLS handshake must fail)" \
    --cacert "${CA_CRT}" \
    "${BASE_URL}/health"

# -----------------------------------------------------------------------------
# Test 5 — Cert signed by an unknown (rogue) CA.
# What it proves: the server's trust anchor is narrow — certs signed by
# any other CA are rejected at handshake time, NOT admitted and later
# checked at the app layer.
# -----------------------------------------------------------------------------
assert_tls_reject "cert signed by rogue CA (handshake must fail)" \
    --cacert "${CA_CRT}" \
    --cert "${TMP_DIR}/rogue-chain.crt" \
    --key  "${TMP_DIR}/rogue-chain.key" \
    "${BASE_URL}/health"

# -----------------------------------------------------------------------------
# Test 6 — Valid cert chain, but CN is NOT in the allowlist.
# What it proves: the Phase-3 allowlist (ALLOWED_CLIENT_CNS) adds a second
# authorization layer on TOP of TLS trust; a client that is cryptographically
# trusted can still be denied at the app layer and receives a 403 JSON
# body matching the project schema.
# -----------------------------------------------------------------------------
assert_http "valid cert, CN=rogue-99 (must get 403)" "403" \
    --cacert "${CA_CRT}" \
    --cert "${TMP_DIR}/rogue-cn.crt" \
    --key  "${TMP_DIR}/rogue-cn.key" \
    "${BASE_URL}/health"

# --- Summary table ----------------------------------------------------------
printf '\n%s================= SUMMARY =================%s\n' "${BOLD}" "${NC}"
printf '| %-45s | %-15s | %-20s | %-4s |\n' "Test" "Expected" "Actual" "?"
printf '|%s|%s|%s|%s|\n' \
    "$(printf -- '-%.0s' {1..47})" \
    "$(printf -- '-%.0s' {1..17})" \
    "$(printf -- '-%.0s' {1..22})" \
    "$(printf -- '-%.0s' {1..6})"

pass_count=0
fail_count=0
for r in "${RESULTS[@]}"; do
    IFS='|' read -r name expected actual verdict <<< "${r}"
    printf '| %-45s | %-15s | %-20s | %-4s |\n' \
        "${name}" "${expected}" "${actual}" "${verdict}"
    if [[ "${verdict}" == "PASS" ]]; then
        pass_count=$((pass_count + 1))
    else
        fail_count=$((fail_count + 1))
    fi
done

printf '\n'
if [[ ${fail_count} -eq 0 ]]; then
    printf '%s%sAll %d tests passed.%s\n' "${BOLD}" "${GREEN}" "${pass_count}" "${NC}"
    exit 0
else
    printf '%s%s%d/%d failed.%s\n' "${BOLD}" "${RED}" \
        "${fail_count}" "$((pass_count + fail_count))" "${NC}"
    exit 1
fi
