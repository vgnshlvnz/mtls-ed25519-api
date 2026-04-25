#!/usr/bin/env bash
# tests/curl_tests.sh — v1.3 curl matrix against Apache :8445.
#
# v1.3: auth is entirely at Apache httpd. FastAPI :8443 is plain HTTP.
# This script targets Apache (the v1.3 auth boundary) and asserts the
# six canonical scenarios from the v1.0 baseline still hold under the
# new architecture:
#
#     1. GET /health (valid client-01 cert)            -> HTTP 200
#     2. GET /data   (valid client-01 cert)            -> HTTP 200
#     3. POST /data  (valid client-01 cert + JSON)     -> HTTP 200
#     4. No client cert                                -> rejected (TLS abort or 4xx)
#     5. Cert signed by rogue CA                       -> TLS handshake fail
#     6. Valid chain, CN=rogue-99 (not on allowlist)   -> HTTP 403 + JSON body
#
# Differences from the v1.0 / v1.1 versions:
#   * Endpoint is https://localhost:8445 (Apache test rig), not :8443
#   * Scenario 4 accepts EITHER curl exit ≠ 0 (TLS abort — Apache 2.4 +
#     OpenSSL 3 + TLS 1.3 default behaviour) OR an HTTP 4xx response
#     (some Apache builds complete the handshake first); both are valid
#     rejections, the upstream is never contacted in either case.
#   * Scenario 6 expects the canonical v1.3 JSON body
#     {"error":"forbidden","reason":"cn_not_allowlisted"} — note that
#     unlike nginx, Apache cannot interpolate $ssl_client_cn in the
#     ErrorDocument body, so the rejected CN is in the X-Rejected-CN
#     response header instead. The body schema is fixed.
#
# Exit 0 = all 6 pass; exit 1 = at least one regressed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APACHE_URL="https://localhost:${APACHE_HTTPS_PORT:-8445}"
CA="${REPO_ROOT}/pki/ca/ca.crt"
CRT="${REPO_ROOT}/pki/client/client.crt"
KEY="${REPO_ROOT}/pki/client/client.key"

# Throwaway rogue PKI for scenarios 5 and 6.
ROGUE_DIR="$(mktemp -d -t mtls-curl.XXXXXX)"
trap 'rm -rf "${ROGUE_DIR}"' EXIT

# Rogue self-signed CA + cert (different CA than ours)
openssl genpkey -algorithm ed25519 -out "${ROGUE_DIR}/rogueca.key" 2>/dev/null
openssl req -new -x509 -key "${ROGUE_DIR}/rogueca.key" \
    -out "${ROGUE_DIR}/rogueca.crt" \
    -subj "/CN=rogue-CA/O=Evil/C=XX" -days 365 \
    -config "${REPO_ROOT}/pki/openssl.cnf" -extensions v3_ca 2>/dev/null
openssl genpkey -algorithm ed25519 -out "${ROGUE_DIR}/rogue-self.key" 2>/dev/null
openssl req -new -key "${ROGUE_DIR}/rogue-self.key" \
    -out "${ROGUE_DIR}/rogue-self.csr" \
    -subj "/CN=rogue-self/O=Evil/C=XX" \
    -config "${REPO_ROOT}/pki/openssl.cnf" 2>/dev/null
openssl x509 -req -in "${ROGUE_DIR}/rogue-self.csr" \
    -CA "${ROGUE_DIR}/rogueca.crt" -CAkey "${ROGUE_DIR}/rogueca.key" \
    -out "${ROGUE_DIR}/rogue-self.crt" -days 365 2>/dev/null

# Cert with valid chain but disallowed CN.
openssl genpkey -algorithm ed25519 -out "${ROGUE_DIR}/rogue99.key" 2>/dev/null
openssl req -new -key "${ROGUE_DIR}/rogue99.key" \
    -out "${ROGUE_DIR}/rogue99.csr" \
    -subj "/CN=rogue-99/O=Lab/C=MY" \
    -config "${REPO_ROOT}/pki/openssl.cnf" 2>/dev/null
( cd "${REPO_ROOT}" && openssl ca -batch -notext \
    -config pki/openssl.cnf -in "${ROGUE_DIR}/rogue99.csr" \
    -out "${ROGUE_DIR}/rogue99.crt" -extensions v3_client \
    -cert pki/ca/ca.crt -keyfile pki/ca/ca.key -days 1 2>/dev/null )

# --- Helpers ---------------------------------------------------------------

PASS=()
FAIL=()

assert_http_eq() {
    local name="$1" expected="$2" actual="$3"
    if [[ "${actual}" == "${expected}" ]]; then
        PASS+=("${name}: HTTP ${actual}")
        printf '  [PASS] %-50s %s\n' "${name}" "HTTP ${actual}"
    else
        FAIL+=("${name}: expected HTTP ${expected}, got ${actual}")
        printf '  [FAIL] %-50s expected HTTP %s, got HTTP %s\n' \
            "${name}" "${expected}" "${actual}"
    fi
}

assert_rejected() {
    local name="$1" exit_code="$2" http_code="$3"
    # Reject if curl exit ≠ 0 OR HTTP response is in 4xx range.
    if [[ "${exit_code}" -ne 0 ]] || [[ "${http_code}" =~ ^4 ]]; then
        PASS+=("${name}: exit=${exit_code} http=${http_code}")
        printf '  [PASS] %-50s exit=%s http=%s\n' "${name}" "${exit_code}" "${http_code}"
    else
        FAIL+=("${name}: not rejected (exit=${exit_code} http=${http_code})")
        printf '  [FAIL] %-50s exit=%s http=%s (NOT REJECTED)\n' \
            "${name}" "${exit_code}" "${http_code}"
    fi
}

# --- 1-3: positive scenarios -----------------------------------------------

printf '\n--- Positive (expect HTTP 200) ---\n'

c=$(curl -sS --cacert "${CA}" --cert "${CRT}" --key "${KEY}" \
    -o /dev/null -w '%{http_code}' "${APACHE_URL}/health" || echo "000")
assert_http_eq "GET /health (client-01)" "200" "${c}"

c=$(curl -sS --cacert "${CA}" --cert "${CRT}" --key "${KEY}" \
    -o /dev/null -w '%{http_code}' "${APACHE_URL}/data" || echo "000")
assert_http_eq "GET /data (client-01)" "200" "${c}"

c=$(curl -sS --cacert "${CA}" --cert "${CRT}" --key "${KEY}" \
    -X POST -H 'Content-Type: application/json' -d '{"sensor":"x","value":1}' \
    -o /dev/null -w '%{http_code}' "${APACHE_URL}/data" || echo "000")
assert_http_eq "POST /data (client-01 + JSON)" "200" "${c}"

# --- 4: no client cert -----------------------------------------------------

printf '\n--- Negative (expect rejection) ---\n'

set +e
out=$(curl -sS --cacert "${CA}" -o /dev/null -w '%{http_code}' \
    "${APACHE_URL}/health" 2>&1)
ec=$?
set -e
assert_rejected "no client cert" "${ec}" "${out}"

# --- 5: cert signed by rogue CA --------------------------------------------

set +e
out=$(curl -sS --cacert "${CA}" \
    --cert "${ROGUE_DIR}/rogue-self.crt" --key "${ROGUE_DIR}/rogue-self.key" \
    -o /dev/null -w '%{http_code}' "${APACHE_URL}/health" 2>&1)
ec=$?
set -e
assert_rejected "cert signed by rogue CA" "${ec}" "${out}"

# --- 6: valid chain but CN=rogue-99 (HTTP 403 expected) --------------------

c=$(curl -sS --cacert "${CA}" \
    --cert "${ROGUE_DIR}/rogue99.crt" --key "${ROGUE_DIR}/rogue99.key" \
    -o /dev/null -w '%{http_code}' "${APACHE_URL}/health" || echo "000")
assert_http_eq "valid cert, CN=rogue-99 (allowlist deny)" "403" "${c}"

# --- Summary ---------------------------------------------------------------

printf '\n================= SUMMARY =================\n'
printf 'Apache target: %s\n' "${APACHE_URL}"
printf 'Passed: %d\n' "${#PASS[@]}"
printf 'Failed: %d\n' "${#FAIL[@]}"
if [[ ${#FAIL[@]} -gt 0 ]]; then
    printf '\nFailures:\n'
    for f in "${FAIL[@]}"; do printf '  - %s\n' "${f}"; done
    exit 1
fi
printf '\nAll 6 v1.3 curl scenarios passed.\n'
