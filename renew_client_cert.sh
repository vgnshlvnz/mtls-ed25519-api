#!/usr/bin/env bash
# renew_client_cert.sh — rotate the client cert to a fresh 24h-lived one.
#
# Generates a new Ed25519 key and a cert signed by the project CA, then
# atomically replaces pki/client/client.{key,crt}.
#
# Cron: run every 12 hours so a fresh cert is always in place while the
# previous one still has headroom:
#
#   0 */12 * * *  /absolute/path/to/renew_client_cert.sh >> /var/log/mtls-renew.log 2>&1
#
# systemd timer (alternative — OnCalendar in drop-in):
#
#   [Timer]
#   OnCalendar=*-*-* 00,12:00:00
#   Persistent=true
#
# ATOMICITY: each file is replaced via `mv` (atomic rename within the
# filesystem). The key and cert are two files though, so there is a
# microsecond-scale window where one is new and the other is old. We swap
# cert first, then key — so a connection attempted mid-swap sees
# (new cert, old key) which fails fast in signing instead of (old cert,
# new key) which would be the same fail. The Python server only reads
# this material at process start, so it's unaffected either way.

set -euo pipefail

# --- Paths ------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="${SCRIPT_DIR}/pki"
CA_DIR="${PKI_DIR}/ca"
CLIENT_DIR="${PKI_DIR}/client"
CNF="${PKI_DIR}/openssl.cnf"

CA_CRT="${CA_DIR}/ca.crt"
CA_KEY="${CA_DIR}/ca.key"

CLIENT_KEY="${CLIENT_DIR}/client.key"
CLIENT_CRT="${CLIENT_DIR}/client.crt"

CLIENT_CN="${CLIENT_CN:-client-01}"
CLIENT_SUBJECT="/CN=${CLIENT_CN}/O=Lab/C=MY"
LEAF_DAYS=1   # 24h — short-lived, cron rotates

# --- Colors -----------------------------------------------------------------
if [[ -t 1 ]]; then
    GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; NC=$'\033[0m'
else
    GREEN=""; YELLOW=""; RED=""; NC=""
fi
info() { printf '%s[INFO]%s %s\n' "${GREEN}"  "${NC}" "$*"; }
warn() { printf '%s[WARN]%s %s\n' "${YELLOW}" "${NC}" "$*" >&2; }
fail() { printf '%s[FAIL]%s %s\n' "${RED}"    "${NC}" "$*" >&2; exit 1; }

# --- Preflight --------------------------------------------------------------
[[ -f "${CA_CRT}" && -f "${CA_KEY}" ]] || \
    fail "CA material missing. Run ./pki_setup.sh first."
[[ -f "${CNF}" ]] || fail "openssl config missing: ${CNF}"
[[ -d "${CA_DIR}/newcerts" ]] || \
    fail "CA database missing. Run ./pki_setup.sh first."

# --- Stage new material in a tmpdir ----------------------------------------
STAGING="$(mktemp -d -t mtls-renew-XXXXXX)"
# Clean up on any exit path except the successful swap (which we do at the
# end with explicit mv). Failure mid-script leaves no half-installed state.
cleanup() { rm -rf "${STAGING}"; }
trap cleanup EXIT

NEW_KEY="${STAGING}/client.key"
NEW_CRT="${STAGING}/client.crt"
NEW_CSR="${STAGING}/client.csr"

info "generating new Ed25519 private key (staging)"
openssl genpkey -algorithm ed25519 -out "${NEW_KEY}"
chmod 600 "${NEW_KEY}"

info "creating CSR (subject: ${CLIENT_SUBJECT})"
openssl req -new \
    -key "${NEW_KEY}" \
    -out "${NEW_CSR}" \
    -subj "${CLIENT_SUBJECT}" \
    -config "${CNF}"

info "signing with CA (${LEAF_DAYS} day validity)"
(
    cd "${SCRIPT_DIR}"
    openssl ca -config "${CNF}" \
        -batch -notext \
        -in "${NEW_CSR}" \
        -out "${NEW_CRT}" \
        -days "${LEAF_DAYS}" \
        -extensions v3_client \
        -cert "${CA_CRT}" -keyfile "${CA_KEY}" 2>/dev/null
)
chmod 644 "${NEW_CRT}"

# SECURITY: never swap into place if the new cert does not verify against
# the CA. Catches a misconfigured cnf or a half-written cert before a
# broken cert is installed.
openssl verify -CAfile "${CA_CRT}" "${NEW_CRT}" >/dev/null || \
    fail "new cert did not verify against CA — aborting rotation"

# --- Atomic swap ------------------------------------------------------------
# cert first, then key (see header comment for why this order).
info "swapping new cert into place atomically"
mv "${NEW_CRT}" "${CLIENT_CRT}"
mv "${NEW_KEY}" "${CLIENT_KEY}"

# --- Report -----------------------------------------------------------------
not_after=$(openssl x509 -in "${CLIENT_CRT}" -noout -enddate | sed 's/^notAfter=//')
info "new cert installed. notAfter=${not_after}"
printf '\n'
openssl x509 -in "${CLIENT_CRT}" -noout -subject -issuer -dates
