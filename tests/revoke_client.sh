#!/usr/bin/env bash
# revoke_client.sh — mark a client cert revoked and regenerate the CRL.
#
# Usage:
#   ./tests/revoke_client.sh [<cert-path>]
#
# Default target is pki/client/client.crt. The CRL at pki/ca/ca.crl is
# regenerated from pki/ca/index.txt after the revocation so that a server
# restart picks up the new state.
#
# Idempotent: re-running against an already-revoked cert prints a notice
# and still re-emits the CRL. The script only exits non-zero if the CRL
# regeneration itself fails.

set -euo pipefail

# --- Paths ------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CA_DIR="${REPO_ROOT}/pki/ca"
CNF="${REPO_ROOT}/pki/openssl.cnf"
CA_CRL="${CA_DIR}/ca.crl"

TARGET_CERT="${1:-${REPO_ROOT}/pki/client/client.crt}"

# --- Colors -----------------------------------------------------------------
if [[ -t 1 ]]; then
    GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'
    BOLD=$'\033[1m'; NC=$'\033[0m'
else
    GREEN=""; YELLOW=""; RED=""; BOLD=""; NC=""
fi

info() { printf '%s[INFO]%s %s\n' "${GREEN}"  "${NC}" "$*"; }
warn() { printf '%s[WARN]%s %s\n' "${YELLOW}" "${NC}" "$*" >&2; }
fail() { printf '%s[FAIL]%s %s\n' "${RED}"    "${NC}" "$*" >&2; exit 1; }

# --- Preflight --------------------------------------------------------------
[[ -f "${TARGET_CERT}" ]] || fail "cert not found: ${TARGET_CERT}"
[[ -f "${CNF}" ]]         || fail "openssl config missing: ${CNF}"
[[ -f "${CA_DIR}/index.txt" ]] || \
    fail "CA database missing. Run ./pki_setup.sh first."

# --- Inspect before ---------------------------------------------------------
subj=$(openssl x509 -in "${TARGET_CERT}" -noout -subject | sed 's/^subject=//')
serial=$(openssl x509 -in "${TARGET_CERT}" -noout -serial | sed 's/^serial=//')
info "target: ${subj} (serial ${serial})"

# --- Revoke (tolerate "already revoked" errors gracefully) -----------------
# openssl ca -revoke writes to index.txt. If the cert is already marked R
# it exits non-zero with "ERROR:Already revoked"; we capture stderr and
# detect that case so the script stays idempotent.
info "issuing openssl ca -revoke"
set +e
revoke_stderr=$(
    cd "${REPO_ROOT}" && \
    openssl ca -config "${CNF}" -revoke "${TARGET_CERT}" 2>&1 >/dev/null
)
revoke_ec=$?
set -e

if [[ ${revoke_ec} -ne 0 ]]; then
    if grep -qi "already revoked" <<< "${revoke_stderr}"; then
        warn "already revoked — proceeding to regenerate CRL anyway"
    else
        printf '%s\n' "${revoke_stderr}" >&2
        fail "openssl ca -revoke returned ${revoke_ec}"
    fi
fi

# --- Regenerate CRL ---------------------------------------------------------
info "regenerating CRL -> ${CA_CRL##*/}"
(
    cd "${REPO_ROOT}" && \
    openssl ca -config "${CNF}" -gencrl -out "${CA_CRL}" 2>/dev/null
)
chmod 644 "${CA_CRL}"

# --- Show the revoked-certs section of the new CRL --------------------------
printf '\n%s=== New CRL =%s\n' "${BOLD}" "${NC}"
openssl crl -in "${CA_CRL}" -noout -text \
    | awk '/Last Update|Next Update|Revoked Certificates|Serial Number|Revocation Date/ {print}'

printf '\n%s%sDone. Restart the server to pick up the new CRL.%s\n' \
    "${BOLD}" "${GREEN}" "${NC}"
