#!/usr/bin/env bash
# pki_setup.sh — end-to-end ED25519 PKI bootstrap for the mTLS REST API.
#
# Produces:
#   pki/ca/ca.key        CA private key       (Ed25519, chmod 600)
#   pki/ca/ca.crt        Self-signed CA cert  (10 years)
#   pki/server/server.*  server identity      (Ed25519, 1 year, SAN localhost+127.0.0.1)
#   pki/client/client.*  client identity      (Ed25519, 1 year, CN=client-01)
#
# Usage:
#   ./pki_setup.sh           # generate missing artifacts; leave existing ones alone
#   ./pki_setup.sh --force   # wipe all keys/certs under pki/ and regenerate
#
# Idempotent by default. Safe to re-run.

set -euo pipefail

# --- Paths (all relative to this script's directory) -----------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="${SCRIPT_DIR}/pki"
CA_DIR="${PKI_DIR}/ca"
SERVER_DIR="${PKI_DIR}/server"
CLIENT_DIR="${PKI_DIR}/client"
CNF="${PKI_DIR}/openssl.cnf"

CA_KEY="${CA_DIR}/ca.key"
CA_CRT="${CA_DIR}/ca.crt"
CA_SRL="${CA_DIR}/ca.srl"

SRV_KEY="${SERVER_DIR}/server.key"
SRV_CSR="${SERVER_DIR}/server.csr"
SRV_CRT="${SERVER_DIR}/server.crt"

CLI_KEY="${CLIENT_DIR}/client.key"
CLI_CSR="${CLIENT_DIR}/client.csr"
CLI_CRT="${CLIENT_DIR}/client.crt"

# Phase-5 CA database state (needed by `openssl ca` for CRL management).
CA_INDEX="${CA_DIR}/index.txt"
CA_SERIAL="${CA_DIR}/serial"
CA_CRLNUMBER="${CA_DIR}/crlnumber"
CA_NEWCERTS="${CA_DIR}/newcerts"
CA_CRL="${CA_DIR}/ca.crl"

CA_DAYS=3650    # 10 years
LEAF_DAYS=365   # 1 year

# --- Status output (color only when stdout is a TTY) -----------------------
if [[ -t 1 ]]; then
    GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'
    BOLD=$'\033[1m'; NC=$'\033[0m'
else
    GREEN=""; YELLOW=""; RED=""; BOLD=""; NC=""
fi

info() { printf '%s[INFO]%s %s\n' "${GREEN}" "${NC}" "$*"; }
warn() { printf '%s[WARN]%s %s\n' "${YELLOW}" "${NC}" "$*" >&2; }
fail() { printf '%s[FAIL]%s %s\n' "${RED}"   "${NC}" "$*" >&2; exit 1; }

# --- Preflight --------------------------------------------------------------
require_openssl() {
    command -v openssl >/dev/null 2>&1 || fail "openssl not found in PATH"
    local major
    major="$(openssl version | awk '{print $2}' | cut -d. -f1)"
    [[ "${major}" -ge 3 ]] || warn "OpenSSL 3.x recommended (found: $(openssl version))"
}

FORCE=0
case "${1:-}" in
    ""|--force) [[ "${1:-}" == "--force" ]] && FORCE=1 ;;
    -h|--help)
        sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *) fail "Unknown argument: $1 (try --help)" ;;
esac

require_openssl
[[ -f "${CNF}" ]] || fail "Missing OpenSSL config: ${CNF}"
mkdir -p "${CA_DIR}" "${SERVER_DIR}" "${CLIENT_DIR}"

if [[ ${FORCE} -eq 1 ]]; then
    warn "--force: removing existing keys, CSRs, certs, CRL, and CA database"
    rm -f "${CA_KEY}" "${CA_CRT}" "${CA_SRL}" "${CA_CRL}"
    rm -f "${SRV_KEY}" "${SRV_CSR}" "${SRV_CRT}"
    rm -f "${CLI_KEY}" "${CLI_CSR}" "${CLI_CRT}"
    # Wipe the Phase-5 CA database state so openssl ca starts from serial 01.
    rm -f "${CA_INDEX}" "${CA_INDEX}.attr" "${CA_INDEX}.old" \
          "${CA_INDEX}.attr.old" "${CA_SERIAL}" "${CA_SERIAL}.old" \
          "${CA_CRLNUMBER}" "${CA_CRLNUMBER}.old"
    rm -rf "${CA_NEWCERTS}"
fi

# --- CA database (for openssl ca / CRL management) --------------------------
#
# `openssl ca` refuses to start if any of these don't exist. We create them
# as empty/seed values once, then openssl manages them. Skipped cleanly on
# re-runs when they already exist.
init_ca_db() {
    mkdir -p "${CA_NEWCERTS}"
    [[ -f "${CA_INDEX}" ]]     || : > "${CA_INDEX}"
    [[ -f "${CA_SERIAL}" ]]    || printf '01\n' > "${CA_SERIAL}"
    [[ -f "${CA_CRLNUMBER}" ]] || printf '01\n' > "${CA_CRLNUMBER}"
}

# Emit pki/ca/ca.crl. Harmless to call repeatedly — openssl ca rebuilds it
# from index.txt each time (picks up any freshly-revoked certs).
# MUST be called from the project root so CA_default paths in openssl.cnf
# resolve correctly (dir = ./pki/ca).
gen_crl() {
    ( cd "${SCRIPT_DIR}" && \
        openssl ca -config "${CNF}" -gencrl -out "${CA_CRL}" 2>/dev/null )
    chmod 644 "${CA_CRL}"
}

# --- CA ---------------------------------------------------------------------
gen_ca() {
    if [[ -f "${CA_KEY}" && -f "${CA_CRT}" ]]; then
        info "CA already present — skipping (use --force to regenerate)."
        return
    fi

    info "Generating CA private key (Ed25519) -> ${CA_KEY##*/}"
    # genpkey -algorithm ed25519 : produces an unencrypted Ed25519 key.
    openssl genpkey -algorithm ed25519 -out "${CA_KEY}"
    chmod 600 "${CA_KEY}"

    info "Self-signing CA certificate (${CA_DAYS} days) -> ${CA_CRT##*/}"
    # -new -x509       : create a self-signed cert in one step.
    # -config/-extensions v3_ca : load basicConstraints CA:TRUE + keyCertSign/cRLSign.
    # -subj            : deterministic DN (prompt=no in config).
    openssl req -new -x509 \
        -key "${CA_KEY}" \
        -out "${CA_CRT}" \
        -days "${CA_DAYS}" \
        -subj "/CN=mTLS-CA/O=Lab/C=MY" \
        -config "${CNF}" \
        -extensions v3_ca
    chmod 644 "${CA_CRT}"
}

# --- Leaf signing helper ----------------------------------------------------
# Args: <label> <key> <csr> <crt> <subj> <extension-section>
#
# Uses `openssl ca` (not `openssl x509 -req`) so the issued cert is
# registered in pki/ca/index.txt. That registration is what makes Phase-5
# revocation work: `openssl ca -revoke` needs to find the cert's serial in
# index.txt to mark it R(evoked) and have it appear in the next CRL.
gen_leaf() {
    local label="$1" key="$2" csr="$3" crt="$4" subj="$5" ext="$6"

    if [[ -f "${key}" && -f "${crt}" ]]; then
        info "${label} cert already present — skipping."
        return
    fi

    info "Generating ${label} private key (Ed25519)"
    openssl genpkey -algorithm ed25519 -out "${key}"
    chmod 600 "${key}"

    info "Creating ${label} CSR"
    # CSR carries the DN only; extensions are applied at signing time.
    openssl req -new \
        -key "${key}" \
        -out "${csr}" \
        -subj "${subj}" \
        -config "${CNF}"

    info "Signing ${label} cert with CA (${LEAF_DAYS} days)"
    # -batch    : don't prompt for confirmation.
    # -notext   : write only the PEM cert (no preamble text dump).
    # -extensions : pull v3_{server,client} from openssl.cnf.
    # Must run from the project root — paths in [CA_default] are relative.
    (
        cd "${SCRIPT_DIR}"
        openssl ca -config "${CNF}" \
            -batch -notext \
            -in "${csr}" \
            -out "${crt}" \
            -days "${LEAF_DAYS}" \
            -extensions "${ext}" \
            -cert "${CA_CRT}" -keyfile "${CA_KEY}" 2>/dev/null
    )
    chmod 644 "${crt}"
}

# --- Verification -----------------------------------------------------------
verify_chain() {
    local label="$1" crt="$2"
    printf '%s[VERIFY]%s %s: ' "${GREEN}" "${NC}" "${label}"
    if openssl verify -CAfile "${CA_CRT}" "${crt}"; then
        :
    else
        fail "${label} chain verification FAILED"
    fi
}

print_cert_info() {
    local label="$1" crt="$2"
    printf '\n%s=== %s ===%s\n' "${BOLD}" "${label}" "${NC}"
    openssl x509 -in "${crt}" -noout -subject -issuer -startdate -enddate
    # Public-key + signature algorithm lines, extracted from the full text dump.
    openssl x509 -in "${crt}" -noout -text \
        | awk '/Public Key Algorithm|Signature Algorithm/ && n<2 {print; n++}'
    # SAN extension — only present on the server cert in this PKI.
    # Check the full text dump first so we don't emit OpenSSL's confusing
    # "No extensions in certificate" line when the extension is absent.
    if openssl x509 -in "${crt}" -noout -text \
            | grep -q "Subject Alternative Name"; then
        openssl x509 -in "${crt}" -noout -ext subjectAltName \
            | awk '/DNS:|IP:/ {print "    SAN:" $0}'
    fi
}

# --- Main -------------------------------------------------------------------
gen_ca

# CA DB and an initial empty CRL land right after the CA is minted. They are
# only needed by the Phase-5 revoke flow, but generating them here means
# `openssl ca` is ready to use the moment the CA exists, without a separate
# "init" step.
init_ca_db
if [[ ! -f "${CA_CRL}" ]]; then
    info "Generating initial (empty) CRL -> ${CA_CRL##*/}"
    gen_crl
fi

gen_leaf "server" "${SRV_KEY}" "${SRV_CSR}" "${SRV_CRT}" \
    "/CN=server/O=Lab/C=MY" "v3_server"
gen_leaf "client" "${CLI_KEY}" "${CLI_CSR}" "${CLI_CRT}" \
    "/CN=client-01/O=Lab/C=MY" "v3_client"

printf '\n'
verify_chain "server" "${SRV_CRT}"
verify_chain "client" "${CLI_CRT}"

print_cert_info "CA"     "${CA_CRT}"
print_cert_info "Server" "${SRV_CRT}"
print_cert_info "Client" "${CLI_CRT}"

printf '\n%s%sPKI setup complete.%s\n' "${BOLD}" "${GREEN}" "${NC}"
