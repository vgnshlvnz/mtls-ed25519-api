#!/usr/bin/env bash
# nginx-test-gen.sh — substitute PKI_DIR / LOG_DIR / NGINX_CONF_DIR
# placeholders in nginx/nginx.conf with absolute paths for the local
# test config.
#
# Output: nginx/nginx-test.conf (gitignored).
#
# Run from the project root:
#     bash nginx/nginx-test-gen.sh
#
# The generated file is what `make nginx-check` / `make nginx-start`
# consume. Regenerate any time nginx.conf or the repo root moves.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SRC="${SCRIPT_DIR}/nginx.conf"
OUT="${SCRIPT_DIR}/nginx-test.conf"

# Test-mode ports default to unprivileged so `nginx -t` runs without
# CAP_NET_BIND_SERVICE. 8444 (not 8443) so the nginx listener does
# not collide with FastAPI, which still binds 127.0.0.1:8443 in this
# phase. Override via env vars when the lab machine has the
# capability (or when running under sudo).
HTTPS_PORT="${HTTPS_PORT:-8444}"
HTTP_PORT="${HTTP_PORT:-8081}"

[[ -f "${SRC}" ]] || { echo "missing template: ${SRC}" >&2; exit 1; }

# Ensure the log dir exists so nginx -t doesn't complain about
# missing error_log parents.
mkdir -p "${SCRIPT_DIR}/logs"

{
    printf '# GENERATED FILE — do not edit manually.\n'
    printf '# Source: %s\n' "${SRC##"${REPO_ROOT}"/}"
    printf '# Generated at: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '\n'
    sed \
        -e "s|PKI_DIR|${REPO_ROOT}/pki|g" \
        -e "s|LOG_DIR|${SCRIPT_DIR}/logs|g" \
        -e "s|NGINX_CONF_DIR|${SCRIPT_DIR}|g" \
        -e "s|HTTPS_PORT|${HTTPS_PORT}|g" \
        -e "s|HTTP_PORT|${HTTP_PORT}|g" \
        "${SRC}"
} > "${OUT}"

printf '[nginx-test-gen] wrote %s\n' "${OUT##"${REPO_ROOT}"/}"
