#!/usr/bin/env bash
# nginx-test-gen.sh — substitute @@PROJECT_ROOT@@ placeholders in the
# tracked nginx.conf template to produce nginx-test.conf with absolute
# paths suitable for the local test rig.
#
# The generated file is in .gitignore — regenerate it any time the
# checkout moves, or after editing nginx.conf.
#
# Usage:
#     nginx/nginx-test-gen.sh
#     nginx -t -c $(pwd)/nginx/nginx-test.conf   # validates

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SRC="${PROJECT_ROOT}/nginx/nginx.conf"
DST="${PROJECT_ROOT}/nginx/nginx-test.conf"
LOGS="${PROJECT_ROOT}/nginx/logs"

[[ -f "${SRC}" ]] || {
    printf 'error: source template missing: %s\n' "${SRC}" >&2
    exit 1
}

mkdir -p "${LOGS}"

# Write a banner then substitute. Use `#` as sed separator so the
# absolute path's `/`s don't need escaping.
{
    printf '# GENERATED FILE — do not edit manually.\n'
    printf '# Source: nginx/nginx.conf\n'
    printf '# Generated at: %s\n\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    sed "s#@@PROJECT_ROOT@@#${PROJECT_ROOT}#g" "${SRC}"
} > "${DST}"

printf 'wrote %s\n' "${DST}"
