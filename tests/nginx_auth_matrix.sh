#!/usr/bin/env bash
# nginx_auth_matrix.sh — run the N3 auth suite and print a PASS/FAIL
# table grouped by A..F category.
#
# Usage:
#   ./tests/nginx_auth_matrix.sh           # pytest output + group table
#   ./tests/nginx_auth_matrix.sh --quiet   # group table only
#
# Exit codes:
#   0  all passed (NE skips OK)
#   1  one or more tests failed
#   2  pytest / fixtures not available

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

QUIET=0
[[ "${1:-}" == "--quiet" ]] && QUIET=1

if [[ -t 1 ]]; then
    GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'
    BOLD=$'\033[1m'; NC=$'\033[0m'
else
    GREEN=""; RED=""; YELLOW=""; BOLD=""; NC=""
fi

PYTEST_BIN=""
for c in \
    "${REPO_ROOT}/venv/bin/pytest" \
    "$(command -v pytest || true)"
do
    if [[ -n "${c}" && -x "${c}" ]]; then PYTEST_BIN="${c}"; break; fi
done
if [[ -z "${PYTEST_BIN}" ]]; then
    printf '%b[FAIL]%b pytest not found — activate the venv\n' \
        "${RED}" "${NC}" >&2
    exit 2
fi

log="$(mktemp -t n3-auth-XXXX.log)"
trap 'rm -f "${log}"' EXIT

[[ ${QUIET} -eq 0 ]] && \
    printf '%b== Running N3 nginx auth matrix ==%b\n' "${BOLD}" "${NC}"

ec=0
"${PYTEST_BIN}" tests/test_nginx_auth.py -v --tb=line > "${log}" 2>&1 || ec=$?

[[ ${QUIET} -eq 0 ]] && cat "${log}"

group_counts() {
    local letter="$1"
    local passed failed skipped
    passed=$(grep -cE "test_N${letter}[0-9].*PASSED" "${log}" || true)
    failed=$(grep -cE "test_N${letter}[0-9].*FAILED" "${log}" || true)
    skipped=$(grep -cE "test_N${letter}[0-9].*SKIPPED" "${log}" || true)
    printf "  Group %s  pass=%s  fail=%s  skip=%s\n" \
        "${letter}" "${passed}" "${failed}" "${skipped}"
}

tot_pass=$(grep -cE "PASSED" "${log}" || true)
tot_fail=$(grep -cE "FAILED" "${log}" || true)
tot_skip=$(grep -cE "SKIPPED" "${log}" || true)

printf '\n%b-- N3 nginx auth matrix summary --%b\n' "${BOLD}" "${NC}"
for L in A B C D E F; do group_counts "${L}"; done
printf '  ---\n'
printf '  total: %bpass=%s%b  %bfail=%s%b  %bskip=%s%b\n' \
    "${GREEN}" "${tot_pass}" "${NC}" \
    "${RED}"   "${tot_fail}" "${NC}" \
    "${YELLOW}" "${tot_skip}" "${NC}"

# Explicit ND1 check per N3 exit criteria — make sure the *critical* test
# didn't silently get skipped.
nd1=$(grep -E "test_ND1_.*PASSED" "${log}" || true)
if [[ -z "${nd1}" ]]; then
    printf '%b[FAIL]%b ND1 did not pass — the nginx integration is insecure.\n' \
        "${RED}" "${NC}" >&2
    exit 1
fi

if [[ ${ec} -ne 0 ]]; then
    printf '%b[FAIL]%b pytest exit %d — see output above\n' \
        "${RED}" "${NC}" "${ec}" >&2
    exit 1
fi

printf '%b[PASS]%b N3 matrix: all attack assertions held\n' "${GREEN}" "${NC}"
exit 0
