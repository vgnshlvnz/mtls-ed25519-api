#!/usr/bin/env bash
# tls_attack_matrix.sh — run the T2 security tests and print a grouped
# PASS/FAIL table. A thin wrapper around `pytest -m security` that
# splits the results by Group (A..E) for human-readable output in CI
# or at the console.
#
# Usage:
#   ./tests/tls_attack_matrix.sh           # run the matrix, print a table
#   ./tests/tls_attack_matrix.sh --quiet   # print only the final table
#
# Exit codes:
#   0  all attack tests passed (B2 may skip cleanly)
#   1  one or more attack tests failed
#   2  pytest itself could not run (missing venv etc.)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

QUIET=0
if [[ "${1:-}" == "--quiet" ]]; then
    QUIET=1
fi

# --- Colour (only when writing to a TTY) -----------------------------------
if [[ -t 1 ]]; then
    GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'
    BOLD=$'\033[1m'; NC=$'\033[0m'
else
    GREEN=""; RED=""; YELLOW=""; BOLD=""; NC=""
fi

# --- Locate a pytest binary -------------------------------------------------
PYTEST_BIN=""
for candidate in \
    "${REPO_ROOT}/venv/bin/pytest" \
    "${REPO_ROOT}/.venv/bin/pytest" \
    "$(command -v pytest || true)"
do
    if [[ -n "${candidate}" && -x "${candidate}" ]]; then
        PYTEST_BIN="${candidate}"
        break
    fi
done

if [[ -z "${PYTEST_BIN}" ]]; then
    printf '%b[FAIL]%b pytest not found — activate the venv first\n' \
        "${RED}" "${NC}" >&2
    exit 2
fi

# --- Run the T2 matrix ------------------------------------------------------
results_file="$(mktemp -t tls-attack-XXXX.log)"
trap 'rm -f "${results_file}"' EXIT

if [[ ${QUIET} -eq 0 ]]; then
    printf '%b== Running T2 TLS attack matrix ==%b\n' "${BOLD}" "${NC}"
fi

pytest_ec=0
"${PYTEST_BIN}" -m security tests/test_tls_attacks.py -v --tb=line \
    > "${results_file}" 2>&1 || pytest_ec=$?

if [[ ${QUIET} -eq 0 ]]; then
    cat "${results_file}"
fi

# --- Group results by A..E prefix -------------------------------------------
count_pass=$(grep -cE "PASSED" "${results_file}" || true)
count_fail=$(grep -cE "FAILED" "${results_file}" || true)
count_skip=$(grep -cE "SKIPPED" "${results_file}" || true)

group_stat() {
    local letter="$1"
    local passed failed skipped
    passed=$(grep -cE "test_${letter}[0-9].*PASSED" "${results_file}" || true)
    failed=$(grep -cE "test_${letter}[0-9].*FAILED" "${results_file}" || true)
    skipped=$(grep -cE "test_${letter}[0-9].*SKIPPED" "${results_file}" || true)
    printf "  Group %s  pass=%s  fail=%s  skip=%s\n" \
        "${letter}" "${passed}" "${failed}" "${skipped}"
}

printf '\n%b-- T2 attack-matrix summary --%b\n' "${BOLD}" "${NC}"
group_stat A
group_stat B
group_stat C
group_stat D
group_stat E
printf '  ---\n'
printf '  total: %bpass=%s%b  %bfail=%s%b  %bskip=%s%b\n' \
    "${GREEN}" "${count_pass}" "${NC}" \
    "${RED}"   "${count_fail}" "${NC}" \
    "${YELLOW}" "${count_skip}" "${NC}"

if [[ ${pytest_ec} -ne 0 ]]; then
    printf '%b[FAIL]%b pytest returned %d — see output above\n' \
        "${RED}" "${NC}" "${pytest_ec}" >&2
    exit 1
fi

printf '%b[PASS]%b T2 matrix: all attack assertions held\n' "${GREEN}" "${NC}"
exit 0
