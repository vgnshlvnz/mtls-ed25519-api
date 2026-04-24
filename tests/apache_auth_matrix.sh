#!/usr/bin/env bash
# apache_auth_matrix.sh — wrapper that runs the Apache pytest suite
# (tests/test_apache_auth.py) and prints a per-group PASS/FAIL table.
#
# Mirrors the v1.0/v1.1 curl-style matrix scripts but runs against
# the v1.3 Apache integration. Group F is explicitly labelled as
# "Apache-specific (no nginx equivalent)" so the table lines up with
# the architectural narrative.
#
# Usage:
#     bash tests/apache_auth_matrix.sh
#     bash tests/apache_auth_matrix.sh --quiet   # suppress per-test output

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

QUIET=0
[[ "${1:-}" == "--quiet" ]] && QUIET=1

cd "${REPO_ROOT}"

# Run pytest, capture per-group counts from the JSON report. We use
# pytest's exit code as the truth source; the table is informational
# but matches what pytest saw.
PYTEST_EXTRA=()
[[ ${QUIET} -eq 1 ]] && PYTEST_EXTRA+=("-q") || PYTEST_EXTRA+=("-v")

LOG_FILE="$(mktemp)"
set +e
venv/bin/python -m pytest \
    tests/test_apache_auth.py \
    --tb=short \
    "${PYTEST_EXTRA[@]}" \
    > "${LOG_FILE}" 2>&1
PYTEST_RC=$?
set -e

# Direct grep approach using the test name prefix (a*, b*, c*, …).
# Uses grep -c (not grep | wc -l) to avoid the SC2126 shellcheck nag.
count_outcome() {
    local prefix="$1" outcome="$2"
    grep -cE "tests/test_apache_auth\.py::Test[A-Z]*::test_${prefix}[0-9].* ${outcome}" \
        "${LOG_FILE}" 2>/dev/null || echo 0
}

a_pass=$(count_outcome "aa" "PASSED")
a_fail=$(count_outcome "aa" "FAILED")
b_pass=$(count_outcome "ab" "PASSED")
b_fail=$(count_outcome "ab" "FAILED")
c_pass=$(count_outcome "ac" "PASSED")
c_fail=$(count_outcome "ac" "FAILED")
d_pass=$(count_outcome "ad" "PASSED")
d_fail=$(count_outcome "ad" "FAILED")
e_pass=$(count_outcome "ae" "PASSED")
e_fail=$(count_outcome "ae" "FAILED")
f_pass=$(count_outcome "af" "PASSED")
f_fail=$(count_outcome "af" "FAILED")
f_skip=$(count_outcome "af" "SKIPPED")

total_pass=$(grep -cE ' PASSED ' "${LOG_FILE}" 2>/dev/null || echo 0)
total_fail=$(grep -cE ' FAILED ' "${LOG_FILE}" 2>/dev/null || echo 0)
total_skip=$(grep -cE ' SKIPPED ' "${LOG_FILE}" 2>/dev/null || echo 0)

# Print table.
printf '\n=== Apache auth matrix (v1.3) ===\n\n'
printf '%-50s %6s %6s %6s\n' 'Group' 'PASS' 'FAIL' 'SKIP'
printf '%s\n' '-----------------------------------------------------------------------'
printf '%-50s %6s %6s %6s\n' 'A — happy path'                                            "${a_pass}" "${a_fail}" "0"
printf '%-50s %6s %6s %6s\n' 'B — TLS / HTTP rejection'                                  "${b_pass}" "${b_fail}" "0"
printf '%-50s %6s %6s %6s\n' 'C — RewriteMap CN allowlist (log-absence)'                 "${c_pass}" "${c_fail}" "0"
printf '%-50s %6s %6s %6s\n' 'D — information disclosure'                                "${d_pass}" "${d_fail}" "0"
printf '%-50s %6s %6s %6s\n' 'E — concurrency'                                           "${e_pass}" "${e_fail}" "0"
printf '%-50s %6s %6s %6s\n' 'F — Apache-specific (no nginx equivalent)'                 "${f_pass}" "${f_fail}" "${f_skip}"
printf '%s\n' '-----------------------------------------------------------------------'
printf '%-50s %6s %6s %6s\n' 'TOTAL'                                                     "${total_pass}" "${total_fail}" "${total_skip}"
printf '\n'

if [[ ${PYTEST_RC} -eq 0 ]]; then
    printf '[PASS] all Apache auth tests green (rc=0)\n'
else
    printf '[FAIL] pytest exit code: %d\n' "${PYTEST_RC}"
    if [[ ${QUIET} -eq 1 ]]; then
        printf '\n--- last 30 lines of pytest output ---\n'
        tail -30 "${LOG_FILE}"
    fi
fi

rm -f "${LOG_FILE}"
exit "${PYTEST_RC}"
