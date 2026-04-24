"""Long-running stability test (T4 Part 4).

Single test, ``@pytest.mark.slow``. 1000 sequential requests over
~60s with a 60ms sleep between. Records:

* zero 5xx responses
* zero connection errors
* server-process RSS growth below 50 MiB (via ``psutil``)
* p99 latency does not degrade (first 100 vs last 100)

The memory and latency checks are approximations — the 50 MiB
budget and "p99 of last 100 ≤ 3x p99 of first 100" ratio are
picked to flag order-of-magnitude regressions without being flaky
on slow CI boxes.
"""

from __future__ import annotations

import statistics
import subprocess
import time
from pathlib import Path

import psutil
import pytest
import requests


# The single test below runs ~60s (1000 calls, 60ms between). Override
# the default pytest.ini timeout (30s) so it actually finishes.
pytestmark = [
    pytest.mark.slow,
    pytest.mark.integration,
    pytest.mark.timeout(180),
]


_REQUESTS = 1000
_DELAY_S = 0.060  # ~60ms between calls, ~60s total
_MEMORY_BUDGET_BYTES = 50 * 1024 * 1024  # 50 MiB
_LATENCY_DEGRADATION_FACTOR = 3.0


def test_ST1_1000_sequential_requests_stable_memory_and_latency(
    pki_paths: dict[str, Path],
    server_process: dict[str, object],
) -> None:
    """ST1. 1000 sequential GET /health calls.

    Asserts four invariants, any one of which failing indicates a
    regression:

    1. Every response is < 500 (no server error).
    2. No connection / TLS / socket exception is raised on any call.
    3. Server RSS grows by less than 50 MiB across the run.
    4. p99 of the LAST 100 calls is not more than 3x the p99 of the
       FIRST 100 calls — i.e. steady-state latency does not creep.

    The psutil reading is an approximation: kernel paging, glibc
    arena fragmentation, and Python GC all inject noise. The 50 MiB
    ceiling exists to catch an unbounded cache or fd leak, not a
    micro-regression of a few hundred KB.
    """
    base_url = str(server_process["base_url"])
    server_proc: subprocess.Popen = server_process["process"]  # type: ignore[assignment]
    server_pid = server_proc.pid

    ps = psutil.Process(server_pid)

    sess = requests.Session()
    sess.verify = str(pki_paths["ca_cert"])
    sess.cert = (
        str(pki_paths["client_cert"]),
        str(pki_paths["client_key"]),
    )
    # Prime the TLS handshake so the first real call's latency
    # reflects steady-state behaviour, not handshake overhead.
    assert sess.get(f"{base_url}/health", timeout=5).status_code == 200

    rss_before = ps.memory_info().rss

    latencies: list[float] = []
    statuses: list[int] = []
    errors: list[str] = []
    try:
        for i in range(_REQUESTS):
            started = time.perf_counter()
            try:
                r = sess.get(f"{base_url}/health", timeout=5)
                latencies.append(time.perf_counter() - started)
                statuses.append(r.status_code)
            except requests.RequestException as exc:
                errors.append(f"[{i}] {type(exc).__name__}: {exc}")
                statuses.append(-1)
                latencies.append(time.perf_counter() - started)
            time.sleep(_DELAY_S)
    finally:
        sess.close()

    rss_after = ps.memory_info().rss
    rss_growth = rss_after - rss_before

    # --- Invariants ---------------------------------------------------------
    assert (
        errors == []
    ), f"ST1: connection errors ({len(errors)}): first 5 = {errors[:5]}"
    status_5xx = [s for s in statuses if s >= 500]
    assert status_5xx == [], f"ST1: got {len(status_5xx)} 5xx responses"

    assert rss_growth < _MEMORY_BUDGET_BYTES, (
        f"ST1: server RSS grew {rss_growth / 1_048_576:.1f} MiB "
        f"(budget {_MEMORY_BUDGET_BYTES / 1_048_576:.0f} MiB); leak suspected"
    )

    first_100 = latencies[:100]
    last_100 = latencies[-100:]
    first_p99 = statistics.quantiles(first_100, n=100)[98]
    last_p99 = statistics.quantiles(last_100, n=100)[98]
    assert last_p99 <= first_p99 * _LATENCY_DEGRADATION_FACTOR, (
        f"ST1: p99 degraded — first {first_p99 * 1000:.1f}ms → "
        f"last {last_p99 * 1000:.1f}ms (factor "
        f"{last_p99 / max(first_p99, 1e-9):.2f}x, budget "
        f"{_LATENCY_DEGRADATION_FACTOR:.1f}x)"
    )
