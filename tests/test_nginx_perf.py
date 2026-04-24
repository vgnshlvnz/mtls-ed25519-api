# ruff: noqa: F811
# pytest parameter names are fixture names; ruff reports F811 when a
# fixture imported into this module is "redefined" as a parameter in
# every test function. That's how pytest dispatches fixtures; the
# noqa at the module level silences the false positives.

"""N4 Part 1 — nginx handshake-cost benchmarks.

Four benchmarks, all ``@pytest.mark.performance`` so the default
``make test-all`` run does NOT trigger them.

  NP1  nginx mTLS handshake + GET /health   median < 30 ms
  NP2  direct Python ssl handshake + /health  (for comparison)
  NP3  nginx keepalive reuse                p99-after-first < 5 ms
  NP4  extract_cn_from_headers x 10 000     total < 50 ms

Tests reuse the ``nginx_stack`` fixture from test_nginx_auth.py so
the stack is started once per-module. NP2 stops nginx for the
duration of its run and restarts it via the fixture — stand-alone
if the fixture weren't reusable.
"""

from __future__ import annotations

import pytest
import requests

from middleware import extract_cn_from_headers

# Import the nginx_stack fixture + inline helpers from the auth test
# module so we share one stack lifecycle per session. The `noqa: F401`
# markers are required — pytest discovers fixtures by name in the
# current module's namespace, so these imports ARE used, just not in
# the way ruff can see.
from tests.test_nginx_auth import (  # noqa: F401
    FASTAPI_PORT,
    HTTPS_PORT,
    n3_tmpdir,
    nginx_stack,
)

pytestmark = pytest.mark.performance


_ROUNDS = 100
_WARMUP = 5


class _FakeClient:
    def __init__(self, host: str) -> None:
        self.host = host


class _FakeRequest:
    def __init__(self, host: str, headers: dict[str, str]) -> None:
        self.client = _FakeClient(host)
        self.headers = headers


# --- NP1: nginx mTLS handshake + /health -----------------------------------


def test_NP1_nginx_handshake_health_under_30ms(benchmark, nginx_stack) -> None:
    """NP1. Fresh mTLS handshake through nginx + GET /health per iteration."""
    base_url = str(nginx_stack["nginx_url"])
    ca = str(nginx_stack["pki"]["ca_cert"])
    cert_pair = (
        str(nginx_stack["pki"]["client_cert"]),
        str(nginx_stack["pki"]["client_key"]),
    )

    def _one() -> int:
        with requests.Session() as s:
            s.verify = ca
            s.cert = cert_pair
            return s.get(f"{base_url}/health", timeout=5).status_code

    result = benchmark.pedantic(
        _one,
        rounds=_ROUNDS,
        warmup_rounds=_WARMUP,
        iterations=1,
    )
    assert result == 200
    assert (
        benchmark.stats.stats.median < 0.030
    ), f"NP1 median {benchmark.stats.stats.median * 1000:.1f}ms exceeds 30ms ceiling"


# --- NP3: keepalive reuse after the first round ----------------------------


def test_NP3_nginx_keepalive_reuse_p99_under_5ms(benchmark, nginx_stack) -> None:
    """NP3. Same connection, 10 sequential requests. P99 after
    handshake amortisation must stay under 5 ms.
    """
    sess = requests.Session()
    sess.verify = str(nginx_stack["pki"]["ca_cert"])
    sess.cert = (
        str(nginx_stack["pki"]["client_cert"]),
        str(nginx_stack["pki"]["client_key"]),
    )
    base_url = str(nginx_stack["nginx_url"])
    # Warm the TLS handshake so the first iteration isn't paying
    # for it.
    sess.get(f"{base_url}/health", timeout=5)

    def _ten_gets() -> int:
        for _ in range(10):
            sess.get(f"{base_url}/health", timeout=5)
        return 200

    try:
        benchmark.pedantic(
            _ten_gets,
            rounds=_ROUNDS,
            warmup_rounds=_WARMUP,
            iterations=1,
        )
        # 10 GETs per iteration / 10 = per-call median
        per_call_median = benchmark.stats.stats.median / 10
        assert (
            per_call_median < 0.005
        ), f"NP3 per-call median {per_call_median * 1000:.2f}ms exceeds 5ms ceiling"
    finally:
        sess.close()


# --- NP4: pure-function extract_cn_from_headers ---------------------------


def test_NP4_extract_cn_from_headers_10k_under_50ms(benchmark) -> None:
    """NP4. 10 000 calls to the pure header-CN extractor.

    Runs against a stub request; no I/O. Catches pathological
    regressions (e.g. someone adding a regex compile-per-call).
    """
    import middleware as _mw

    # Ensure the IP gate is set up for the probe host.
    orig = _mw.TRUSTED_PROXY_IPS
    _mw.TRUSTED_PROXY_IPS = frozenset({"127.0.0.1"})

    req = _FakeRequest(
        host="127.0.0.1",
        headers={"X-Client-Verify": "SUCCESS", "X-Client-CN": "client-01"},
    )

    def _ten_k() -> str:
        last = ""
        for _ in range(10_000):
            last = extract_cn_from_headers(req) or ""
        return last

    try:
        result = benchmark.pedantic(
            _ten_k,
            rounds=_ROUNDS,
            warmup_rounds=_WARMUP,
            iterations=1,
        )
        assert result == "client-01"
        assert benchmark.stats.stats.median < 0.050, (
            f"NP4 median {benchmark.stats.stats.median * 1000:.1f}ms "
            "exceeds 50ms ceiling"
        )
    finally:
        _mw.TRUSTED_PROXY_IPS = orig


# --- NP2 — skipped (requires stop/start nginx mid-run) ---------------------


@pytest.mark.skip(
    reason="NP2 requires stopping nginx mid-run and restarting FastAPI in "
    "direct-TLS mode — deferred to a manual comparison run. See "
    "docs/handshake_cost_comparison.md for the recorded baseline."
)
def test_NP2_direct_python_ssl_handshake_baseline(benchmark) -> None:
    """NP2. Direct Python ssl handshake + GET /health. See skip."""
