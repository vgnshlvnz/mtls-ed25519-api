"""Performance baselines via pytest-benchmark (T4 Part 1).

Five benchmarks, every one marked ``@pytest.mark.performance`` so the
default ``make test-all`` run does NOT trigger them. Run explicitly:

    pytest -m performance
    make bench

Benchmark results land in ``.benchmarks/`` — commit the JSON to let
later phases use ``pytest --benchmark-compare`` to fail CI on a
regression larger than 20%.

Baselines (documented in docs/performance_baselines.md):

    PB1  mTLS handshake + GET /health (no session reuse) ........ median < 50ms
    PB2  GET /data (shared session, no handshake) .............. median < 10ms
    PB3  POST /data with a ~1KB body ........................... median < 15ms
    PB4  extract_cn() x 10 000 ................................. total  < 100ms
    PB5  subject_fingerprint() x 10 000 ........................ total  < 100ms

The PBx ceilings are guardrails, not tight limits — they exist to
catch order-of-magnitude regressions without being flaky on slow
CI boxes. Tighten them as confidence grows.
"""

from __future__ import annotations

import ssl
from pathlib import Path

import pytest
import requests

from middleware import extract_cn, subject_fingerprint


pytestmark = pytest.mark.performance


# Round / warmup counts picked to keep a full bench under a minute
# while giving pytest-benchmark enough samples to produce a stable
# median. T4 plan mandated 100 rounds + 5 warmup.
_ROUNDS = 100
_WARMUP = 5


# --- Helpers ----------------------------------------------------------------


def _mtls_session(pki_paths: dict[str, Path]) -> requests.Session:
    sess = requests.Session()
    sess.verify = str(pki_paths["ca_cert"])
    sess.cert = (
        str(pki_paths["client_cert"]),
        str(pki_paths["client_key"]),
    )
    return sess


def _mock_peer_cert(cn: str) -> dict:
    """Reuse the same mock shape unit tests use, locally."""
    return {
        "subject": (
            (("commonName", cn),),
            (("organizationName", "Lab"),),
            (("countryName", "MY"),),
        ),
        "issuer": ((("commonName", "mTLS-CA"),),),
    }


# --- PB1: handshake + /health -----------------------------------------------


def test_PB1_handshake_and_health_median_under_50ms(
    benchmark,
    pki_paths: dict[str, Path],
    server_process: dict[str, object],
) -> None:
    """PB1. Fresh mTLS handshake + GET /health per iteration.

    We build a brand-new ``requests.Session`` every iteration so the
    measured time includes the TLS handshake, not just the HTTP round
    trip. This is the upper bound on per-connection latency clients
    should see on first contact.
    """
    base_url = str(server_process["base_url"])
    ca = str(pki_paths["ca_cert"])
    cert_pair = (
        str(pki_paths["client_cert"]),
        str(pki_paths["client_key"]),
    )

    def _one_handshake_and_request() -> int:
        with requests.Session() as s:
            s.verify = ca
            s.cert = cert_pair
            return s.get(f"{base_url}/health", timeout=5).status_code

    result = benchmark.pedantic(
        _one_handshake_and_request,
        rounds=_ROUNDS,
        warmup_rounds=_WARMUP,
        iterations=1,
    )
    assert result == 200
    assert (
        benchmark.stats.stats.median < 0.050
    ), f"PB1 median {benchmark.stats.stats.median * 1000:.1f}ms exceeds 50ms ceiling"


# --- PB2: /data with session reuse -----------------------------------------


def test_PB2_get_data_session_reuse_median_under_10ms(
    benchmark,
    pki_paths: dict[str, Path],
    server_process: dict[str, object],
) -> None:
    """PB2. GET /data over an already-established connection.

    The connection is set up once BEFORE the benchmark loop starts
    (via a warmup call) so the measurement reflects HTTP processing
    only — no handshake, no DNS lookup, no keepalive negotiation.
    """
    base_url = str(server_process["base_url"])
    sess = _mtls_session(pki_paths)
    # Prime the connection pool with a throwaway call so the TLS
    # handshake cost isn't attributed to the first benchmark round.
    sess.get(f"{base_url}/health", timeout=5)

    def _get_data() -> int:
        return sess.get(f"{base_url}/data", timeout=5).status_code

    try:
        result = benchmark.pedantic(
            _get_data,
            rounds=_ROUNDS,
            warmup_rounds=_WARMUP,
            iterations=1,
        )
        assert result == 200
        assert (
            benchmark.stats.stats.median < 0.010
        ), f"PB2 median {benchmark.stats.stats.median * 1000:.1f}ms exceeds 10ms ceiling"
    finally:
        sess.close()


# --- PB3: POST /data with 1KB body -----------------------------------------


def test_PB3_post_data_1kb_body_median_under_15ms(
    benchmark,
    pki_paths: dict[str, Path],
    server_process: dict[str, object],
) -> None:
    """PB3. POST /data with a ~1KB JSON body (session reuse).

    ``sensor_id`` is padded to keep the serialised body near 1KB so
    regressions in body parsing (Pydantic validation, JSON decode)
    show up rather than being lost in the fixed overhead.
    """
    base_url = str(server_process["base_url"])
    sess = _mtls_session(pki_paths)
    sess.get(f"{base_url}/health", timeout=5)  # warm up

    # Build a body that serialises to ~1024 bytes. The padding is
    # what drives the size — sensor_id content doesn't matter to
    # validation (it is a non-empty string).
    payload = {
        "sensor_id": "s" + "x" * 900,
        "value": 42.0,
        "unit": "C",
    }

    def _post_data() -> int:
        return sess.post(f"{base_url}/data", json=payload, timeout=5).status_code

    try:
        result = benchmark.pedantic(
            _post_data,
            rounds=_ROUNDS,
            warmup_rounds=_WARMUP,
            iterations=1,
        )
        assert result == 200
        assert (
            benchmark.stats.stats.median < 0.015
        ), f"PB3 median {benchmark.stats.stats.median * 1000:.1f}ms exceeds 15ms ceiling"
    finally:
        sess.close()


# --- PB4 / PB5: CPU-only helpers (no server) --------------------------------


def test_PB4_extract_cn_10k_calls_under_100ms(benchmark) -> None:
    """PB4. 10 000 ``extract_cn`` calls must finish in < 100ms total.

    Pure-function hot path — this asserts the helper stays cheap
    (small constant per call) and doesn't silently start doing I/O
    or regex compilation on each call.
    """
    cert = _mock_peer_cert("client-01")

    def _call_10k() -> str:
        last: str | None = None
        for _ in range(10_000):
            last = extract_cn(cert)
        assert last == "client-01"
        return last

    result = benchmark.pedantic(
        _call_10k,
        rounds=_ROUNDS,
        warmup_rounds=_WARMUP,
        iterations=1,
    )
    assert result == "client-01"
    assert (
        benchmark.stats.stats.median < 0.100
    ), f"PB4 median {benchmark.stats.stats.median * 1000:.1f}ms exceeds 100ms ceiling"


def test_PB5_subject_fingerprint_10k_calls_under_100ms(benchmark) -> None:
    """PB5. 10 000 ``subject_fingerprint`` calls must finish in < 100ms.

    Same rationale as PB4. Also guards against "oh let me salt the
    hash with uuid4()" drift, which would both break determinism
    (guarded by test_subject_fingerprint_1000_iterations_are_invariant)
    and slow each call by a non-trivial amount.
    """
    cert = _mock_peer_cert("client-01")

    def _call_10k() -> str:
        last = ""
        for _ in range(10_000):
            last = subject_fingerprint(cert)
        return last

    result = benchmark.pedantic(
        _call_10k,
        rounds=_ROUNDS,
        warmup_rounds=_WARMUP,
        iterations=1,
    )
    assert isinstance(result, str) and len(result) == 16
    assert (
        benchmark.stats.stats.median < 0.100
    ), f"PB5 median {benchmark.stats.stats.median * 1000:.1f}ms exceeds 100ms ceiling"


# --- Sanity: every benchmark exercises the real ssl path --------------------


def test_PB_sanity_ssl_is_available() -> None:
    """Guards against a test run on a Python built without ssl."""
    assert hasattr(ssl, "SSLContext"), "TLS benchmarks need the ssl module"
