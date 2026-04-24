"""Concurrency stress tests (T4 Part 3).

Five scenarios (CS1..CS5), every one marked ``@pytest.mark.slow`` so
they run via ``pytest -m slow`` or ``make stress``, not during the
default ``make test-all``.

The point of these tests is not raw throughput — that's covered by
locust (Part 2) and pytest-benchmark (Part 1). These tests exercise
CORRECTNESS under concurrency: a race condition in the identity
middleware or a leaked request.state attribute would corrupt the
expected (200 / SSLError / 403) counts in CS3, and the thundering
herd in CS5 would expose any subtle handshake serialisation.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import ssl
import time
from pathlib import Path

import httpx
import pytest
import requests


pytestmark = [pytest.mark.slow, pytest.mark.integration]


def _ssl_context(ca: Path, cert: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH,
        cafile=str(ca),
    )
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    return ctx


# --- CS1: 100 concurrent valid clients with a fresh handshake each ---------


def test_CS1_100_fresh_handshakes_all_succeed_under_15s(
    pki_paths: dict[str, Path],
    server_process: dict[str, object],
) -> None:
    """CS1. 100 unique ``requests.Session`` instances, one per thread.

    No connection reuse anywhere — every worker performs a full TLS
    handshake + HTTP request + close. Measures whether the server
    can sustain a fan-in without serialising handshakes.
    """
    base_url = str(server_process["base_url"])
    ca = str(pki_paths["ca_cert"])
    cert_pair = (
        str(pki_paths["client_cert"]),
        str(pki_paths["client_key"]),
    )

    def _one_client() -> int:
        with requests.Session() as sess:
            sess.verify = ca
            sess.cert = cert_pair
            return sess.get(f"{base_url}/health", timeout=10).status_code

    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        futures = [ex.submit(_one_client) for _ in range(100)]
        results = [f.result(timeout=15.0) for f in futures]
    elapsed = time.perf_counter() - started

    assert all(
        code == 200 for code in results
    ), f"CS1: not all 100 succeeded — {results.count(200)}/100 ok"
    assert elapsed < 15.0, f"CS1 wall-clock {elapsed:.1f}s exceeds 15s budget"


# --- CS2: 50 concurrent requests on one shared session ---------------------


def test_CS2_50_shared_session_requests_under_5s(
    pki_paths: dict[str, Path],
    server_process: dict[str, object],
) -> None:
    """CS2. One ``requests.Session`` shared across 50 threads.

    Tests the connection pool (`HTTPAdapter`) under contention. A
    bug that serialises pool access would blow past the 5s budget;
    a TLS-session-ticket race would yield non-200 responses.
    """
    base_url = str(server_process["base_url"])
    sess = requests.Session()
    sess.verify = str(pki_paths["ca_cert"])
    sess.cert = (
        str(pki_paths["client_cert"]),
        str(pki_paths["client_key"]),
    )
    # Bump the adapter pool so all 50 threads can hold a connection
    # at once; the default (10) would serialise 40 of them.
    adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50)
    sess.mount("https://", adapter)

    try:
        # Prime the TLS handshake once.
        assert sess.get(f"{base_url}/health", timeout=5).status_code == 200

        def _one_call() -> int:
            return sess.get(f"{base_url}/health", timeout=5).status_code

        started = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
            futures = [ex.submit(_one_call) for _ in range(50)]
            results = [f.result(timeout=5.0) for f in futures]
        elapsed = time.perf_counter() - started
    finally:
        sess.close()

    assert all(
        code == 200 for code in results
    ), f"CS2: {results.count(200)}/50 ok, others: {[c for c in results if c != 200]}"
    assert elapsed < 5.0, f"CS2 wall-clock {elapsed:.1f}s exceeds 5s budget"


# --- CS3: mixed fleet — 20 valid + 10 no-cert + 10 wrong-CN ---------------


def test_CS3_mixed_fleet_preserves_outcome_classes(
    pki_paths: dict[str, Path],
    server_process: dict[str, object],
    wrong_cn_leaf: dict[str, Path],
) -> None:
    """CS3. Critical race-condition guard.

    Three cohorts hammer the server concurrently:
      - 20 valid clients     → expect 200
      - 10 no-cert clients   → expect TLS-layer SSLError
      - 10 wrong-CN clients  → expect app-layer 403

    The middleware attaches ``client_cn`` to ``request.state``. If
    any per-request state is accidentally shared (class attr,
    module global) the 200/403 counts will drift. The TLS-layer
    failure count must also stay exact — a lax server would let
    some no-cert clients through.
    """
    base_url = str(server_process["base_url"])
    ca = pki_paths["ca_cert"]
    valid_cert = pki_paths["client_cert"]
    valid_key = pki_paths["client_key"]
    wrong_cert = wrong_cn_leaf["cert"]
    wrong_key = wrong_cn_leaf["key"]

    def _valid() -> tuple[str, int | str]:
        with requests.Session() as s:
            s.verify = str(ca)
            s.cert = (str(valid_cert), str(valid_key))
            r = s.get(f"{base_url}/health", timeout=10)
            return ("valid", r.status_code)

    def _no_cert() -> tuple[str, int | str]:
        # httpx with a context that has NO client cert chain.
        # SECURITY: the context STILL verifies the server against our
        # CA — we are only omitting OUR identity, not disabling
        # verification.
        ctx = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH,
            cafile=str(ca),
        )
        try:
            with httpx.Client(verify=ctx, timeout=10.0) as c:
                c.get(f"{base_url}/health")
        except (
            httpx.ConnectError,
            httpx.RemoteProtocolError,
            httpx.ReadError,
            ssl.SSLError,
        ) as exc:
            # All acceptable outcomes when the server hangs up on us
            # at the handshake because we never presented a client
            # cert. httpx maps the low-level disconnect to one of
            # these depending on exactly when the TCP reset arrives.
            return ("no_cert", type(exc).__name__)
        return ("no_cert", "unexpected_success")

    def _wrong_cn() -> tuple[str, int | str]:
        with requests.Session() as s:
            s.verify = str(ca)
            s.cert = (str(wrong_cert), str(wrong_key))
            r = s.get(f"{base_url}/health", timeout=10)
            return ("wrong_cn", r.status_code)

    workload = [_valid] * 20 + [_no_cert] * 10 + [_wrong_cn] * 10

    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
        futures = [ex.submit(fn) for fn in workload]
        results = [f.result(timeout=20.0) for f in futures]

    valid_ok = sum(1 for kind, code in results if kind == "valid" and code == 200)
    wrong_cn_denied = sum(
        1 for kind, code in results if kind == "wrong_cn" and code == 403
    )
    no_cert_rejected = sum(
        1
        for kind, code in results
        if kind == "no_cert" and isinstance(code, str) and code != "unexpected_success"
    )

    assert valid_ok == 20, f"CS3: {valid_ok}/20 valid clients got 200; got {results}"
    assert (
        wrong_cn_denied == 10
    ), f"CS3: {wrong_cn_denied}/10 wrong-CN clients got 403; got {results}"
    assert (
        no_cert_rejected == 10
    ), f"CS3: {no_cert_rejected}/10 no-cert clients rejected at TLS; got {results}"


# --- CS4: burst of 200 connections, then a probe must still answer ---------


def test_CS4_200_burst_then_single_request_under_2s(
    pki_paths: dict[str, Path],
    server_process: dict[str, object],
) -> None:
    """CS4. Fire 200 concurrent connections, then probe with one
    legitimate request. The probe must return in < 2s.

    A burst followed by a low-traffic probe catches two failure modes:
    (a) the server failed to reclaim FDs/contexts after the spike, so
    the probe hits an exhausted queue; (b) the server logs or locks
    became contended, preventing prompt handling.
    """
    base_url = str(server_process["base_url"])
    ca = str(pki_paths["ca_cert"])
    cert_pair = (
        str(pki_paths["client_cert"]),
        str(pki_paths["client_key"]),
    )

    def _burst_one() -> int:
        with requests.Session() as s:
            s.verify = ca
            s.cert = cert_pair
            try:
                return s.get(f"{base_url}/health", timeout=15).status_code
            except requests.RequestException:
                return 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as ex:
        futures = [ex.submit(_burst_one) for _ in range(200)]
        # Wait for the burst to finish.
        burst_results = [f.result(timeout=30.0) for f in futures]

    # Not every burst request needs to succeed — the system is
    # legitimately overloaded here. We only assert that the POST-
    # burst probe is served quickly, which is the real SLO.
    burst_ok = sum(1 for code in burst_results if code == 200)
    assert (
        burst_ok >= 150
    ), f"CS4: only {burst_ok}/200 burst requests succeeded; server may be stuck"

    started = time.perf_counter()
    with requests.Session() as probe:
        probe.verify = ca
        probe.cert = cert_pair
        r = probe.get(f"{base_url}/health", timeout=5)
    elapsed = time.perf_counter() - started

    assert r.status_code == 200
    assert elapsed < 2.0, (
        f"CS4: post-burst probe took {elapsed:.2f}s (budget 2s); "
        f"server did not reclaim fast enough"
    )


# --- CS5: thundering herd via asyncio.Barrier ------------------------------


async def test_CS5_thundering_herd_50_clients_complete_under_10s(
    pki_paths: dict[str, Path],
    server_process: dict[str, object],
) -> None:
    """CS5. 50 clients release simultaneously via ``asyncio.Barrier``.

    Unlike CS1 (which staggers by thread-pool scheduling), this test
    releases all 50 clients at the SAME await point. Exposes race
    conditions that only manifest under genuinely simultaneous
    starts — e.g. a lazy-initialised SSLContext being built twice
    on the first concurrent call.
    """
    base_url = str(server_process["base_url"])
    ctx = _ssl_context(
        pki_paths["ca_cert"],
        pki_paths["client_cert"],
        pki_paths["client_key"],
    )

    n_clients = 50
    barrier = asyncio.Barrier(n_clients)

    async def _client(client_id: int) -> int:
        async with httpx.AsyncClient(
            base_url=base_url,
            verify=ctx,
            timeout=10.0,
        ) as c:
            # Hold here until all 50 coroutines are ready.
            await barrier.wait()
            r = await c.get("/health")
            return r.status_code

    started = time.perf_counter()
    results = await asyncio.wait_for(
        asyncio.gather(*(_client(i) for i in range(n_clients))),
        timeout=10.0,
    )
    elapsed = time.perf_counter() - started

    assert all(code == 200 for code in results), (
        f"CS5: {results.count(200)}/{n_clients} ok; server did not "
        f"tolerate a simultaneous herd"
    )
    assert elapsed < 10.0, f"CS5: wall-clock {elapsed:.1f}s exceeds 10s budget"
