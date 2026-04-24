# ruff: noqa: F811
# pytest fixture parameters shadow names imported from other test
# modules — same reason as test_nginx_perf.py.

"""N4 Part 2 — nginx concurrency stress tests.

Four tests, all ``@pytest.mark.slow`` so the default run doesn't
trigger them:

  NC1  50 concurrent valid clients                all 200, <10s
  NC2  mixed fleet (20 valid + 10 no-cert + 10 wrong-CN) — NC3-equivalent
  NC3  40 connections beyond keepalive=32;        recovers <3s
  NC4  FastAPI restart with nginx alive;          nginx 502s in the gap,
                                                   recovers <5s

All tests run against the ``nginx_stack`` fixture from
test_nginx_auth.py (same stack lifecycle).
"""

from __future__ import annotations

import concurrent.futures
import ssl
import subprocess
import sys
import time

import httpx
import pytest
import requests

from tests.test_nginx_auth import (  # noqa: F401
    HTTPS_PORT,
    FASTAPI_PORT,
    REPO_ROOT,
    nginx_stack,
    n3_tmpdir,
    project_ca_mirror,
)


pytestmark = [pytest.mark.slow, pytest.mark.e2e]


# --- NC1: 50 valid clients -------------------------------------------------


def test_NC1_50_valid_clients_under_10s(nginx_stack) -> None:
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
            return s.get(f"{base_url}/health", timeout=10).status_code

    t0 = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        results = list(ex.map(lambda _: _one(), range(50)))
    elapsed = time.perf_counter() - t0

    assert all(
        r == 200 for r in results
    ), f"NC1: {results.count(200)}/50 ok; others: {[r for r in results if r != 200]}"
    assert elapsed < 10.0, f"NC1 wall-clock {elapsed:.1f}s > 10s"


# --- NC2: mixed fleet (critical — sibling of T4 CS3) -----------------------


def test_NC2_mixed_fleet_preserves_outcome_classes(
    nginx_stack, project_ca_mirror
) -> None:
    """NC2. 20 valid + 10 no-cert + 10 wrong-CN concurrently through
    nginx. Each cohort's outcome class must be preserved — no
    cross-contamination through the proxy.

    This is the nginx-path equivalent of the T4 CS3 test and carries
    the same importance: a race condition in the dual-mode middleware
    or the nginx→FastAPI forwarding would corrupt the counts.
    """
    base_url = str(nginx_stack["nginx_url"])
    ca = nginx_stack["pki"]["ca_cert"]
    valid_cert = nginx_stack["pki"]["client_cert"]
    valid_key = nginx_stack["pki"]["client_key"]

    # Sign a throwaway wrong-CN leaf.
    wrong_cn = project_ca_mirror.sign_client("nc2-rogue")

    def _valid() -> tuple[str, int | str]:
        with requests.Session() as s:
            s.verify = str(ca)
            s.cert = (str(valid_cert), str(valid_key))
            r = s.get(f"{base_url}/health", timeout=10)
            return ("valid", r.status_code)

    def _no_cert() -> tuple[str, int | str]:
        ctx = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH,
            cafile=str(ca),
        )
        try:
            with httpx.Client(verify=ctx, timeout=10.0) as c:
                r = c.get(f"{base_url}/health")
        except (
            httpx.ConnectError,
            httpx.RemoteProtocolError,
            httpx.ReadError,
            ssl.SSLError,
        ) as exc:
            return ("no_cert", type(exc).__name__)
        # nginx with `ssl_verify_client on` completes the TLS
        # handshake, then returns HTTP 400 ("No required SSL
        # certificate was sent") at the application layer. That's
        # a valid rejection — unlike the Python ssl path which
        # raises at handshake time.
        if r.status_code == 400:
            return ("no_cert", "nginx_400_no_cert")
        return ("no_cert", f"unexpected_status_{r.status_code}")

    def _wrong_cn() -> tuple[str, int | str]:
        with requests.Session() as s:
            s.verify = str(ca)
            s.cert = (str(wrong_cn.cert), str(wrong_cn.key))
            r = s.get(f"{base_url}/health", timeout=10)
            return ("wrong_cn", r.status_code)

    workload = [_valid] * 20 + [_no_cert] * 10 + [_wrong_cn] * 10

    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
        futures = [ex.submit(fn) for fn in workload]
        results = [f.result(timeout=20.0) for f in futures]

    valid_ok = sum(1 for k, c in results if k == "valid" and c == 200)
    wrong_denied = sum(1 for k, c in results if k == "wrong_cn" and c == 403)
    no_cert_rejected = sum(
        1
        for k, c in results
        if k == "no_cert" and isinstance(c, str) and not c.startswith("unexpected_")
    )

    assert valid_ok == 20, f"NC2: got {valid_ok}/20 valid; {results}"
    assert wrong_denied == 10, f"NC2: got {wrong_denied}/10 wrong-CN 403s"
    assert (
        no_cert_rejected == 10
    ), f"NC2: got {no_cert_rejected}/10 no-cert TLS rejections"


# --- NC3: beyond keepalive pool --------------------------------------------


def test_NC3_40_connections_beyond_keepalive_recover_under_3s(
    nginx_stack,
) -> None:
    """NC3. Fire 40 concurrent connections when upstream keepalive=32;
    verify a follow-up probe returns fast."""
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
            try:
                return s.get(f"{base_url}/health", timeout=15).status_code
            except requests.RequestException:
                return 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
        burst = list(ex.map(lambda _: _one(), range(40)))

    # Not every one MUST succeed (we're over the keepalive limit;
    # nginx may close a few) but the majority should.
    assert burst.count(200) >= 30, f"NC3: too many dropped: {burst.count(200)}/40"

    # Post-burst probe must recover quickly.
    t0 = time.perf_counter()
    with requests.Session() as s:
        s.verify = ca
        s.cert = cert_pair
        r = s.get(f"{base_url}/health", timeout=5)
    elapsed = time.perf_counter() - t0
    assert r.status_code == 200
    assert elapsed < 3.0, f"NC3 post-burst probe {elapsed:.2f}s > 3s"


# --- NC4: restart FastAPI with nginx alive ---------------------------------


def test_NC4_fastapi_restart_nginx_502s_then_recovers(
    nginx_stack,
) -> None:
    """NC4. Kill FastAPI while nginx is still running. Assert nginx
    returns 502 in the gap (not a silent hang), then FastAPI comes
    back within 5s and traffic resumes.
    """
    import os
    import signal as _signal

    base_url = str(nginx_stack["nginx_url"])
    ca = str(nginx_stack["pki"]["ca_cert"])
    cert_pair = (
        str(nginx_stack["pki"]["client_cert"]),
        str(nginx_stack["pki"]["client_key"]),
    )

    # Locate FastAPI PID via ss on the upstream port.
    out = subprocess.run(
        ["ss", "-tlnp"],
        capture_output=True,
        text=True,
        check=False,
    )
    api_pid = None
    for line in out.stdout.splitlines():
        if f":{FASTAPI_PORT}" in line and "python" in line:
            import re as _re

            m = _re.search(r"pid=(\d+)", line)
            if m:
                api_pid = int(m.group(1))
                break
    if api_pid is None:
        pytest.skip("could not resolve FastAPI pid")

    # Kill FastAPI.
    os.kill(api_pid, _signal.SIGKILL)
    time.sleep(0.3)

    # Within the gap, nginx should 502 (upstream unreachable).
    try:
        with requests.Session() as s:
            s.verify = ca
            s.cert = cert_pair
            r = s.get(f"{base_url}/health", timeout=5)
    except requests.exceptions.RequestException:
        # Some nginx versions send 502 immediately; others drop the
        # connection. Either is acceptable — not a silent hang.
        r = None
    if r is not None:
        assert r.status_code in (
            502,
            503,
            504,
        ), f"NC4: expected 5xx in the gap, got {r.status_code}"

    # Restart FastAPI.
    env = os.environ.copy()
    env.update(
        MTLS_API_PORT=str(FASTAPI_PORT),
        NGINX_MODE="true",
        TRUSTED_PROXY_IPS="127.0.0.1",
    )
    api_log = REPO_ROOT / f".server-test-{FASTAPI_PORT}.log"
    # Fire-and-forget: the replacement API is cleaned up by the
    # nginx_stack fixture teardown (pkill).
    subprocess.Popen(
        [sys.executable, str(REPO_ROOT / "server.py")],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=api_log.open("ab"),
        stderr=subprocess.STDOUT,
    )

    # Within 5s, traffic should flow again.
    deadline = time.monotonic() + 5.0
    recovered = False
    while time.monotonic() < deadline:
        try:
            with requests.Session() as s:
                s.verify = ca
                s.cert = cert_pair
                r = s.get(f"{base_url}/health", timeout=2)
                if r.status_code == 200:
                    recovered = True
                    break
        except requests.RequestException:
            pass
        time.sleep(0.3)

    # Leave the replacement API running — the nginx_stack fixture
    # teardown will kill it via process-group SIGINT (or by pkill
    # in a later test's fixture setup).
    assert recovered, "NC4: FastAPI did not recover within 5s of restart"
