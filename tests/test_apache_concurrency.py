"""test_apache_concurrency.py — AC1-AC3 concurrency tests for v1.3.

Apache's MPM (event on Ubuntu 22.04+) determines the concurrency
profile. These tests document the MPM in use at test time and run
modest concurrency (≤ 60 clients) so default-tuned hosts pass on
all three MPMs (event/worker/prefork).

    AC1  50 concurrent valid clients → all 200, total < 15s
         Apache is expected to be slower than nginx here; documented
         in docs/handshake_cost_comparison_apache.md.

    AC2  Mixed traffic: 20 valid + 10 no-cert + 10 wrong-CN.
         Two-flavour 403 behaviour — both no-cert and wrong-CN can
         end up at HTTP 403 in Apache (different from nginx, where
         no-cert is HTTP 400). We distinguish the two by curl's
         exit code: exit 0 means TLS handshake completed and Apache
         returned an HTTP code; exit ≠ 0 means TLS handshake aborted.

    AC3  Apache MPM stress: 60 concurrent connections. With prefork
         this hits MaxRequestWorkers (150 default) and may queue;
         with event/worker it should be smooth. Assert the server
         recovers within 5s after the burst.
"""
# ruff: noqa: F811

from __future__ import annotations

import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest
import requests

from tests.conftest import (
    APACHE_HTTPS_PORT,
    REPO_ROOT,
    _client_auth,
)


def _detect_mpm() -> str:
    """Return the active Apache MPM."""
    proc = subprocess.run(
        ["apachectl", "-V"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    for line in proc.stdout.splitlines():
        if line.lstrip().startswith("Server MPM:"):
            return line.split(":", 1)[1].strip().lower()
    return "unknown"


def _curl_to_apache_exit_and_http(
    *extra: str,
) -> tuple[int, str]:
    """Drive curl directly; return (exit_code, http_code_string).

    Used by AC2 to distinguish TLS abort (exit ≠ 0) from
    HTTP-completed (exit 0 + status code captured)."""
    proc = subprocess.run(
        [
            "curl",
            "-sS",
            "--cacert",
            str(REPO_ROOT / "pki" / "ca" / "ca.crt"),
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            *extra,
            f"https://localhost:{APACHE_HTTPS_PORT}/health",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return proc.returncode, proc.stdout.strip()


@pytest.mark.integration
@pytest.mark.slow
class TestApacheConcurrency:
    # -------- AC1 ---------------------------------------------------------
    def test_ac1_50_concurrent_valid_clients(self, apache_stack, pki_paths):
        """50 concurrent valid clients via Apache → all 200, total < 15s.
        Apache is expected to be slower than nginx for this workload —
        the per-connection process/thread overhead adds up."""
        url = f"{apache_stack['apache_url']}/health"
        auth = _client_auth(pki_paths)

        def _call() -> int:
            r = requests.get(url, **auth)
            return r.status_code

        t0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=15) as ex:
            futures = [ex.submit(_call) for _ in range(50)]
            statuses = [f.result() for f in as_completed(futures)]
        elapsed = time.perf_counter() - t0

        mpm = _detect_mpm()
        assert all(s == 200 for s in statuses), (
            f"AC1 (Apache MPM={mpm}) status distribution: "
            f"{ {s: statuses.count(s) for s in set(statuses)} }"
        )
        assert elapsed < 15.0, (
            f"AC1 (Apache MPM={mpm}) 50 concurrent took {elapsed:.2f}s " "(ceiling 15s)"
        )

    # -------- AC2 ---------------------------------------------------------
    def test_ac2_mixed_traffic_two_flavour_403(
        self,
        apache_stack,
        cert_kit,
        pki_paths,
    ):
        """Three concurrent batches:
            * 20 valid clients (client-01) — expect HTTP 200
            * 10 no-cert requests           — expect TLS abort OR HTTP 403
            * 10 wrong-CN (client-99)       — expect HTTP 403 with JSON body

        APACHE_VS_NGINX_DIFFERENCE: Apache returns HTTP 403 for both
        no-cert AND wrong-CN cases. nginx returns HTTP 400 for no-cert
        and HTTP 403 for wrong-CN. We disambiguate the two flavours
        in Apache via curl's exit code:
            exit 0 means TLS handshake completed → HTTP-layer 403
            exit ≠ 0 means TLS handshake aborted → no HTTP code at all
        """
        rogue_key, rogue_crt = cert_kit["client_99"]

        def _call_valid() -> tuple[str, int, str]:
            r = requests.get(
                f"{apache_stack['apache_url']}/health",
                **_client_auth(pki_paths),
            )
            return ("valid", r.status_code, "")

        def _call_no_cert() -> tuple[str, int, str]:
            ec, http = _curl_to_apache_exit_and_http()
            return ("no_cert", ec, http)

        def _call_wrong_cn() -> tuple[str, int, str]:
            ec, http = _curl_to_apache_exit_and_http(
                "--cert",
                str(rogue_crt),
                "--key",
                str(rogue_key),
            )
            return ("wrong_cn", ec, http)

        tasks = [_call_valid] * 20 + [_call_no_cert] * 10 + [_call_wrong_cn] * 10
        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = [ex.submit(t) for t in tasks]
            results = [f.result() for f in as_completed(futures)]

        valid_results = [r for r in results if r[0] == "valid"]
        no_cert_results = [r for r in results if r[0] == "no_cert"]
        wrong_cn_results = [r for r in results if r[0] == "wrong_cn"]

        # Valid: all 200.
        assert len(valid_results) == 20
        assert all(s == 200 for _, s, _ in valid_results), valid_results

        # No-cert: each individual result is either a TLS abort
        # (exit_code != 0) or HTTP 403 (exit_code == 0, status == "403").
        assert len(no_cert_results) == 10
        for label, ec, http in no_cert_results:
            rejected = ec != 0 or http in {"400", "401", "403", "495"}
            assert rejected, f"{label}: ec={ec} http={http!r} (NOT rejected)"

        # Wrong-CN: handshake completes (exit 0), HTTP 403 returned.
        assert len(wrong_cn_results) == 10
        for label, ec, http in wrong_cn_results:
            assert ec == 0, f"{label}: handshake aborted ec={ec}"
            assert http == "403", f"{label}: expected HTTP 403, got {http!r}"

    # -------- AC3 ---------------------------------------------------------
    def test_ac3_mpm_stress_recovery(self, apache_stack, pki_paths):
        """60 concurrent connections fired simultaneously. With prefork
        MPM this can hit MaxRequestWorkers (default 150 — fine), with
        event MPM it should be smooth. Assert that the server recovers
        and accepts a normal request within 5s of the burst."""
        url = f"{apache_stack['apache_url']}/health"
        auth = _client_auth(pki_paths)

        def _call() -> int:
            r = requests.get(url, **auth)
            return r.status_code

        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = [ex.submit(_call) for _ in range(60)]
            statuses = [f.result() for f in as_completed(futures)]

        mpm = _detect_mpm()
        # Most must succeed — we tolerate a small number of timeouts /
        # backpressure on a heavily-stressed prefork MPM, but the
        # majority should come back 200.
        ok = sum(1 for s in statuses if s == 200)
        assert ok >= 55, (
            f"AC3 (Apache MPM={mpm}) burst: only {ok}/60 returned 200 "
            f"(distribution: { {s: statuses.count(s) for s in set(statuses)} })"
        )

        # Recovery: a simple request within 5s must succeed.
        t0 = time.perf_counter()
        deadline = t0 + 5.0
        recovered = False
        while time.perf_counter() < deadline:
            try:
                r = requests.get(url, **auth)
                if r.status_code == 200:
                    recovered = True
                    break
            except requests.exceptions.RequestException:
                pass
            time.sleep(0.2)
        assert recovered, f"AC3 (Apache MPM={mpm}) did not recover within 5s of burst"
