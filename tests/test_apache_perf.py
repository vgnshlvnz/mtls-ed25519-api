"""test_apache_perf.py — AP1-AP4 perf benchmarks for the v1.3 stack.

Mirrors test_nginx_perf.py, but driving Apache 2.4 + mod_ssl. The
underlying Apache MPM (event on Ubuntu 22.04+) determines the
concurrency profile; this file documents the MPM in use at test
time so historical comparisons stay reproducible.

    AP1  baseline mTLS handshake + GET /health latency
    AP2  keepalive reuse on a single TLS session
    AP3  three-way handshake-cost table — v1.0 (Python ssl) vs
         v1.2 (nginx) vs v1.3 (Apache); written to
         docs/handshake_cost_comparison_apache.md by the AP3
         driver. The pytest test itself just runs the Apache leg
         and asserts it fits the documented envelope.
    AP4  RewriteMap allowlist scaling: 10-entry vs 1000-entry
         allowlist. Apache's RewriteMap txt: is O(log n), so we
         allow the 1000-entry case to be up to 50% slower than the
         baseline (much weaker than nginx map{} O(1) but still
         well within usable territory).
"""
# ruff: noqa: F811

from __future__ import annotations

import subprocess
import time

import pytest
import requests

from tests.conftest import _client_auth


# Absolute ceilings. Apache is typically 5-10ms slower than nginx
# for the same TLS handshake due to per-process / per-thread overhead.
# These ceilings are loose enough to pass on CI hardware and on
# event/worker/prefork MPMs alike.
_MEAN_LATENCY_CEILING_S = 0.060  # 60ms (vs nginx's 50ms ceiling)
_KEEPALIVE_P99_CEILING_S = 0.020  # 20ms (single TLS session, no handshake cost)


def _detect_mpm() -> str:
    """Return the active Apache MPM ('event'/'worker'/'prefork')."""
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


@pytest.mark.integration
@pytest.mark.performance
@pytest.mark.slow
class TestApachePerf:
    # -------- AP1 ---------------------------------------------------------
    def test_ap1_baseline_latency(self, benchmark, apache_stack, pki_paths):
        """Allowed GET /health through Apache — the fast path.
        New TLS handshake per benchmark iteration (Session not reused
        across rounds; pytest-benchmark calls our function fresh)."""
        url = f"{apache_stack['apache_url']}/health"
        auth = _client_auth(pki_paths)

        def _call() -> None:
            r = requests.get(url, **auth)
            assert r.status_code == 200

        benchmark.pedantic(_call, iterations=10, rounds=5, warmup_rounds=1)
        mpm = _detect_mpm()
        mean_ms = benchmark.stats.stats.mean * 1000
        assert benchmark.stats.stats.mean < _MEAN_LATENCY_CEILING_S, (
            f"AP1 (Apache MPM={mpm}) baseline mean={mean_ms:.2f}ms "
            f"exceeds {_MEAN_LATENCY_CEILING_S * 1000}ms ceiling"
        )

    # -------- AP2 ---------------------------------------------------------
    def test_ap2_keepalive_p99(self, benchmark, apache_stack, pki_paths):
        """Single TLS session, 10 sequential GETs — measures HTTP
        request-response latency on a hot connection (no handshake
        cost). Apache's keepalive is less efficient than nginx's
        upstream keepalive pool because each request needs to traverse
        Apache's process/thread boundary; we accept p99 < 20ms."""
        session = requests.Session()
        auth = _client_auth(pki_paths)
        session.cert = auth["cert"]
        session.verify = auth["verify"]
        url = f"{apache_stack['apache_url']}/health"

        # Warm the connection.
        assert session.get(url, timeout=5.0).status_code == 200

        def _call() -> None:
            r = session.get(url, timeout=5.0)
            assert r.status_code == 200

        benchmark.pedantic(_call, iterations=10, rounds=5, warmup_rounds=1)
        # Use the max instead of p99 (pytest-benchmark doesn't expose
        # a p99 directly; max is a stricter bound and good enough).
        max_ms = benchmark.stats.stats.max * 1000
        assert benchmark.stats.stats.max < _KEEPALIVE_P99_CEILING_S, (
            f"AP2 keepalive max={max_ms:.2f}ms exceeds "
            f"{_KEEPALIVE_P99_CEILING_S * 1000}ms ceiling — Apache keepalive "
            "is degrading"
        )

    # -------- AP3 ---------------------------------------------------------
    def test_ap3_apache_leg_for_three_way_comparison(
        self,
        apache_stack,
        pki_paths,
    ):
        """Run 100 cold-handshake requests to Apache; capture mean.
        v1.0 / v1.2 numbers come from prior wiki measurements (see
        docs/handshake_cost_comparison_apache.md). The pytest assertion
        is just an envelope check — the doc is the real artefact."""
        session = requests.Session()
        auth = _client_auth(pki_paths)
        session.cert = auth["cert"]
        session.verify = auth["verify"]
        url = f"{apache_stack['apache_url']}/health"

        # Warm the connection so first-request bias doesn't distort.
        session.get(url, timeout=5.0)

        N = 100
        # Force fresh TLS handshakes — close after every request.
        cold_session_kwargs = {
            "cert": auth["cert"],
            "verify": auth["verify"],
            "headers": {"Connection": "close"},
            "timeout": 5.0,
        }
        t0 = time.perf_counter()
        for _ in range(N):
            r = requests.get(url, **cold_session_kwargs)
            assert r.status_code == 200
        elapsed = time.perf_counter() - t0
        mean_s = elapsed / N

        mpm = _detect_mpm()
        # Loose envelope: < 100ms per cold request on loopback
        # (TLS handshake + Apache process dispatch + plain HTTP
        # to upstream). CI hardware varies wildly so this is slack.
        assert mean_s < 0.100, (
            f"AP3 (Apache MPM={mpm}) cold-handshake mean="
            f"{mean_s * 1000:.2f}ms exceeds 100ms envelope"
        )

    # -------- AP4 — 1000-CN allowlist scaling -----------------------------
    def test_ap4_rewritemap_scales_with_1000_cns(
        self,
        apache_stack,
        pki_paths,
    ):
        """Patch 1000 entries into cn_allowlist.txt, graceful-reload,
        measure latency, restore. RewriteMap txt: is O(log n) — much
        weaker than nginx's O(1) hash map but still usable.

        Allowance: up to 50% slower than the 10-entry baseline. nginx's
        equivalent test (NP3) holds within the same absolute ceiling,
        which is a stronger guarantee — documented in
        docs/handshake_cost_comparison_apache.md."""
        allowlist = apache_stack["cn_allowlist"]
        original = allowlist.read_text(encoding="utf-8")

        # 10-entry baseline (the file already has 2 + 8 dummies).
        baseline_entries = (
            original.rstrip()
            + "\n"
            + "\n".join(f"baseline-cn-{i:02d}\t1" for i in range(8))
            + "\n"
        )

        # 1000-entry stress.
        stress_entries = (
            original.rstrip()
            + "\n"
            + "\n".join(f"bench-cn-{i:04d}\t1" for i in range(1000))
            + "\n"
        )

        def _measure(label: str) -> float:
            """Time 50 cold-handshake requests; return mean seconds."""
            session_kwargs = {
                **_client_auth(pki_paths),
                "headers": {"Connection": "close"},
            }
            url = f"{apache_stack['apache_url']}/health"
            # Warm.
            requests.get(url, **session_kwargs)
            t0 = time.perf_counter()
            for _ in range(50):
                r = requests.get(url, **session_kwargs)
                assert r.status_code == 200
            return (time.perf_counter() - t0) / 50

        try:
            # Baseline.
            allowlist.write_text(baseline_entries, encoding="utf-8")
            subprocess.run(
                [
                    "apachectl",
                    "-f",
                    str(apache_stack["apache_conf"]),
                    "-d",
                    str(apache_stack["apache_dir"]),
                    "-k",
                    "graceful",
                ],
                check=True,
                timeout=5,
                capture_output=True,
            )
            time.sleep(0.6)
            baseline_mean = _measure("baseline-10")

            # Stress.
            allowlist.write_text(stress_entries, encoding="utf-8")
            subprocess.run(
                [
                    "apachectl",
                    "-f",
                    str(apache_stack["apache_conf"]),
                    "-d",
                    str(apache_stack["apache_dir"]),
                    "-k",
                    "graceful",
                ],
                check=True,
                timeout=5,
                capture_output=True,
            )
            time.sleep(0.6)
            stress_mean = _measure("stress-1000")

            # Allow up to 50% degradation. Apache's RewriteMap is
            # O(log n) so 1000 vs 10 should add roughly log(1000)/log(10)
            # ~ 3 cache misses' worth of latency — well below 50%.
            ratio = stress_mean / baseline_mean
            assert ratio < 1.50, (
                f"AP4 RewriteMap latency degradation: 10-entry={baseline_mean*1000:.2f}ms, "
                f"1000-entry={stress_mean*1000:.2f}ms, ratio={ratio:.2f} "
                "(expected < 1.50)"
            )
        finally:
            allowlist.write_text(original, encoding="utf-8")
            subprocess.run(
                [
                    "apachectl",
                    "-f",
                    str(apache_stack["apache_conf"]),
                    "-d",
                    str(apache_stack["apache_dir"]),
                    "-k",
                    "graceful",
                ],
                check=False,
                timeout=5,
                capture_output=True,
            )
            time.sleep(0.6)
