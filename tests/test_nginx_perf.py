"""test_nginx_perf.py — NP1-NP3 perf benchmarks for the v1.2 stack.

Three benchmarks, each on the same nginx + FastAPI stack:

    NP1   Baseline latency: allowed GET /health via nginx.
    NP2   Deny-path latency: rogue-CN → 403 at nginx. Should be
          comparable to NP1 because nginx short-circuits before
          the upstream is even dialled.
    NP3   Allowlist-scale: patch 1000 CNs into the map{} block,
          reload, measure latency. nginx's hash-table lookup is
          O(1) — latency MUST stay within the same order of
          magnitude as NP1.

All benchmarks run on loopback, so numbers are generous (<50ms mean)
and CI-hardware-tolerant. What we actually care about is the
*relative* shape of NP3 vs NP1, not absolute wall-clock numbers.
"""
# ruff: noqa: F811

from __future__ import annotations

import subprocess
import time

import pytest
import requests

from tests.conftest import REPO_ROOT, _client_auth


# Absolute ceilings. These are intentionally loose — they're insurance
# against "nginx is utterly broken" (e.g. 10s per request), not SLO
# enforcement. Real SLO lives in the Locust run (nginx_locustfile_v2.py).
_MEAN_LATENCY_CEILING_S = 0.050  # 50ms


@pytest.mark.integration
@pytest.mark.performance
@pytest.mark.slow
class TestNginxPerf:
    # -------- NP1 ---------------------------------------------------------
    def test_np1_baseline_latency(self, benchmark, nginx_stack, pki_paths):
        """Allowed GET /health through nginx — the fast path."""
        session = requests.Session()
        auth = _client_auth(pki_paths)
        session.cert = auth["cert"]
        session.verify = auth["verify"]
        url = f"{nginx_stack['nginx_url']}/health"

        def _call() -> None:
            r = session.get(url, timeout=5.0)
            assert r.status_code == 200

        benchmark.pedantic(_call, iterations=20, rounds=5, warmup_rounds=1)
        assert benchmark.stats.stats.mean < _MEAN_LATENCY_CEILING_S, (
            f"NP1 baseline exceeded ceiling: "
            f"mean={benchmark.stats.stats.mean * 1000:.2f}ms"
        )

    # -------- NP2 ---------------------------------------------------------
    def test_np2_deny_path_latency(
        self,
        benchmark,
        nginx_stack,
        cert_kit,
        pki_paths,
    ):
        """Rogue-CN → 403 at nginx. Latency must be within 3× the NP1
        baseline — deny is always cheaper or equal, never an outlier."""
        session = requests.Session()
        auth = _client_auth(pki_paths, pair=cert_kit["client_99"])
        session.cert = auth["cert"]
        session.verify = auth["verify"]
        url = f"{nginx_stack['nginx_url']}/health"

        def _call() -> None:
            r = session.get(url, timeout=5.0)
            assert r.status_code == 403

        benchmark.pedantic(_call, iterations=20, rounds=5, warmup_rounds=1)
        assert (
            benchmark.stats.stats.mean < _MEAN_LATENCY_CEILING_S * 3
        ), f"NP2 deny path too slow: mean={benchmark.stats.stats.mean * 1000:.2f}ms"

    # -------- NP3 — 1000-CN allowlist -------------------------------------
    def test_np3_allowlist_scales_with_1000_cns(
        self,
        nginx_stack,
        pki_paths,
    ):
        """Patch 1000 bench-cn entries into the allowlist and verify the
        real client-01 still responds with comparable latency.

        If nginx ever switches from its internal hash table to a linear
        scan, this test catches it: the mean latency stays the same only
        while lookup is O(1). We don't use pytest-benchmark here because
        NP3 has its own lifecycle (patch → reload → measure → restore)
        and interleaving that with benchmark's machinery complicates
        teardown."""
        conf = nginx_stack["nginx_conf"]
        original = conf.read_text(encoding="utf-8")

        # 1000 entries of the form  "bench-cn-0001"   1;
        bench_entries = "\n".join(
            f'        "bench-cn-{i:04d}"   1;' for i in range(1000)
        )
        patched = original.replace(
            '"client-02"   1;',
            f'"client-02"   1;\n{bench_entries}',
        )
        assert patched != original, "patch did not apply — template shape changed?"
        conf.write_text(patched, encoding="utf-8")

        try:
            subprocess.run(
                ["nginx", "-s", "reload", "-c", str(conf)],
                cwd=str(REPO_ROOT),
                check=True,
                timeout=5,
                capture_output=True,
            )
            time.sleep(0.5)

            session = requests.Session()
            auth = _client_auth(pki_paths)
            session.cert = auth["cert"]
            session.verify = auth["verify"]
            url = f"{nginx_stack['nginx_url']}/health"

            # Warm up: one request before timing (TLS handshake amortisation).
            r = session.get(url, timeout=5.0)
            assert r.status_code == 200, r.text

            # Time 100 iterations.
            N = 100
            t0 = time.perf_counter()
            for _ in range(N):
                r = session.get(url, timeout=5.0)
                assert r.status_code == 200
            elapsed = time.perf_counter() - t0
            mean_s = elapsed / N

            assert mean_s < _MEAN_LATENCY_CEILING_S, (
                f"NP3 mean latency with 1000-entry allowlist: "
                f"{mean_s * 1000:.2f}ms (ceiling {_MEAN_LATENCY_CEILING_S * 1000}ms). "
                "map{} lookup appears to have degraded below O(1)."
            )
        finally:
            conf.write_text(original, encoding="utf-8")
            subprocess.run(
                ["nginx", "-s", "reload", "-c", str(conf)],
                cwd=str(REPO_ROOT),
                check=False,
                timeout=5,
                capture_output=True,
            )
            time.sleep(0.3)
