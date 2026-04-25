"""nginx_locustfile_v2.py — Locust load scenario for the v1.2 stack.

Usage (assumes the stack is already up — `make stack` or equivalent):

    locust \
        --locustfile tests/nginx_locustfile_v2.py \
        --host https://localhost:8444 \
        --users 50 --spawn-rate 10 --run-time 30s \
        --headless \
        --exit-code-on-error 1

The SLO check in ``on_test_stop`` asserts p95 < 30ms across all
requests. If the p95 violates the SLO, the process exits non-zero
so CI can gate on this.

Tightened from the v1.1 SLO (which allowed 50ms) — v1.2's single-
layer auth is measurably faster, and we want to keep the win.

Credentials live in the project's PKI:
    pki/ca/ca.crt                trust anchor
    pki/client/client.crt / .key client-01 identity (allowlisted)
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from locust import HttpUser, between, events, task


_V12_P95_SLO_MS = 30.0

_DEFAULT_REPO_ROOT = Path(__file__).resolve().parent.parent


def _pki_dir() -> Path:
    override = os.environ.get("MTLS_PKI_DIR")
    if override:
        return Path(override).resolve()
    return _DEFAULT_REPO_ROOT / "pki"


class NginxV2User(HttpUser):
    """Simulated client for the v1.2 nginx-mTLS + plain-FastAPI stack.

    Task weights roughly match expected production shape for a sensor
    ingest API: reads (health + data) dominate writes. Adjust if your
    workload differs — the SLO check doesn't depend on the weights."""

    wait_time = between(0.1, 0.5)

    def on_start(self) -> None:
        pki = _pki_dir()
        ca = pki / "ca" / "ca.crt"
        client_crt = pki / "client" / "client.crt"
        client_key = pki / "client" / "client.key"
        for path in (ca, client_crt, client_key):
            if not path.is_file():
                raise RuntimeError(
                    f"required PKI artefact missing: {path}. "
                    "Run ./pki_setup.sh first, or set MTLS_PKI_DIR."
                )

        # locust's requests.Session — same mTLS/verify conventions as
        # tests/test_nginx_auth.py.
        self.client.verify = str(ca)
        self.client.cert = (str(client_crt), str(client_key))

    @task(3)
    def health(self) -> None:
        self.client.get("/health", name="/health")

    @task(2)
    def data_get(self) -> None:
        self.client.get("/data", name="/data [GET]")

    @task(1)
    def data_post(self) -> None:
        self.client.post(
            "/data",
            json={"sensor_id": "bench-01", "value": 42},
            name="/data [POST]",
        )


# --- SLO gate --------------------------------------------------------------


@events.test_stop.add_listener
def _check_p95_slo(environment, **kwargs) -> None:
    """Emit a non-zero exit code if total-request p95 is above the SLO.

    Uses the aggregate stats (``environment.stats.total``) rather than
    per-endpoint stats because the SLO is defined against the whole
    auth path: a client perceives the slowest endpoint, not the mean.
    """
    total = environment.stats.total
    p95_ms = total.get_response_time_percentile(0.95)
    logger = logging.getLogger("locust.slo")
    if p95_ms is None:
        logger.warning("no requests recorded — cannot evaluate SLO")
        return
    logger.info(
        "v1.2 p95 = %.2f ms (SLO: < %.1f ms, %d total samples)",
        p95_ms,
        _V12_P95_SLO_MS,
        total.num_requests,
    )
    if p95_ms >= _V12_P95_SLO_MS:
        environment.process_exit_code = 1
        logger.error(
            "SLO VIOLATED: p95 %.2f ms >= %.1f ms",
            p95_ms,
            _V12_P95_SLO_MS,
        )
