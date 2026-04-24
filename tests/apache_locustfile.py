"""apache_locustfile.py — Locust load scenario for the v1.3 stack.

Usage (assumes the stack is already up — `make apache-server` or
`make stack-apache`):

    locust \
        --locustfile tests/apache_locustfile.py \
        --host https://localhost:8445 \
        --users 50 --spawn-rate 10 --run-time 60s \
        --headless \
        --exit-code-on-error 1

Pass thresholds (looser than the v1.2 nginx SLO — Apache is typically
5-10ms slower for the same handshake due to per-process overhead):

    0% failure rate
    p95  < 50ms
    p99  < 150ms

The on_test_stop hook fails the run with process_exit_code=1 if any
of those thresholds is violated, so CI can gate on this directly.

Credentials live in the project's PKI:
    pki/ca/ca.crt                trust anchor
    pki/client/client.crt / .key client-01 identity (allowlisted)
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from locust import HttpUser, between, events, task


_P95_SLO_MS = 50.0
_P99_SLO_MS = 150.0
_FAILURE_RATE_SLO = 0.0  # zero failures tolerated

_DEFAULT_REPO_ROOT = Path(__file__).resolve().parent.parent


def _pki_dir() -> Path:
    override = os.environ.get("MTLS_PKI_DIR")
    if override:
        return Path(override).resolve()
    return _DEFAULT_REPO_ROOT / "pki"


class ApacheMTLSUser(HttpUser):
    """Simulated client for the v1.3 Apache mTLS + plain-FastAPI stack.

    Task weights match expected production shape — reads dominate
    writes — but the SLO check doesn't depend on the weights."""

    wait_time = between(0.05, 0.2)

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

        self.client.verify = str(ca)
        self.client.cert = (str(client_crt), str(client_key))

    @task(3)
    def health_check(self) -> None:
        self.client.get("/health", name="/health")

    @task(2)
    def get_data(self) -> None:
        self.client.get("/data", name="/data [GET]")

    @task(1)
    def post_data(self) -> None:
        self.client.post(
            "/data",
            json={"sensor_id": "apache-bench-01", "value": 42},
            name="/data [POST]",
        )


# --- SLO gate ---------------------------------------------------------------


@events.test_stop.add_listener
def _check_slo(environment, **kwargs) -> None:
    """Fail with non-zero exit if any of: failure-rate, p95, p99 SLOs
    are violated. Aggregate stats (environment.stats.total) capture
    all endpoints together — a client perceives the slowest one."""
    total = environment.stats.total
    logger = logging.getLogger("locust.slo")

    if total.num_requests == 0:
        logger.warning("no requests recorded — cannot evaluate SLO")
        return

    failure_rate = total.num_failures / total.num_requests
    p95_ms = total.get_response_time_percentile(0.95) or 0
    p99_ms = total.get_response_time_percentile(0.99) or 0

    logger.info(
        "v1.3 Apache load run: %d req, %d failures (%.2f%%), "
        "p95=%.2fms (SLO < %.0fms), p99=%.2fms (SLO < %.0fms)",
        total.num_requests,
        total.num_failures,
        failure_rate * 100,
        p95_ms,
        _P95_SLO_MS,
        p99_ms,
        _P99_SLO_MS,
    )

    breaches = []
    if failure_rate > _FAILURE_RATE_SLO:
        breaches.append(f"failure rate {failure_rate:.2%} > 0%")
    if p95_ms >= _P95_SLO_MS:
        breaches.append(f"p95 {p95_ms:.2f}ms >= {_P95_SLO_MS}ms")
    if p99_ms >= _P99_SLO_MS:
        breaches.append(f"p99 {p99_ms:.2f}ms >= {_P99_SLO_MS}ms")

    if breaches:
        environment.process_exit_code = 1
        for breach in breaches:
            logger.error("SLO VIOLATED: %s", breach)
