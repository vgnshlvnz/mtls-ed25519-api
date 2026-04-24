"""Locust user-behaviour model for the T4 load test.

Exercises the three mTLS endpoints with a weighted mix that
approximates a health-check-dominant workload:

    health_check  weight 3
    get_data      weight 2
    post_data     weight 1

Each user instance runs its own ``requests.Session`` preconfigured
with the project client cert + CA so every request is a real mTLS
round trip — the same code path as a production caller.

Invocation (also exposed via ``make load-test``)::

    locust -f tests/locustfile.py --headless \\
           -u 20 --spawn-rate 5 --run-time 30s \\
           --host https://127.0.0.1:8443 \\
           --exit-code-on-error 1

Pass thresholds asserted in ``make load-test``:
    - 0% failure rate
    - p95 < 200ms
    - p99 < 500ms
"""

from __future__ import annotations

from pathlib import Path

from locust import HttpUser, between, events, task
from locust.env import Environment


REPO_ROOT = Path(__file__).resolve().parent.parent
PKI_DIR = REPO_ROOT / "pki"

_CA_CERT = PKI_DIR / "ca" / "ca.crt"
_CLIENT_CERT = PKI_DIR / "client" / "client.crt"
_CLIENT_KEY = PKI_DIR / "client" / "client.key"


class mTLSUser(HttpUser):
    """A single simulated mTLS client.

    SECURITY: every locust user carries the same client identity as
    the real synchronous / async clients. ``verify`` is the CA path;
    ``cert`` is the (cert, key) tuple. We never set ``verify=False``
    or use ``--insecure`` — that would defeat the point of load-
    testing an mTLS service.
    """

    wait_time = between(0.1, 0.5)

    def on_start(self) -> None:
        for path in (_CA_CERT, _CLIENT_CERT, _CLIENT_KEY):
            if not path.is_file():
                raise RuntimeError(f"PKI material missing: {path}. Run ./pki_setup.sh")
        self.client.verify = str(_CA_CERT)
        self.client.cert = (str(_CLIENT_CERT), str(_CLIENT_KEY))

    @task(3)
    def health_check(self) -> None:
        with self.client.get("/health", name="/health", catch_response=True) as resp:
            if resp.status_code != 200:
                resp.failure(f"expected 200, got {resp.status_code}")
            elif resp.json().get("status") != "ok":
                resp.failure("health body missing status=ok")

    @task(2)
    def get_data(self) -> None:
        with self.client.get("/data", name="/data", catch_response=True) as resp:
            if resp.status_code != 200:
                resp.failure(f"expected 200, got {resp.status_code}")
            elif "readings" not in resp.json():
                resp.failure("/data body missing readings key")

    @task(1)
    def post_data(self) -> None:
        payload = {
            "sensor_id": "locust-probe",
            "value": 25.0,
            "unit": "C",
        }
        with self.client.post(
            "/data", name="/data (POST)", json=payload, catch_response=True
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"expected 200, got {resp.status_code}")
            elif "echoed_at" not in resp.json():
                resp.failure("/data POST body missing echoed_at")


# --- CI gate: fail the run if p95 / p99 / failure-rate drift off spec -------


@events.quitting.add_listener
def _enforce_sla(environment: Environment, **_: object) -> None:
    """Raise a non-zero exit code when SLO thresholds are breached.

    Locust itself only fails the run on protocol errors; we also want
    to fail on latency regressions and any failure-rate, matching the
    T4 pass thresholds. ``environment.process_exit_code`` is respected
    by ``--exit-code-on-error 1``.
    """
    stats = environment.stats.total
    if stats.num_requests == 0:
        return

    fail_ratio = stats.num_failures / stats.num_requests
    p95 = stats.get_response_time_percentile(0.95)
    p99 = stats.get_response_time_percentile(0.99)

    # Locust returns latencies in milliseconds.
    violations = []
    if fail_ratio > 0:
        violations.append(f"failure rate {fail_ratio * 100:.2f}% (budget 0%)")
    if p95 is not None and p95 > 200:
        violations.append(f"p95 {p95:.0f}ms (budget 200ms)")
    if p99 is not None and p99 > 500:
        violations.append(f"p99 {p99:.0f}ms (budget 500ms)")

    if violations:
        print(f"[locust] SLO violations: {'; '.join(violations)}")
        environment.process_exit_code = 1
    else:
        print(f"[locust] SLO ok — failure_rate=0, p95={p95:.0f}ms, p99={p99:.0f}ms")
