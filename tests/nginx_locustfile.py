"""NginxMTLSUser — Locust load driver hitting nginx :8444 over mTLS.

Invoked via ``make load-test-nginx``:

    locust -f tests/nginx_locustfile.py --headless \\
           -u 50 --spawn-rate 10 --run-time 60s \\
           --host https://localhost:8444 --exit-code-on-error 1

Pass thresholds (enforced in the `quitting` listener):
  - 0% failure rate
  - p95 < 50 ms
  - p99 < 150 ms

The user carries the real client cert and validates nginx with
the project CA — same posture as a production caller through
the mTLS termination layer.
"""

from __future__ import annotations

from pathlib import Path

from locust import HttpUser, between, events, task
from locust.env import Environment


REPO_ROOT = Path(__file__).resolve().parent.parent
PKI = REPO_ROOT / "pki"

_CA = PKI / "ca" / "ca.crt"
_CERT = PKI / "client" / "client.crt"
_KEY = PKI / "client" / "client.key"


class NginxMTLSUser(HttpUser):
    """Simulated mTLS client going through nginx."""

    wait_time = between(0.05, 0.2)

    def on_start(self) -> None:
        for p in (_CA, _CERT, _KEY):
            if not p.is_file():
                raise RuntimeError(f"PKI missing: {p}")
        self.client.verify = str(_CA)
        self.client.cert = (str(_CERT), str(_KEY))

    @task(3)
    def health_check(self) -> None:
        with self.client.get("/health", name="/health", catch_response=True) as resp:
            if resp.status_code != 200:
                resp.failure(f"status={resp.status_code}")

    @task(2)
    def get_data(self) -> None:
        with self.client.get("/data", name="/data", catch_response=True) as resp:
            if resp.status_code != 200:
                resp.failure(f"status={resp.status_code}")

    @task(1)
    def post_data(self) -> None:
        with self.client.post(
            "/data",
            name="/data (POST)",
            json={"sensor_id": "nginx-locust", "value": 24.5, "unit": "C"},
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"status={resp.status_code}")


@events.quitting.add_listener
def _enforce_sla(environment: Environment, **_: object) -> None:
    stats = environment.stats.total
    if stats.num_requests == 0:
        return
    fail_ratio = stats.num_failures / stats.num_requests
    p95 = stats.get_response_time_percentile(0.95) or 0
    p99 = stats.get_response_time_percentile(0.99) or 0

    violations: list[str] = []
    if fail_ratio > 0:
        violations.append(f"failure rate {fail_ratio * 100:.2f}%")
    if p95 > 50:
        violations.append(f"p95 {p95:.0f}ms (budget 50ms)")
    if p99 > 150:
        violations.append(f"p99 {p99:.0f}ms (budget 150ms)")

    if violations:
        print(f"[locust-nginx] SLO violations: {'; '.join(violations)}")
        environment.process_exit_code = 1
    else:
        print(
            f"[locust-nginx] SLO ok — failure_rate=0, p95={p95:.0f}ms, p99={p99:.0f}ms"
        )
