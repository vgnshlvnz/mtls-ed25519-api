"""Integration tests — synchronous mTLS client against the live server.

Uses ``requests.Session`` so the TLS handshake / connection pool is
reused across calls, matching the pattern of ``tests/client_test.py``
but now under pytest with ``server_process`` as the fixture that owns
the server lifecycle.

All three tests assert BOTH status code AND the JSON body shape so a
regression that returns 200 with the wrong payload still fails.

Run:
    pytest -m integration
"""

from __future__ import annotations

from pathlib import Path

import pytest
import requests


pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def session(
    pki_paths: dict[str, Path],
    server_process: dict[str, object],  # noqa: ARG001 — lifecycle dependency
) -> requests.Session:
    """Module-scoped mTLS session reusing the server fixture's lifecycle.

    SECURITY: ``verify`` MUST be a CA path, never ``False``; ``cert``
    MUST be the tuple form. These are enforced by code review and by
    the project's no-``verify=False`` pre-commit grep.
    """
    sess = requests.Session()
    sess.verify = str(pki_paths["ca_cert"])
    sess.cert = (str(pki_paths["client_cert"]), str(pki_paths["client_key"]))
    return sess


def _base_url(server_process: dict[str, object]) -> str:
    return str(server_process["base_url"])


def test_get_health_returns_ok_and_tls_true(
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    resp = session.get(f"{_base_url(server_process)}/health", timeout=5)

    assert resp.status_code == 200
    assert resp.headers.get("X-Request-ID"), "X-Request-ID header must be present"

    body = resp.json()
    assert body == {"status": "ok", "tls": True}


def test_get_data_returns_readings_and_timestamp(
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    resp = session.get(f"{_base_url(server_process)}/data", timeout=5)

    assert resp.status_code == 200
    body = resp.json()

    assert set(body.keys()) == {"readings", "generated_at"}
    assert isinstance(body["readings"], list)
    assert len(body["readings"]) >= 1
    for reading in body["readings"]:
        assert set(reading.keys()) == {
            "sensor_id",
            "temperature_c",
            "humidity_pct",
            "recorded_at",
        }
        assert isinstance(reading["temperature_c"], (int, float))


def test_post_data_echoes_payload_with_server_timestamp(
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    payload = {"sensor_id": "temp-sync-test", "value": 42.0, "unit": "C"}
    resp = session.post(
        f"{_base_url(server_process)}/data",
        json=payload,
        timeout=5,
    )

    assert resp.status_code == 200
    body = resp.json()

    assert set(body.keys()) == {"received", "echoed_at"}
    assert body["received"] == payload
    assert isinstance(body["echoed_at"], str) and body["echoed_at"]
