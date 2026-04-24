"""Integration tests — async mTLS client against the live server.

Three concurrent requests via ``httpx.AsyncClient`` + ``asyncio.gather``.
The elapsed-time assertion at the end (< 500ms wall-clock for all three
combined) is a regression guard: it fails if the server serialises
handshakes or if a future change accidentally re-handshakes per call.

Run:
    pytest -m integration tests/test_client_async.py
"""

from __future__ import annotations

import asyncio
import ssl
import time
from pathlib import Path

import httpx
import pytest


pytestmark = pytest.mark.integration

# Wall-clock budget for the three concurrent calls combined. Local
# machine round-trips are single-digit ms; 500ms is ~100x headroom and
# catches pathological regressions (per-call handshake, serialisation,
# DNS stalls, etc.) without being flaky on slow CI boxes.
_LATENCY_BUDGET_MS = 500.0


def _build_client_ssl_context(pki_paths: dict[str, Path]) -> ssl.SSLContext:
    """Fresh client-side SSLContext for httpx.

    We build a module-local context rather than depending on the
    session-scoped ``client_ssl_context`` fixture because httpx's
    AsyncClient consumes the context and we want a predictable,
    per-test lifecycle.
    """
    ctx = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH,
        cafile=str(pki_paths["ca_cert"]),
    )
    ctx.load_cert_chain(
        certfile=str(pki_paths["client_cert"]),
        keyfile=str(pki_paths["client_key"]),
    )
    return ctx


async def test_three_endpoints_concurrently_under_budget(
    pki_paths: dict[str, Path],
    server_process: dict[str, object],
) -> None:
    """All three endpoints succeed concurrently within the latency budget."""
    base_url = str(server_process["base_url"])

    async with httpx.AsyncClient(
        base_url=base_url,
        verify=_build_client_ssl_context(pki_paths),
        timeout=5.0,
    ) as client:
        started = time.perf_counter()
        health, data, echo = await asyncio.gather(
            client.get("/health"),
            client.get("/data"),
            client.post(
                "/data",
                json={"sensor_id": "temp-async", "value": 24.5, "unit": "C"},
            ),
        )
        elapsed_ms = (time.perf_counter() - started) * 1000

    # Correctness first — we want to know if something is actually
    # broken before we blame the latency guard.
    assert health.status_code == 200
    assert health.json() == {"status": "ok", "tls": True}

    assert data.status_code == 200
    data_body = data.json()
    assert "readings" in data_body and "generated_at" in data_body
    assert isinstance(data_body["readings"], list) and data_body["readings"]

    assert echo.status_code == 200
    echo_body = echo.json()
    assert echo_body["received"] == {
        "sensor_id": "temp-async",
        "value": 24.5,
        "unit": "C",
    }
    assert echo_body["echoed_at"]

    # Regression guard: combined wall-clock for three gathered requests.
    assert elapsed_ms < _LATENCY_BUDGET_MS, (
        f"three concurrent calls took {elapsed_ms:.1f}ms "
        f"(budget {_LATENCY_BUDGET_MS:.0f}ms)"
    )


async def test_each_endpoint_has_distinct_request_id(
    pki_paths: dict[str, Path],
    server_process: dict[str, object],
) -> None:
    """Every concurrent call gets its own X-Request-ID from the middleware."""
    base_url = str(server_process["base_url"])

    async with httpx.AsyncClient(
        base_url=base_url,
        verify=_build_client_ssl_context(pki_paths),
        timeout=5.0,
    ) as client:
        responses = await asyncio.gather(
            client.get("/health"),
            client.get("/data"),
            client.get("/health"),
        )

    request_ids = [r.headers.get("X-Request-ID") for r in responses]
    for rid in request_ids:
        assert rid, "every response must carry X-Request-ID"
    assert len(set(request_ids)) == len(
        request_ids
    ), f"X-Request-IDs were not unique across concurrent calls: {request_ids}"


async def test_honours_client_supplied_request_id(
    pki_paths: dict[str, Path],
    server_process: dict[str, object],
) -> None:
    """A client-supplied X-Request-ID is echoed back on the response.

    Gives operators the "same request-id on the client and server log
    lines" guarantee that the middleware's code path promises.
    """
    base_url = str(server_process["base_url"])
    supplied_id = "pytest-integration-t1-xyz"

    async with httpx.AsyncClient(
        base_url=base_url,
        verify=_build_client_ssl_context(pki_paths),
        timeout=5.0,
    ) as client:
        resp = await client.get("/health", headers={"X-Request-ID": supplied_id})

    assert resp.status_code == 200
    assert resp.headers.get("X-Request-ID") == supplied_id
