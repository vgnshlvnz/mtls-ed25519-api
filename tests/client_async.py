"""Async mTLS client — fires three requests concurrently via ``httpx``.

Uses a single ``httpx.AsyncClient`` so the underlying connection pool
amortises the TLS handshake across the concurrent dispatch. Results are
printed *as they arrive* (via ``asyncio.as_completed``) so you can see
that the three calls really are overlapping rather than serialised.

Exit codes:
    0   all three endpoints returned 2xx AND matched the expected shape
    1   one or more endpoints did not meet the contract
    2   server unreachable / setup problem

Run:
    python tests/client_async.py
"""

from __future__ import annotations

import asyncio
import json
import ssl
import sys
import time
from pathlib import Path
from typing import Any

import httpx

# --- Paths ------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
PKI_DIR = REPO_ROOT / "pki"

CA_CERT = PKI_DIR / "ca" / "ca.crt"
CLIENT_CERT = PKI_DIR / "client" / "client.crt"
CLIENT_KEY = PKI_DIR / "client" / "client.key"

BASE_URL = "https://localhost:8443"


def _assert_ok(label: str, resp: httpx.Response, shape_check: Any) -> bool:
    """Return True if the response meets the contract for the given label."""
    try:
        payload = resp.json()
    except json.JSONDecodeError:
        payload = None

    print(f"\n=== {label} ===")
    print(f"  HTTP {resp.status_code}")
    print(f"  X-Request-ID: {resp.headers.get('X-Request-ID', '-')}")
    print(
        f"  body: {json.dumps(payload, indent=2) if payload is not None else resp.text}"
    )

    if resp.status_code != 200:
        return False
    return bool(shape_check(payload))


async def _call(
    client: httpx.AsyncClient, method: str, path: str, **kwargs: Any
) -> tuple[str, httpx.Response, float]:
    started = time.perf_counter()
    resp = await client.request(method, path, **kwargs)
    elapsed_ms = (time.perf_counter() - started) * 1000
    return f"{method} {path}", resp, elapsed_ms


def _build_ssl_context() -> ssl.SSLContext:
    """Client-side SSLContext: verify server with our CA, present our client cert.

    httpx 0.28 deprecated the ``cert=(crt, key)`` and ``verify=<path>`` kwargs
    on AsyncClient in favour of passing an ``ssl.SSLContext`` directly.
    Keeping both identity and trust material on one explicit context also
    makes the security posture easier to audit.
    """
    # SECURITY: purpose=SERVER_AUTH is correct — we are the client validating
    # a server. Never flip to check_hostname=False or verify_mode=CERT_NONE;
    # that would defeat the "client trusts server's identity" side of mTLS.
    ctx = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH, cafile=str(CA_CERT)
    )
    ctx.load_cert_chain(certfile=str(CLIENT_CERT), keyfile=str(CLIENT_KEY))
    return ctx


async def main() -> int:
    for path in (CA_CERT, CLIENT_CERT, CLIENT_KEY):
        if not path.is_file():
            print(f"[SETUP-FAIL] missing {path}", file=sys.stderr)
            return 2

    async with httpx.AsyncClient(
        base_url=BASE_URL,
        verify=_build_ssl_context(),
        timeout=5.0,
    ) as client:
        try:
            tasks = [
                asyncio.create_task(_call(client, "GET", "/health")),
                asyncio.create_task(_call(client, "GET", "/data")),
                asyncio.create_task(
                    _call(
                        client,
                        "POST",
                        "/data",
                        json={"sensor_id": "temp-async", "value": 24.5, "unit": "C"},
                    )
                ),
            ]

            # Contract checks keyed by label.
            contracts = {
                "GET /health": lambda p: (
                    p.get("status") == "ok" and p.get("tls") is True
                ),
                "GET /data": lambda p: "readings" in p and "generated_at" in p,
                "POST /data": lambda p: "received" in p and "echoed_at" in p,
            }

            failures = 0
            for fut in asyncio.as_completed(tasks):
                try:
                    label, resp, elapsed_ms = await fut
                except httpx.ConnectError as exc:
                    print(f"[SETUP-FAIL] server not reachable: {exc}", file=sys.stderr)
                    print(
                        "             Start it with: python server.py", file=sys.stderr
                    )
                    return 2

                ok = _assert_ok(label, resp, contracts[label])
                print(f"  elapsed: {elapsed_ms:.1f}ms")
                if not ok:
                    failures += 1

        except httpx.ConnectError as exc:
            print(f"[SETUP-FAIL] connect failed: {exc}", file=sys.stderr)
            return 2

    print()
    if failures == 0:
        print("[PASS] all 3 concurrent endpoints behaved as expected under mTLS.")
        return 0
    print(f"[FAIL] {failures} endpoint(s) did not meet the contract.")
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
