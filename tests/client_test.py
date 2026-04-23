"""Synchronous mTLS client — positive-path smoke test using ``requests``.

Exercises the three Phase-2/3 endpoints with the Phase-1 client cert and
verifies the server against the Phase-1 CA. Prints status and JSON for
each call. Uses ``requests.Session`` so the TLS handshake / connection
is reused across calls (SKILL-04 rule).

Exit codes:
    0   all three endpoints returned 2xx
    1   one or more endpoints returned a non-2xx or mismatched payload
    2   the server was unreachable (setup problem — not a test failure)

Run:
    python tests/client_test.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import requests

# --- Paths (relative to this file) ------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
PKI_DIR = REPO_ROOT / "pki"

CA_CERT = PKI_DIR / "ca" / "ca.crt"
CLIENT_CERT = PKI_DIR / "client" / "client.crt"
CLIENT_KEY = PKI_DIR / "client" / "client.key"

BASE_URL = "https://localhost:8443"


def _print_result(label: str, resp: requests.Response) -> None:
    try:
        payload: Any = resp.json()
        body_str = json.dumps(payload, indent=2)
    except json.JSONDecodeError:
        body_str = resp.text
    print(f"\n=== {label} ===")
    print(f"  HTTP {resp.status_code}")
    print(f"  X-Request-ID: {resp.headers.get('X-Request-ID', '-')}")
    print(f"  body: {body_str}")


def main() -> int:
    # Pre-flight: make sure PKI material exists. Fail with exit 2 (setup
    # error) so we don't conflate "server broken" with "test env broken".
    for path in (CA_CERT, CLIENT_CERT, CLIENT_KEY):
        if not path.is_file():
            print(f"[SETUP-FAIL] missing {path}", file=sys.stderr)
            return 2

    session = requests.Session()
    # SECURITY: NEVER verify=False. The CA file is the sole trust anchor
    # for verifying the SERVER's cert; without this the client would
    # happily talk to any TLS endpoint on localhost:8443.
    session.verify = str(CA_CERT)
    # Client identity presented during the handshake. Skills rule:
    # cert tuple, no intermediate material.
    session.cert = (str(CLIENT_CERT), str(CLIENT_KEY))

    failures = 0

    try:
        r_health = session.get(f"{BASE_URL}/health", timeout=5)
    except requests.exceptions.ConnectionError as exc:
        print(f"[SETUP-FAIL] server not reachable: {exc}", file=sys.stderr)
        print("             Start it with: python server.py", file=sys.stderr)
        return 2

    _print_result("GET /health", r_health)
    if r_health.status_code != 200 or r_health.json().get("tls") is not True:
        failures += 1

    r_data = session.get(f"{BASE_URL}/data", timeout=5)
    _print_result("GET /data", r_data)
    if r_data.status_code != 200 or "readings" not in r_data.json():
        failures += 1

    r_post = session.post(
        f"{BASE_URL}/data",
        json={"sensor_id": "temp-test", "value": 42.0, "unit": "C"},
        timeout=5,
    )
    _print_result("POST /data", r_post)
    if r_post.status_code != 200 or "echoed_at" not in r_post.json():
        failures += 1

    print()
    if failures == 0:
        print("[PASS] all 3 endpoints behaved as expected under mTLS.")
        return 0
    print(f"[FAIL] {failures} endpoint(s) did not meet the contract.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
