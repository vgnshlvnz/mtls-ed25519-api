"""client_test.py — synchronous mTLS client smoke test for v1.3 Apache.

v1.3: auth is entirely at Apache httpd. FastAPI :8443 is plain HTTP.
This script hits the Apache test rig on :8445 (https) using the
project's client-01 cert + project CA. Three contract checks across
the three endpoints; non-zero exit if any contract regressed.

Exit codes (same as v1.0):
    0   all three endpoints returned 2xx AND matched the contract
    1   at least one endpoint missed the contract
    2   server unreachable (setup problem; not a test failure)

Run:
    python tests/client_test.py

The companion async client (httpx) was deleted in v1.2 alongside the
rest of the legacy mTLS-direct test surface. This sync version is
kept because (a) it was a useful smoke and (b) it's the simplest
demonstration of how a Python caller talks to the v1.3 stack.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import requests


REPO_ROOT = Path(__file__).resolve().parent.parent
APACHE_PORT = int(os.environ.get("APACHE_HTTPS_PORT", "8445"))
BASE_URL = f"https://localhost:{APACHE_PORT}"

CA = str(REPO_ROOT / "pki" / "ca" / "ca.crt")
CRT = str(REPO_ROOT / "pki" / "client" / "client.crt")
KEY = str(REPO_ROOT / "pki" / "client" / "client.key")


def _check(name: str, ok: bool, detail: str = "") -> bool:
    marker = "[PASS]" if ok else "[FAIL]"
    sys.stdout.write(f"{marker} {name}{(' — ' + detail) if detail else ''}\n")
    return ok


def main() -> int:
    session = requests.Session()
    session.verify = CA
    session.cert = (CRT, KEY)

    try:
        # /health
        r = session.get(f"{BASE_URL}/health", timeout=5.0)
        body = r.json()
        ok_health = r.status_code == 200 and body.get("status") == "ok"
        _check(
            f"GET /health → {r.status_code} {body!r}",
            ok_health,
        )

        # /data
        r = session.get(f"{BASE_URL}/data", timeout=5.0)
        body = r.json()
        ok_data = (
            r.status_code == 200
            and "readings" in body
            and "generated_at" in body
            and len(body["readings"]) == 2
        )
        _check(
            f"GET /data → {r.status_code} (readings={len(body.get('readings', []))})",
            ok_data,
        )

        # /data POST
        payload = {"sensor_id": "smoke-test", "value": 42}
        r = session.post(
            f"{BASE_URL}/data",
            json=payload,
            timeout=5.0,
        )
        body = r.json()
        ok_post = (
            r.status_code == 200
            and body.get("received") == payload
            and "echoed_at" in body
        )
        _check(
            f"POST /data → {r.status_code} (echoed_at={body.get('echoed_at')!r})",
            ok_post,
        )

    except requests.exceptions.ConnectionError as exc:
        sys.stderr.write(
            f"[SETUP] cannot reach {BASE_URL} — is `make apache-server` running?\n"
            f"        underlying error: {exc!r}\n"
        )
        return 2

    if all((ok_health, ok_data, ok_post)):
        sys.stdout.write("\nAll 3 v1.3 endpoint contracts hold.\n")
        return 0

    sys.stderr.write("\nOne or more contracts failed — see [FAIL] lines above.\n")
    sys.stderr.write(f"Last response body for context:\n{json.dumps(body, indent=2)}\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
