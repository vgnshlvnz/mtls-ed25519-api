# SDK Integration Guide

Working client recipes for the four most common Python HTTP
libraries. Every example is covered by a test in
`tests/test_realworld_scenarios.py::test_SDK*_…` — copy the code
below verbatim and you will get an authenticated 200.

> `MTLS_CERT`, `MTLS_KEY`, `MTLS_CA` are the 12-factor env-var
> names the test suite uses. Substitute real paths / secrets
> management for a production deployment.

## 1. `requests.Session` with env-var config (SDK1)

```python
import os
import requests

session = requests.Session()
session.verify = os.environ["MTLS_CA"]
session.cert = (os.environ["MTLS_CERT"], os.environ["MTLS_KEY"])

r = session.get("https://api.example.com/health", timeout=5)
r.raise_for_status()
print(r.json())
```

SECURITY: `verify` is the CA path; `cert` is the `(cert, key)`
tuple. Never set `verify=False`.

## 2. `httpx.Client` with explicit `ssl.SSLContext` (SDK2)

httpx 0.28 deprecated the `verify=<path>` / `cert=(...)` kwargs in
favour of passing an `ssl.SSLContext`. This is the supported path
going forward.

```python
import os
import ssl
import httpx

ctx = ssl.create_default_context(
    purpose=ssl.Purpose.SERVER_AUTH,
    cafile=os.environ["MTLS_CA"],
)
ctx.load_cert_chain(
    certfile=os.environ["MTLS_CERT"],
    keyfile=os.environ["MTLS_KEY"],
)

with httpx.Client(verify=ctx, timeout=5) as client:
    r = client.get("https://api.example.com/health")
    r.raise_for_status()
```

Same context works for `httpx.AsyncClient`:

```python
async with httpx.AsyncClient(verify=ctx, timeout=5) as client:
    r = await client.get("https://api.example.com/health")
```

## 3. `aiohttp` with `ssl.SSLContext` (SDK3)

```python
import asyncio
import os
import ssl
import aiohttp

ctx = ssl.create_default_context(
    purpose=ssl.Purpose.SERVER_AUTH,
    cafile=os.environ["MTLS_CA"],
)
ctx.load_cert_chain(
    certfile=os.environ["MTLS_CERT"],
    keyfile=os.environ["MTLS_KEY"],
)

async def fetch() -> dict:
    connector = aiohttp.TCPConnector(ssl=ctx)
    async with aiohttp.ClientSession(connector=connector) as sess:
        async with sess.get(
            "https://api.example.com/health",
            timeout=aiohttp.ClientTimeout(total=5),
        ) as resp:
            resp.raise_for_status()
            return await resp.json()

asyncio.run(fetch())
```

## 4. `urllib3.PoolManager` direct (SDK4)

urllib3 is what `requests` wraps. Using it directly is useful
when you want to skip `requests`' session-scoped defaults.

```python
import os
import urllib3

http = urllib3.PoolManager(
    cert_reqs="CERT_REQUIRED",
    ca_certs=os.environ["MTLS_CA"],
    cert_file=os.environ["MTLS_CERT"],
    key_file=os.environ["MTLS_KEY"],
)
r = http.request("GET", "https://api.example.com/health", timeout=5)
assert r.status == 200
```

---

## Cert-pinning stretch (optional)

For clients that want to pin the server cert's SHA-256 fingerprint
(not just trust any cert signed by the CA):

```python
import hashlib
import ssl
import socket

pin = os.environ["MTLS_PIN"].replace(":", "").lower()  # 64 hex chars

ctx = ssl.create_default_context(
    purpose=ssl.Purpose.SERVER_AUTH,
    cafile=os.environ["MTLS_CA"],
)
ctx.load_cert_chain(os.environ["MTLS_CERT"], os.environ["MTLS_KEY"])

with socket.create_connection(("api.example.com", 443)) as raw:
    with ctx.wrap_socket(raw, server_hostname="api.example.com") as tls:
        der = tls.getpeercert(binary_form=True)
        seen = hashlib.sha256(der).hexdigest()
        if seen != pin:
            raise RuntimeError(f"pin mismatch: saw {seen}, expected {pin}")
        # now safe to speak HTTP over `tls`
```

Full reference implementation lives in `pinned_client.py` in this
repo.

---

## What NEVER to write

```python
# NEVER — bypasses the whole mTLS contract
requests.get(url, verify=False)

# NEVER — server trust-chain anchor is lost
ctx.verify_mode = ssl.CERT_NONE
ctx.check_hostname = False

# NEVER — sets the wrong purpose and breaks hostname checking
ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
```

The project pre-commit hook greps for these patterns on every
commit, and T6 CI1-CI5 block them at review time.
