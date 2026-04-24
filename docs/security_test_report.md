# Security Test Report (T6)

Summary of the pentest-style tests in `tests/test_security_pentest.py`.
Each category below lists the attack class, the assertion the test
makes, and — where relevant — the server-side change this phase
shipped to fix a real issue the test surfaced.

## Category 1 — CN Injection

| ID  | Payload                       | Outcome                                        |
|-----|-------------------------------|-----------------------------------------------|
| CI1 | ANSI escape in CN             | Cert signs OR is refused by openssl; if admitted, middleware **sanitises control chars before logging** (fix in middleware.py) |
| CI2 | Newline in CN                 | Same sanitisation path; no forged second log line |
| CI3 | CN with dotted suffix         | 403 — allowlist is exact match, not startswith |
| CI4 | Null byte in CN               | openssl / Python rejects at tooling layer; skip with proof |
| CI5 | Leading whitespace            | 403 — no strip() bypass                        |

**Fix shipped:** `middleware._safe_for_log()` replaces control
characters (< 0x20 and 0x7F) with `\xHH` escapes before any logger
call. Raw CN is still stored on `request.state.client_cn` —
downstream code is unchanged.

## Category 2 — Allowlist Bypass

| ID  | Attack                             | Outcome                                |
|-----|------------------------------------|----------------------------------------|
| AB1 | Uppercase CN                       | 403 (allowlist case-sensitive)         |
| AB2 | Identical-bytes Unicode CN         | 200 (documents no normalisation)       |
| AB3 | Multiple CNs, rogue first          | `extract_cn` returns first — covered by unit test |
| AB4 | Glob-pattern CN                    | 403 (allowlist is a set, not a glob)   |

## Category 3 — Information Disclosure

| ID  | Scenario                               | Outcome                                |
|-----|----------------------------------------|----------------------------------------|
| ID1 | 404 response                           | **No `server: uvicorn` header** (fix shipped) |
| ID2 | 422 response                           | No traceback / source path in body     |
| ID3 | Failed TLS handshake                   | Socket closed; no HTTP banner          |
| ID4 | Timing delta allow vs deny             | Median < 10ms                          |

**Fix shipped:** `server.py` now starts uvicorn with
`server_header=False, date_header=False`. The product-name +
version leak was a genuine fingerprinting primitive the tests
uncovered.

## Category 4 — Request Smuggling

| ID  | Payload                                    | Outcome                         |
|-----|--------------------------------------------|---------------------------------|
| RS1 | Both Content-Length and Transfer-Encoding  | 4xx or connection drop          |
| RS2 | Chunked body with immediate zero-chunk     | Graceful handling, no 5xx       |
| RS3 | Line folding in headers                    | Server does not 5xx; may accept, reject, or drop the folded line (h11 behaviour) |

## Category 5 — Cert Pinning Bypass

| ID  | Attack                                  | Outcome                            |
|-----|-----------------------------------------|------------------------------------|
| PP1 | Off-by-one-byte pin                     | `pinned_client.py` exit code != 0  |
| PP2 | No pin source at all                    | Fails closed with clear message    |
| PP3 | MD5 digest instead of SHA-256           | Length / mismatch rejection        |

## Category 6 — Log Injection and Audit Trail

| ID  | Attack                                     | Outcome                            |
|-----|--------------------------------------------|------------------------------------|
| LI1 | Newline in X-Request-ID                    | Client-side rejection (requests / urllib3); raw-socket variant asserts server does NOT log `[CRITICAL] fake log entry` |
| LI2 | 10 requests from same client               | 10 distinct X-Request-IDs          |
| LI3 | Single request ID round-trip               | Same ID appears ≥ 2 times in log (req_start + req_end) |

## Real issues fixed in T6

1. **Uvicorn server header leak (ID1).** Default response included
   `server: uvicorn` — valuable fingerprinting primitive. Turned off
   via `server_header=False` in `uvicorn.Config`.
2. **CN log injection (CI1).** Middleware logged the raw CN; ANSI
   escapes and newlines could forge log output. Added
   `middleware._safe_for_log` that hex-escapes controls.

## How to run the suite

```bash
pytest -m security tests/test_security_pentest.py
```

Produces a clean run (~20s). The attack strings live in
`tests/attack_payloads.py` — change payloads there, not in the
test functions, so the full matrix stays unified.
