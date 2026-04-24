# API Contract

Machine-readable contract for the three mTLS REST endpoints. Tests in
`tests/test_api_contracts.py` and `tests/test_api_fuzzing.py` enforce
this document — any change to a shape below must be reflected in
those tests first (or the tests will break on the next `make test`).

## Transport

| Property | Value |
|----------|-------|
| Base URL | `https://127.0.0.1:8443` (override via `MTLS_API_PORT`) |
| Protocol | HTTPS with mutual TLS, `ssl.CERT_REQUIRED` |
| TLS min | 1.2 (server rejects 1.0 / 1.1) |
| Auth | Client cert chains to `pki/ca/ca.crt` + CN in `ALLOWED_CLIENT_CNS` |
| Content-Type (req/resp) | `application/json` |
| Required response header | `X-Request-ID` — UUID-parseable, unique per request |

Error envelope (always JSON, never HTML / text):

```json
{"error": "<stable_slug>", "cn": "<client_cn_or_empty>", "reason": "<slug>"}
```

HTTP codes in use:
- `200` — success
- `403` — CN allowlist / missing peer cert
- `422` — request body failed Pydantic validation
- `4xx` (other) — malformed request envelope (see header-injection tests)

The server MUST NEVER return a 5xx under well-formed mTLS. 500s
indicate an unhandled exception path and are treated as defects.

---

## `GET /health`

**Purpose**: liveness probe; confirms the handshake and reports the
app version so a rolling deploy can be observed from the client side.

### Response schema

```json
{
  "status": "ok",
  "tls": true,
  "version": "0.4.0"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `status` | string, always `"ok"` | Constant — liveness signal |
| `tls` | boolean, always `true` | JSON `true`, not the string `"true"` |
| `version` | string | Matches `app.version` in `server.py` |

**Invariants** (lock-tested in `tests/test_api_contracts.py`):
- Key set is exactly `{status, tls, version}` (H1)
- `status == "ok"` (H2)
- `tls is True` (not a string) (H3)
- `Content-Type` starts with `application/json` (H4)
- `X-Request-ID` parses as UUID (H5)

---

## `GET /data`

**Purpose**: returns a snapshot of mock sensor readings.

### Response schema

```json
{
  "readings": [
    {
      "sensor_id": "temp-01",
      "temperature_c": 22.5,
      "humidity_pct": 41.0,
      "recorded_at": "2026-04-24T18:00:00.000000+00:00"
    },
    ...
  ],
  "generated_at": "2026-04-24T18:00:00.000000+00:00"
}
```

| Field | Type | Notes |
|-------|------|-------|
| `readings` | array, length ≥ 1 | |
| `readings[i].sensor_id` | string, non-empty | Stable identifier for the sensor |
| `readings[i].temperature_c` | number (int or float) | Degrees Celsius |
| `readings[i].humidity_pct` | number (int or float) | Relative humidity, 0–100 |
| `readings[i].recorded_at` | string, ISO 8601 | |
| `generated_at` | string, ISO 8601 | Response-level timestamp |

**Invariants** (D1–D4 in `tests/test_api_contracts.py`):
- `readings` is a non-empty list (D1)
- Every reading has exactly the four keys above (D2)
- `generated_at` parses via `datetime.fromisoformat` (D3)
- Response shape is deterministic across 10 consecutive calls (D4)

---

## `POST /data`

**Purpose**: echo a sensor reading back with a server-side timestamp.

### Request schema (`SensorIn`)

```json
{
  "sensor_id": "temp-test",
  "value": 42.0,
  "unit": "C"
}
```

| Field | Type | Validation |
|-------|------|------------|
| `sensor_id` | string | `min_length=1` |
| `value` | number | float; ints are coerced (P6) |
| `unit` | string | `min_length=1` |

Missing or wrong-typed fields → `422 Unprocessable Entity` (P2/P3/P4).
Extra keys are silently dropped per Pydantic defaults (P5).

### Response schema (`EchoResponse`)

```json
{
  "received": {
    "sensor_id": "temp-test",
    "value": 42.0,
    "unit": "C"
  },
  "echoed_at": "2026-04-24T18:00:00.000000+00:00"
}
```

**Invariants** (P1–P8):
- `200` for a valid body (P1)
- `422` for missing fields, wrong types, non-JSON content type, or `{}` (P2, P3, P4, P7, P8)
- `200` with unknown keys dropped (P5)
- `200` with integer coerced to float (P6)

### Fuzz-test invariants (F1–F8)

- `sensor_id = <any text>`: response ∈ {200, 422}, never 5xx (F1)
- `value = NaN / ±Inf`: consistently rejected or accepted; never 5xx (F2)
- `value = <any signed-64bit int>`: never 5xx (F3)
- arbitrary binary body (up to 64 KiB): response ∈ {200, 400, 413, 422} (F4)
- arbitrary string-to-string dict: never 5xx (F5)
- 10 MiB POST body: responds in <5s with 4xx (F6)
- 100-level nested JSON: never 5xx, never `RecursionError` (F7)
- adversarial unicode `sensor_id` (null bytes, RTL override, SQL/XSS payloads): response ∈ {200, 422} (F8)

### Header-injection invariants (HI1–HI5)

- Null byte in `Host` header: connection drop or 4xx (HI1)
- Newline-injected `X-Forwarded-For`: rejected client-side by `requests`/urllib3 (HI2)
- `Content-Length` larger than body: timeout or 4xx (HI3)
- Malformed `Transfer-Encoding: chunked` body: timeout or 4xx (HI4)
- Duplicate `Content-Type` headers: any status except 5xx (HI5)

---

## Version stability

A change to any **Invariant** above is a contract change and requires:
1. Updating the corresponding test(s) in `tests/test_api_contracts.py` /
   `tests/test_api_fuzzing.py` in the same commit.
2. Bumping `app.version` in `server.py`.
3. Noting the change in the per-phase feature table in `README.md`.
