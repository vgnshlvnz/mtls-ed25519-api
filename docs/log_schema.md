# Log Schema

Every log line emitted by the server is a single-line JSON object.
The emitter lives in `logging_config.py::JsonFormatter`. This
document is the contract: tests in `tests/test_observability.py`
enforce it; a change here must land in the same commit as the
code + test change.

## Common fields (every record)

| Field        | Type   | Description                                   |
|--------------|--------|-----------------------------------------------|
| `timestamp`  | string | ISO 8601 UTC                                  |
| `level`      | string | INFO / WARNING / ERROR / CRITICAL             |
| `logger`     | string | Python logger name (mtls_api / middleware / tls / uvicorn) |
| `message`    | string | Human-readable summary                        |
| `event`      | string | Machine-readable slug (see below)             |

## Events

### Request lifecycle (middleware.py)

| `event`          | Level    | Fields                                                                   |
|------------------|----------|--------------------------------------------------------------------------|
| `req_start`      | INFO     | `method`, `path`, `cn`, `subj`, `reqid`, `peer`                          |
| `req_end`        | INFO     | `method`, `path`, `cn`, `reqid`, `status`                                |
| `authz_reject`   | WARNING  | `reason`, `cn`?, `subj`?, `reqid`, `peer`                                |
| `req_error`      | ERROR    | `reqid`, exception text (internal only — never leaked to client)         |

`cn` is the Subject CommonName, safely escaped via
`middleware._safe_for_log` so control characters in a malicious CN
can't forge log lines.

### TLS layer (server.py)

| `event`                  | Level    | Fields                    |
|--------------------------|----------|---------------------------|
| `tls_handshake_failed`   | WARNING  | coarse `reason` + `library` (no cert detail, no peer CN) |
| `tls_context`            | INFO     | `mode`, `min_version`, `ciphers` (count)                 |
| `crl_loaded`             | INFO     | `path`, `mode`                                           |
| `crl_disabled`           | INFO     | (when no CRL configured)                                 |
| `crl_refreshed`          | INFO     | `path`                                                   |
| `crl_refresh_skipped`    | WARNING  | `reason`                                                 |
| `crl_refresh_failed`     | WARNING  | `reason` / `exit` + `stderr` (first 400 chars)           |
| `server_cert_near_expiry`| WARNING  | `remaining_days`, `not_after`                            |

### Server lifecycle (server.py)

| `event`           | Level | Fields                                                 |
|-------------------|-------|--------------------------------------------------------|
| `server_started`  | INFO  | `bind_addr`, `tls_version_min`, `cert_expiry_days`     |

The `server_started` line is the operations-friendly "ready"
marker — log tailing tools can pin on it without guessing at
uvicorn's banner.

## Secret-material invariant

No log line ever contains:

* `-----BEGIN (…) PRIVATE KEY-----` headers
* `-----BEGIN CERTIFICATE-----` blocks
* raw cert DER bytes
* raw peer-cert dict (full `getpeercert()` output)

The pre-commit hook (`.pre-commit-config.yaml`) plus
`tests/test_observability.py::test_L7_no_private_key_material_appears_in_log`
enforce this structurally.

## Example records

```json
{"timestamp":"2026-04-24T12:13:37.123+00:00","level":"INFO","logger":"middleware","message":"req_start","event":"req_start","method":"GET","path":"/health","cn":"client-01","subj":"cdb5a77ca6fc0cf2","reqid":"abc…","peer":"127.0.0.1"}
{"timestamp":"2026-04-24T12:13:37.128+00:00","level":"INFO","logger":"middleware","message":"req_end","event":"req_end","method":"GET","path":"/health","cn":"client-01","reqid":"abc…","status":200}
{"timestamp":"2026-04-24T12:13:45.200+00:00","level":"WARNING","logger":"middleware","message":"authz_reject","event":"authz_reject","reason":"cn_not_allowlisted","cn":"client-evil","subj":"…","reqid":"…","peer":"127.0.0.1"}
```

## Ingest tips

* `jq -c 'select(.level=="WARNING")'` — auth + TLS failure stream.
* `jq -c 'select(.event=="req_end" and .status>=500)'` — 5xx watch.
* `jq -c 'select(.event=="server_started")'` — deploy marker.
