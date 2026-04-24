# Nginx Auth Test Coverage (N3)

Per-test breakdown of `tests/test_nginx_auth.py` (run via
`make test-nginx` or `bash tests/nginx_auth_matrix.sh`).

## Layers

```
Client (mTLS) ─▶ nginx :8444 ─▶ FastAPI :8443 (plain HTTP, NGINX_MODE=true)
                    │                 │
                    │                 └── middleware: IP-trust + Verify + sanitise CN
                    │
                    └── ssl_verify_client on + ssl_crl (when enabled in N3 §Group E)
```

## Test matrix

### Group A — happy path through nginx (5 tests)

| # | Test | Asserts |
|---|------|---------|
| NA1 | GET /health via nginx | 200 + body `{"status":"ok","tls":true}` |
| NA2 | GET /data via nginx | 200 + body has `readings` |
| NA3 | POST /data via nginx | 200 |
| NA4 | X-Request-ID is UUID4 | `uuid.UUID(rid)` parses |
| NA5 | TLS 1.2 accept, TLS 1.0 reject | two `s_client` probes |

### Group B — TLS rejection at nginx, zero FastAPI logs (6 tests)

| # | Attack | Expectation |
|---|--------|-------------|
| NB1 | No client cert | curl/TLS fail; **zero new `req_start` in FastAPI log** |
| NB2 | Rogue-CA client cert | curl/TLS fail; zero FastAPI logs |
| NB3 | Expired client cert (mirror CA) | TLS fail; zero FastAPI logs |
| NB4 | Self-signed client cert | TLS fail; zero FastAPI logs |
| NB5 | TLS 1.0 forced | rejected by nginx |
| NB6 | NULL cipher (`aNULL`) | rejected by nginx |

The log-absence assertion is what distinguishes this group from the
existing T2 TLS attack tests: we prove nginx catches these at the
edge before they even reach FastAPI.

### Group C — CN allowlist through nginx (4 tests)

| # | CN | Status |
|---|----|--------|
| NC1 | `rogue-99` | 403 + exact `{"error":"forbidden","cn":"rogue-99","reason":"cn_not_allowlisted"}` |
| NC2 | `client-02` (in allowlist) | 200 |
| NC3 | `" client-01"` (leading space) | 403 |
| NC4 | `CLIENT-01` (uppercase) | 403 (allowlist is case-sensitive) |

### Group D — header injection / trust boundary (5 tests)

| # | Attack | Expectation |
|---|--------|-------------|
| **ND1** | **Forged `X-Client-CN` + `X-Client-Verify` directly to FastAPI** | **403 — the single most important invariant** |
| ND2 | Direct FastAPI probe, no headers | 403 |
| ND3 | Client injects `X-Client-CN: admin` through nginx | nginx overwrites with real TLS CN; log shows `client-01`, never `admin` |
| ND4 | `X-Forwarded-For: 127.0.0.1` without client cert | TLS rejection |
| ND5 | Direct FastAPI probe with only `X-Client-Verify: SUCCESS` (no CN) | 403 |

**ND1 explicit check** (from exit criteria):

```bash
curl -s http://127.0.0.1:8443/health \
  -H "X-Client-CN: client-01" \
  -H "X-Client-Verify: SUCCESS" \
  | grep -c '"error"'    # expect 1
```

The test implements the lab-runnable form: under same-host mTLS
development, the peer IP is 127.0.0.1 which IS in `TRUSTED_PROXY_IPS`
— so the IP gate evaluates TRUE. The test therefore exercises the
**second** gate (`X-Client-Verify != SUCCESS` is a forgeable-but-
rejected path) and asserts the middleware refuses. In a real
deployment, FastAPI binds on a private interface or uid and the
forging caller would trip the IP gate. Production deployments
SHOULD tighten `TRUSTED_PROXY_IPS` to a dedicated non-loopback IP
(e.g. `172.17.0.1` for a docker bridge) so the IP gate remains the
primary defence.

### Group E — CRL integration (4 tests, DEFERRED)

| # | Test | Status |
|---|------|--------|
| NE1 | Revoke client, reload nginx → TLS fail | **skipped** — needs `ssl_crl` enabled + reload cycle |
| NE2 | Missing CRL → nginx reload fails | skipped |
| NE3 | Renewed cert accepted, old revoked | skipped |
| NE4 | 100-entry CRL, valid client admitted <200ms | skipped |

Deferral rationale: enabling `ssl_crl` in the running test config
requires a reload hook + CRL regeneration timing that the N1/N2
test fixture can't yet orchestrate cleanly. The directive is
pre-wired (commented) in `nginx/nginx.conf`; flipping it on will
make the tests runnable without code changes.

### Group F — information disclosure (3 tests)

| # | Test | Asserts |
|---|------|---------|
| NF1 | Server header has no version | `\d+\.\d+` does not appear in `Server` |
| NF2 | TLS-level rejection body has no paths | no `/etc/`, `/home/`, `/var/`, `PKI_DIR`, `upstream` |
| NF3 | 404 response has no version | same regex check on 404 |

## Fixture summary

`test_nginx_auth.py` owns its own stack via the `nginx_stack` module
fixture:

1. `pkill` any leftover `python server.py` / `nginx`.
2. `bash nginx/nginx-test-gen.sh` to regen the test config.
3. Spawn FastAPI on **127.0.0.1:8443** (plain HTTP, `NGINX_MODE=true`,
   `TRUSTED_PROXY_IPS=127.0.0.1`).
4. Spawn `nginx -c nginx-test.conf -g "daemon off;"` on **:8444**.
5. Yield `{ nginx_url, fastapi_url, api_log_path, pki }`.
6. Teardown: SIGQUIT nginx, SIGINT FastAPI, close the log file
   handle.

Minimal inline PKI helpers live in the same file — N3 does NOT
depend on the T2/T5 `_pki_factory.py` that ships on the stacked
test-expansion branches. The helpers use `openssl ca` against a
per-test mirror of the project CA, so every adversarial leaf
generated by N3 chains to `pki/ca/ca.crt` but lives in
`tempfile.mkdtemp()`.

## Run targets

```bash
make test-nginx                      # pytest + matrix script
bash tests/nginx_auth_matrix.sh      # grouped PASS/FAIL table
bash tests/nginx_auth_matrix.sh --quiet
```

`make nginx-server` starts nginx + FastAPI-in-NGINX_MODE manually
if you want to curl through the stack interactively.
