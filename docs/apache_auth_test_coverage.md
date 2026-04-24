# Apache auth test coverage (v1.3)

Reference table for `tests/test_apache_auth.py`. The ENFORCED_BY
column is uniformly "Apache" — that's the v1.3 architectural invariant
in tabular form. FastAPI never enforces auth; if any row's enforcer
ever shifts to "FastAPI", the structural test suite catches it before
that test even has a chance to fail at runtime.

## Group A — happy path (5 tests)

| Test ID | What it asserts | ENFORCED_BY | Layer |
|---------|------------------|-------------|-------|
| AA1 | GET /health returns 200 + `{"status":"ok"}` | Apache | TLS + RewriteMap allow + proxy |
| AA2 | GET /data returns 200 + 2 readings | Apache | same |
| AA3 | POST /data echoes body + stamps echoed_at | Apache | same |
| AA4 | X-Request-ID is minted (32-char uuid hex) | Apache | proxy preserves request-id |
| AA5 | TLS 1.2 accepted, TLS 1.0 rejected | Apache | mod_ssl `SSLProtocol` |

## Group B — Apache TLS / HTTP rejection (6 tests)

Each test asserts both the rejection signal AND that FastAPI's
`req_start` count does not increment.

| Test ID | What it asserts | ENFORCED_BY | Layer |
|---------|------------------|-------------|-------|
| AB1 | No client cert → TLS abort or 4xx (NEVER 2xx) | Apache | `SSLVerifyClient require` |
| AB2 | Untrusted-CA cert → handshake failure | Apache | mod_ssl chain verify |
| AB3 | Expired cert → handshake failure | Apache | mod_ssl notAfter check |
| AB4 | Self-signed cert (no CA) → handshake failure | Apache | mod_ssl chain verify |
| AB5 | TLS 1.0 forced → handshake failure | Apache | `SSLProtocol -all +TLSv1.2 +TLSv1.3` |
| AB6 | Revoked cert → handshake failure | Apache | `SSLCARevocationCheck chain` |

## Group C — RewriteMap CN allowlist (5 tests)

**CRITICAL:** every Group C test asserts FastAPI's `req_start` count
is unchanged. If any row fails, Apache let a denied request through
to the upstream — a v1.3 invariant violation.

| Test ID | What it asserts | ENFORCED_BY | Layer |
|---------|------------------|-------------|-------|
| AC1 | Rogue CN (client-99, valid chain) → 403 + canonical JSON + X-Rejected-CN header + log absence | Apache | mod_rewrite + RewriteMap |
| AC2 | Second allowlist entry (client-02) admitted | Apache | RewriteMap (multi-key) |
| AC3 | Leading whitespace CN → 403 + log absence | Apache | RewriteMap exact-key match |
| AC4 | Uppercase CN → 403 + log absence | Apache | RewriteMap case-sensitive |
| AC5 | Graceful reload propagates new CN | Apache | apachectl graceful + new workers |

## Group D — information disclosure (4 tests)

| Test ID | What it asserts | ENFORCED_BY | Layer |
|---------|------------------|-------------|-------|
| AD1 | Server header is exactly "Apache" (no version) | Apache | `ServerTokens Prod` |
| AD2 | RewriteMap 403 body is JSON + Content-Type matches | Apache | ErrorDocument + Header |
| AD3 | TLS rejection responses don't leak filesystem paths | Apache | static error pages |
| AD4 | 404 response also has no version disclosure | Apache | ServerTokens Prod (consistent) |

## Group E — concurrency (2 tests)

| Test ID | What it asserts | ENFORCED_BY | Layer |
|---------|------------------|-------------|-------|
| AE1 | 20 concurrent valid clients → all 200 in < 5s | Apache | MPM event + worker pool |
| AE2 | 5 sequential requests on same connection → all 200 | Apache | KeepAlive On |

## Group F — Apache-specific (5 tests; no nginx equivalent)

| Test ID | What it asserts | ENFORCED_BY | Apache-only because |
|---------|------------------|-------------|-------|
| AF1 | %{SSL_CLIENT_S_DN_CN} returns clean CN (no "CN=" prefix, no whitespace) | Apache | nginx OSS lacks this variable; needs regex |
| AF2 | No-cert response code is NOT 2xx | Apache | nginx returns HTTP 400; Apache returns TLS abort |
| AF3 | Concurrent requests from 2 different CNs preserve identity | Apache | Apache MPM has per-process state |
| AF4 | apachectl graceful preserves in-flight requests | Apache | nginx -s reload also does this, but mechanism differs |
| AF5 | SSLCARevocationCheck=chain rejects on intermediate revocation | Apache | nginx ssl_crl is leaf-only by default |

## Cross-cut: log-absence structural invariant

| Test ID | What it asserts | ENFORCED_BY |
|---------|------------------|-------------|
| `test_apache_owns_the_allowlist_log_absence` | Rogue CN reaches Apache, gets 403, never reaches FastAPI | Apache (proven by FastAPI log inspection) |

## Coverage summary

```
Group A — happy path                    5/5  PASS
Group B — TLS / HTTP rejection          6/6  PASS
Group C — RewriteMap CN allowlist       5/5  PASS  (all with log-absence)
Group D — information disclosure        4/4  PASS
Group E — concurrency                   2/2  PASS
Group F — Apache-specific               4/5  PASS  (1 skipped: AF5 multi-CA fixture pending)
Cross-cut log-absence                   1/1  PASS

Total                                  27/28 PASS  (28th = AF5 skipped)
```

ENFORCED_BY = Apache for **every** row. That's the v1.3 architectural
invariant in test form: no test in this file expects FastAPI to
participate in authentication or authorization. If any row ever flips
to ENFORCED_BY = FastAPI, that's the moment v1.3 has degraded back to
the v1.1 hybrid model.

## Cross-reference

- `tests/test_apache_auth.py` — the test file
- `tests/apache_auth_matrix.sh` — wrapper that runs all groups + prints PASS/FAIL table
- `docs/apache_vs_nginx_behaviour.md` — runtime behaviour differences
- `docs/apache_vs_nginx_cn_extraction.md` — config mechanics differences
