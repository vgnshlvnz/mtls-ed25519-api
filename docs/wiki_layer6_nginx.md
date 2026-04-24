# Wiki update — Layer 6 (nginx auth)

Ready-to-paste content for the [Test Suite Expansion](https://github.com/vgnshlvnz/mtls-ed25519-api/wiki/Test-Suite-Expansion)
or [Home](https://github.com/vgnshlvnz/mtls-ed25519-api/wiki/Home)
wiki page. Add the Layer 6 row to the TL;DR table, then paste the
`## Layer 6 — nginx auth chain` section under the existing Layer 5
content. Also update the "What is NOT tested" table row for "reverse
proxy / mTLS termination".

---

## Layer 6 — nginx auth chain

Introduced in v1.1 alongside the nginx termination layer (phases N1–N5).
All tests run against a live nginx subprocess on `:8444` forwarding
plain HTTP to FastAPI on `:8443` (bound to `127.0.0.1` only).

### Subgroup matrix

| Layer | File | Count | Style |
|-------|------|-------|-------|
| 6a Happy path            | `test_nginx_auth.py` Group A | 5 | Real nginx, real mTLS — `NA1..NA5` |
| 6b TLS rejection         | `test_nginx_auth.py` Group B | 6 | Handshake fail + zero FastAPI log entries — `NB1..NB6` |
| 6c CN allowlist via nginx| `test_nginx_auth.py` Group C | 4 | nginx->FastAPI chain — `NC1..NC4` |
| 6d Header injection      | `test_nginx_auth.py` Group D | 5 | **Adversarial; ND1 is critical** |
| 6e CRL via nginx         | `test_nginx_auth.py` Group E | 4 | deferred — documented in `docs/nginx_auth_test_coverage.md` |
| 6f Information disclosure| `test_nginx_auth.py` Group F | 3 | Response header audit — `NF1..NF3` |

### ND1 — the critical gate

FastAPI on `127.0.0.1:8443` (plain HTTP in `NGINX_MODE=true`) must
**refuse** a request that carries `X-Client-CN: client-01` +
`X-Client-Verify: SUCCESS` when the caller's source IP is not in
`config.TRUSTED_PROXY_IPS`. If that test ever returns HTTP 200,
the nginx integration is insecure — any process that can reach the
plain-HTTP port can forge a CN and bypass auth.

Reproduce manually:

```bash
make stack                         # PKI + nginx + FastAPI (NGINX_MODE=true)
curl -s http://127.0.0.1:8443/health \
  -H "X-Client-CN: client-01" \
  -H "X-Client-Verify: SUCCESS" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); \
                 assert d['error']=='forbidden'"
echo "ND1 PASS"
```

CI enforces it via a dedicated explicit step
(`nginx-auth-tests` → `ND1 CRITICAL — Header Injection Defence
Check` in `.github/workflows/nginx-ci.yml`) so a silent skip of the
pytest case can't sneak through review.

### Performance (from N4 NP1..NP4)

| Bench | Budget | Observed (dev box) |
|-------|:------:|:------------------:|
| NP1  nginx handshake + `/health` | 30 ms | ~3.9 ms |
| NP3  keepalive reuse (per call)  | 5 ms  | ~0.8 ms |
| NP4  `extract_cn_from_headers` x 10k | 50 ms | ~1.7 ms |

nginx does **not** add meaningful per-connection overhead versus
the v1.0 direct-TLS path (~4.5 ms median from T4 PB1). Full
comparison in
[`docs/handshake_cost_comparison.md`](https://github.com/vgnshlvnz/mtls-ed25519-api/blob/main/docs/handshake_cost_comparison.md).

### Security invariants (SI-1..SI-4)

Documented in the middleware module docstring and in
[`docs/nginx_architecture.md`](https://github.com/vgnshlvnz/mtls-ed25519-api/blob/main/docs/nginx_architecture.md):

1. **SI-1** `X-Client-CN` honoured only when source IP ∈ `TRUSTED_PROXY_IPS`
2. **SI-2** `X-Client-Verify` must be the literal string `"SUCCESS"`
3. **SI-3** CN sanitised — whitespace stripped, CR/LF/NUL rejected
4. **SI-4** `NGINX_MODE=true` + empty `TRUSTED_PROXY_IPS` → `sys.exit(2)`

---

## "What is NOT tested" — v1.1 update

Add / amend these rows in the Home page table:

| Area | v1.0 status | After T1–T10 | After v1.1 (nginx) |
|------|-------------|:------------:|:------------------:|
| Reverse proxy / mTLS termination | Not covered. | — | ✅ N1–N5 — nginx config lint, 27 auth tests, 4 benchmarks, CI jobs 9+10 |
| Header trust model (proxy forwarding) | Not applicable. | — | ✅ SI-1..SI-4 enforced in middleware; ND1 locks the invariant |
| Edge CRL enforcement at TLS layer | Python-only. | — | 🟡 `ssl_crl` wired in nginx.conf; NE1..NE4 lifecycle tests deferred |

---

## Invocation / where to find everything

```bash
make test-nginx           # N3 auth suite
make bench-nginx          # N4 benchmarks
make stress-nginx         # N4 concurrency (slow)
make load-test-nginx      # N4 Locust SLO run
make verify-full          # every N1..N4 exit criterion
```

Key docs:

- [`docs/nginx_architecture.md`](https://github.com/vgnshlvnz/mtls-ed25519-api/blob/main/docs/nginx_architecture.md) — topology + trust model
- [`docs/nginx_auth_test_coverage.md`](https://github.com/vgnshlvnz/mtls-ed25519-api/blob/main/docs/nginx_auth_test_coverage.md) — per-test breakdown
- [`docs/handshake_cost_comparison.md`](https://github.com/vgnshlvnz/mtls-ed25519-api/blob/main/docs/handshake_cost_comparison.md) — perf numbers

PRs for the nginx series: [#14 N1](https://github.com/vgnshlvnz/mtls-ed25519-api/pull/14) → [#15 N2](https://github.com/vgnshlvnz/mtls-ed25519-api/pull/15) → [#16 N3](https://github.com/vgnshlvnz/mtls-ed25519-api/pull/16) → [#17 N4](https://github.com/vgnshlvnz/mtls-ed25519-api/pull/17) → #18 N5.
