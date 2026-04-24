# v1.2 — Nginx-Only Authentication

Paste this into the GitHub Wiki as a sibling to
["Nginx-Termination-v1-1"](Nginx-Termination-v1-1). The v1.1 page
documents the hybrid architecture that v1.2 was written to replace;
keeping both pages side-by-side makes the architecture shift easy to
trace.

## tl;dr

v1.2 moves **all** authentication and authorization into nginx.
FastAPI is now completely auth-blind — it serves plain HTTP on
`127.0.0.1:8443` and never parses a client certificate, never reads
an `X-Client-*` header, never consults an allowlist.

This change is enforced at three levels:

1. **Structural.** `middleware.py` and `tls.py` are deleted.
   `config.py` is an empty stub. `server.py` is a plain uvicorn
   process. Pytest suite `test_v12_structural.py` fails CI if any of
   these regress.
2. **Behavioural.** The SP1-SP8 plain-FastAPI tests (`test_server_plain.py`)
   probe FastAPI with spoofed headers and assert it produces identical
   output to clean requests.
3. **Architectural.** The nginx config (`nginx/nginx.conf`) carries the
   CN allowlist in a `map{}` block. nginx returns the canonical 403
   JSON body directly; the upstream is never contacted for denied
   requests.

## Architecture

```
┌──────────────┐ mTLS +           ┌──────────────┐  plain HTTP
│              │ client-01/02     │              │  127.0.0.1:8443
│   client     ├────────────────► │   nginx      ├────────────────►   FastAPI
│              │                  │   :8444      │                    (auth-blind)
└──────────────┘                  └──────┬───────┘
                                         │
                                         │ deny paths:
                                         │   • no cert       → 400
                                         │   • invalid cert  → 400
                                         │   • revoked cert  → 400
                                         │   • rogue CN      → 403 JSON
                                         │  (none reach FastAPI)
                                         ▼
```

The deny branches never dial the upstream — that's the v1.2 invariant.
NP2 in `test_nginx_perf.py` measures this: deny-at-nginx costs 418 µs
on localhost versus 832 µs for an allow path that round-trips through
Python.

## Why the rewrite?

v1.1 shipped a hybrid where nginx terminated TLS **and** FastAPI
re-enforced the CN allowlist via middleware. Two real problems:

1. **Two sources of truth for the allowlist** — the nginx config had
   to stay in sync with `config.ALLOWED_CLIENT_CNS`. Drift between
   them was the v1.1 operational risk.
2. **Header-trust machinery.** FastAPI trusted `X-Client-CN` headers
   from nginx, guarded by a `TRUSTED_PROXY_IPS` list. That gate
   itself became auth surface. The ND1 test existed specifically
   to prove the gate held against forged headers.

v1.2 eliminates both by making nginx the sole boundary. There is no
second allowlist and no header trust — which means there is nothing
to bypass and no ND1 test is needed.

## The allowlist lives in nginx.conf

```nginx
# Parse CN out of the full client Subject DN
# (OSS nginx doesn't expose $ssl_client_s_dn_cn — that's Plus).
map $ssl_client_s_dn $ssl_client_cn {
    ~(?:^|,)\s*CN=(?<cn>[^,]+) $cn;
    default                    "";
}

# THIS is the authorization policy.
map $ssl_client_cn $cn_allowed {
    default       0;
    "client-01"   1;
    "client-02"   1;
}

server {
    listen 8444 ssl;
    ssl_verify_client on;
    ssl_crl /path/to/pki/ca/ca.crl;
    ...
    location / {
        if ($cn_allowed = 0) {
            add_header Content-Type application/json always;
            return 403 '{"error":"forbidden","cn":"$ssl_client_cn","reason":"cn_not_allowlisted"}';
        }
        proxy_pass http://127.0.0.1:8443;
        ...
    }
}
```

To admit a new client:

1. Add the CN to the `$cn_allowed` map.
2. `make nginx-reload` (SIGHUP — no restart, no dropped connections).

NC5 in `test_nginx_auth.py` verifies the live-reload lane. No Python
deploy. No restart.

## Test coverage at a glance

| Module | Count | Role |
|--------|-------|------|
| `test_nginx_auth.py` | 23 | end-to-end allow/deny matrix + live reload |
| `test_server_plain.py` | 9 | plain-FastAPI contract + log discipline |
| `test_v12_structural.py` | 4 | source-level invariant enforcement |
| `test_nginx_perf.py` | 3 | baseline / deny / 1000-CN scaling |
| `test_nginx_concurrency.py` | 3 | 50× concurrent allow/deny/mixed |
| **Total** | **42** | Full suite runs in ~6-7 s on loopback |

Plus `nginx_locustfile_v2.py` for headless Locust runs with a p95 <
30 ms SLO gate.

## Running locally

```bash
# one-time
python -m venv venv && source venv/bin/activate
pip install -r requirements-dev.txt

make pki            # CA + server + nginx + client certs
make stack          # starts FastAPI plain :8443 + nginx mTLS :8444
curl --cacert pki/ca/ca.crt \
     --cert   pki/client/client.crt \
     --key    pki/client/client.key \
     https://localhost:8444/health
# {"status":"ok"}

make nginx-stop && make stop

# full test suite
pytest tests/ -v
```

## Common operations

| Task | Command |
|------|---------|
| Add/remove a CN from the allowlist | edit `nginx/nginx.conf`, then `make nginx-reload` |
| Revoke a client cert | `make revoke` then `make nginx-reload` |
| Rotate a client cert (24h-lived) | `make renew` |
| Fingerprint the nginx cert (for pinning) | `make pin` → `pki/nginx/nginx.fingerprint` |
| Full regen (CA + all leaves) | `make clean && make pki` |

## What NOT to do

Listed in `config.py`'s docstring and enforced by ST2/ST3:

* Do not add an allowlist, trusted-proxy-IP list, or NGINX_MODE flag
  to `config.py`.
* Do not reintroduce `ssl.SSLContext`, `ssl_keyfile`, peer-cert
  parsing, or any `X-Client-*` header read in `server.py`.
* Do not resurrect `middleware.py` or `tls.py`.

Each of these produces a CI failure in the `structural-check` job.

## Related pages

- [Nginx-Termination-v1-1](Nginx-Termination-v1-1) — predecessor
  architecture; retained for history.
- [Test-Suite-Expansion](Test-Suite-Expansion) — broader test-suite
  context (T1-T10).
- `docs/nginx_architecture_v2.md` in the repo — in-tree companion to
  this page; edit both when the architecture shifts.
