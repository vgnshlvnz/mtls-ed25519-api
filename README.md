# mTLS REST API with ED25519

A small FastAPI server behind an nginx reverse proxy that enforces
mutual TLS using **ED25519** keys and a self-hosted CA. As of **v1.2**,
nginx is the sole authentication boundary: it terminates mTLS, checks
the CRL, and enforces a CN allowlist via a `map{}` block. FastAPI is
completely auth-blind — plain HTTP on 127.0.0.1:8443, no cert parsing,
no header trust.

The project is built as incremental phases. The v1.0 baseline shipped
FastAPI-direct mTLS. v1.1 introduced nginx as a co-enforcer (hybrid).
v1.2 finished the migration and removed every line of FastAPI-side
auth code — structural tests now fail CI if any of it reappears.

## Quickstart (≤6 commands from a clean clone)

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements-dev.txt
make pki                  # ED25519 CA + server + nginx + client + initial CRL
make stack                # FastAPI plain-HTTP :8443 + nginx mTLS :8444
curl --cacert pki/ca/ca.crt \
     --cert pki/client/client.crt \
     --key  pki/client/client.key \
     https://localhost:8444/health
make test                 # 42 pytest cases, ~6-7s wall-clock
```

`make nginx-stop && make stop` when you're done. `make help` lists
every target. If any command above fails the very first time —
you're not in a venv.

## What nginx enforces (the only auth in v1.2)

Four independent gates, **all** must pass, **all** at nginx:

1. **TLS handshake** — TLS 1.2+ floor, HIGH cipher list, cert chain
   verified against `pki/ca/ca.crt` (`ssl_verify_client on`).
2. **CRL check** — revoked certs produce HTTP 400 post-handshake
   (`ssl_crl` points at `pki/ca/ca.crl`).
3. **CN allowlist** — parsed out of the client Subject DN via one
   `map{}` block, checked against a second `map{}` that is the
   allowlist:
   ```nginx
   map $ssl_client_cn $cn_allowed {
       default       0;
       "client-01"   1;
       "client-02"   1;
   }
   ```
   Not on the list → nginx returns `403` with the canonical JSON
   body (`{"error":"forbidden","cn":"...","reason":"cn_not_allowlisted"}`)
   directly. FastAPI is never contacted.
4. **Audit logging** — every request lands in the nginx access log
   with `verify=<status>`, `cn="..."`, `allowed=0|1`, serial, and
   status code.

FastAPI only sees requests that have already passed every gate above.
Hitting FastAPI directly with a spoofed `X-Client-CN` header changes
nothing — the tests prove this (`test_server_plain.py::SP8`).

## Per-phase feature table

| Phase | Feature | Key files |
|-------|---------|-----------|
| v1.0 | ED25519 CA + FastAPI mTLS + CN allowlist middleware + 24h client cert rotation + pinning | `pki_setup.sh`, `server.py` (v1.0), `middleware.py`, `tests/test_middleware.py` *(all deleted in v1.2)* |
| v1.1 | nginx termination with FastAPI co-enforcement; header-trust middleware guarded by trusted-proxy-IP list | `nginx/nginx.conf` (hybrid), `middleware.py` (NGINX_MODE branch) *(replaced in v1.2)* |
| v1.2 | nginx-only auth (CN allowlist in `map{}`); FastAPI is auth-blind plain HTTP; structural tests enforce the invariant in CI | `nginx/nginx.conf`, `server.py`, `config.py`, `tests/test_v12_structural.py`, `.github/workflows/nginx-ci.yml` |

The v1.2 wiki page at
[`docs/wiki_v1_2_nginx_only_auth.md`](docs/wiki_v1_2_nginx_only_auth.md)
walks through the architecture shift in detail.

## Security invariants (v1.2, enforced by CI)

* ED25519 keys only. No RSA, no ECDSA.
* nginx enforces TLS 1.2+ minimum, HIGH cipher list, `server_tokens off`.
* `ssl_verify_client on` + `ssl_crl` for revocation. Revoked / expired
  / self-signed certs all produce HTTP 400 at nginx.
* The CN allowlist lives **only** in `nginx/nginx.conf`'s `map{}` block.
  `config.py` intentionally declares no allowlist — ST2 fails CI if
  one reappears.
* `server.py` contains **no** TLS primitives, **no** peer-cert parsing,
  **no** `X-Client-*` header references — ST3 fails CI on any of 22
  forbidden tokens. Even comments/docstrings mentioning those names
  fail the check (the scan is deliberately literal).
* `middleware.py` and `tls.py` are deleted — ST1 fails CI if either
  reappears.
* Private keys live only in `pki/**/*.key`, `chmod 600`, blocked from
  git by both `.gitignore` and a pre-commit grep.

## Running the test suite

```bash
make test                 # pytest — 42 tests, ~6-7s
make test-unit            # only unit-marker tests (ST + fast stuff)
make test-integration     # only integration-marker (nginx + FastAPI subprocess)
make test-cov             # full pytest with branch coverage (HTML: htmlcov/)
```

Marker breakdown (from `pytest.ini`):

| Marker | Count | What runs |
|--------|-------|-----------|
| `unit` | 4 | `test_v12_structural.py` — source inspection only. < 1s. |
| `integration` | 35 | real FastAPI + real nginx subprocesses + real mTLS |
| `performance` | 6 | `test_nginx_perf.py` (NP1-NP3) + `test_nginx_concurrency.py` (NC1-NC3) |
| `security` | 5 | cross-cut marker on ST1-ST3 + LA1 + SP8 |
| `slow` | 3 | NP1-NP3 benchmarks |

For load/SLO testing, use Locust directly:

```bash
make stack
locust --locustfile tests/nginx_locustfile_v2.py \
       --host https://localhost:8444 \
       --users 50 --spawn-rate 10 --run-time 30s \
       --headless --exit-code-on-error 1
```

The Locust run fails with non-zero exit if total-request p95 ≥ 30 ms.

## Day-2 operations

| Task | How |
|------|-----|
| Add/remove a CN from the allowlist | edit `nginx/nginx.conf`, then `make nginx-reload` |
| Revoke the current client cert | `make revoke` then `make nginx-reload` |
| Rotate client cert to fresh 24h-lived one | `make renew` |
| Extract nginx cert SHA-256 pin | `make pin` → `pki/nginx/nginx.fingerprint` |
| Hot-reload nginx without restart | `make nginx-reload` |
| Full PKI regen | `make clean && make pki` |

## Non-obvious design choices

* **ST3 is a literal-text match, not AST-aware.** It catches
  forbidden token references in comments and docstrings too — by
  design. If a comment says "TODO: re-enable ssl.SSLContext", that
  comment is itself a signpost toward the wrong architecture and
  should fail the build.
* **Deny is faster than allow.** nginx short-circuits before dialling
  the upstream for rejected requests. NP2 measures ~418µs for deny vs
  ~832µs for allow on localhost — a measurable win from the
  single-layer model.
* **`openssl ca` for leaf signing, not `openssl x509 -req`.** The
  former writes to `pki/ca/index.txt`, which `openssl ca -revoke`
  needs to find the cert by serial and flip it to R(evoked). Plain
  `x509 -req` does not register, so the CRL flow wouldn't work.
* **Map-lookup is O(1), not O(n).** NP3 patches 1000 bench CNs into
  the allowlist, reloads, and asserts latency stays within the
  baseline ceiling. This is insurance against a future nginx version
  changing its internal hash-table strategy.

## OCSP vs CRL

Short version: this project uses CRL because nginx supports it
natively via `ssl_crl`. OCSP stapling would add a stapling daemon
without changing the trust model. Full trade-off analysis in
[`docs/ocsp_notes.md`](docs/ocsp_notes.md).

## Directory layout

```
.
├── server.py                     # FastAPI app — plain HTTP, auth-blind (v1.2)
├── config.py                     # Documentation stub — empty by design
├── pki_setup.sh                  # ED25519 PKI: CA + server + nginx + client
├── renew_client_cert.sh          # Rotate client cert to 24h-lived
├── pinned_client.py              # stdlib SHA-256 cert pinning demo
├── Makefile                      # Lifecycle: pki/server/nginx-*/stack/test/revoke/renew/pin/clean
├── requirements.txt              # Runtime (fastapi, uvicorn, pydantic)
├── requirements-dev.txt          # Test (+ pytest, requests, httpx, locust, pytest-benchmark)
├── nginx/
│   ├── nginx.conf                # Template w/ @@PROJECT_ROOT@@ placeholder + map{} allowlist
│   ├── ssl_params.conf           # TLS 1.2+, HIGH cipher list, session cache
│   └── nginx-test-gen.sh         # Renders template -> nginx-test.conf
├── pki/
│   ├── openssl.cnf               # v3_{ca,server,nginx,client} extensions + CA_default
│   ├── ca/                       # (gitignored) ca.key, ca.crt, ca.crl, index.txt, ...
│   ├── server/                   # (gitignored) server.{key,crt} — legacy
│   ├── nginx/                    # (gitignored) nginx.{key,crt} — the cert clients see
│   └── client/                   # (gitignored) client.{key,crt}
├── tests/
│   ├── conftest.py               # Shared fixtures: pki_paths, plain_server, cert_kit, nginx_stack
│   ├── test_nginx_auth.py        # N2v2: 22-test auth matrix + NC5 live-reload
│   ├── test_server_plain.py      # N3v2: SP1-SP8 plain FastAPI + LA1 log discipline
│   ├── test_v12_structural.py    # N3v2: ST1-ST3 — enforce v1.2 invariant in CI
│   ├── test_nginx_perf.py        # N4v2: NP1-NP3 benchmarks
│   ├── test_nginx_concurrency.py # N4v2: NC1-NC3 parallel allow/deny
│   ├── nginx_locustfile_v2.py    # Locust scenario with p95 < 30ms SLO gate
│   └── revoke_client.sh          # openssl ca -revoke + CRL regen
├── docs/
│   ├── nginx_architecture_v2.md  # In-tree v1.2 architecture doc
│   ├── wiki_v1_2_nginx_only_auth.md  # Wiki body (paste to GitHub wiki)
│   └── ocsp_notes.md             # CRL vs OCSP trade-offs
└── .github/workflows/
    └── nginx-ci.yml              # structural-check + config-lint + auth-tests jobs
```

## Requirements

* Python 3.11+ (tested on 3.12). 3.11 is the floor because
  `server.py` uses `datetime.UTC`.
* OpenSSL 1.1.1+ (tested on 3.0.13). 1.1.1 is the hard floor for
  Ed25519 signing support — `pki_setup.sh` enforces this.
* nginx 1.18+ (tested on 1.24). Needs support for the `map{}`
  directive and variable substitution in `return`.
* GNU make.
* Bash 4+.

## License

Private lab project — not yet open-sourced. Add a license file
before external sharing.
