# mTLS REST API with ED25519

[![CI](https://github.com/vgnshlvnz/mtls-ed25519-api/actions/workflows/ci.yml/badge.svg)](https://github.com/vgnshlvnz/mtls-ed25519-api/actions/workflows/ci.yml)
[![Secret scan](https://github.com/vgnshlvnz/mtls-ed25519-api/actions/workflows/secret-scan.yml/badge.svg)](https://github.com/vgnshlvnz/mtls-ed25519-api/actions/workflows/secret-scan.yml)


A small FastAPI server that enforces mutual TLS using **ED25519** keys and a
self-hosted CA, with a CN allowlist, CRL-based revocation, short-lived
client certs, and stdlib-only cert pinning.

The project is built as five incremental phases — each fully green on its
own — so the progression from "PKI exists" through to "revocation works
and the cert rotates every 24 hours" is easy to follow commit-by-commit.

## Quickstart (≤5 commands from a clean clone)

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements-dev.txt
make pki                  # ED25519 CA + server + client + initial CRL
make server               # FastAPI at https://127.0.0.1:8443, mTLS required
make test                 # unit tests + curl matrix + requests + httpx
```

`make stop` when you're done. `make help` lists every target. If any command
above fails the very first time — you're not in a venv.

## What the server enforces

Two independent gates, both must pass:

1. **TLS handshake** (`tls.build_server_context`) — ED25519-only, stdlib
   `ssl.SSLContext`, `CERT_REQUIRED`, TLS 1.2+. Any client that can't
   present a cert chaining to `pki/ca/ca.crt` is rejected *before HTTP
   bytes flow*. If a CRL is present, revoked certs die here too
   (`VERIFY_CRL_CHECK_LEAF`).
2. **CN allowlist** (`middleware.ClientIdentityMiddleware`) — the
   Subject CommonName is looked up in `config.ALLOWED_CLIENT_CNS`.
   Trusted cert + wrong CN → `403 {"error":"forbidden","cn":"...","reason":"cn_not_allowlisted"}`.

Every request carries an `X-Request-ID`; handshake failures emit a
single WARNING log line with a coarse reason code (no cert detail).

## Per-phase feature table

| Phase | Feature | Key files |
|-------|---------|-----------|
| 1 | ED25519 CA + server + client certs, script-driven, chain-verified | `pki_setup.sh`, `pki/openssl.cnf` |
| 2 | FastAPI server, mTLS SSLContext, `GET /health`, `GET /data`, `POST /data`, structured logs | `server.py`, `tls.py`, `requirements.txt` |
| 3 | CN allowlist middleware, 403 on rejection, TLS-handshake failures logged, unit tests | `config.py`, `middleware.py`, `tests/test_middleware.py` |
| 4 | curl matrix (6 scenarios), `requests.Session` client, async `httpx` client, TLS-negative tests | `tests/curl_tests.sh`, `tests/negative_tests.sh`, `tests/client_test.py`, `tests/client_async.py` |
| 5 | CRL init + revocation, 24h short-lived cert rotation, SHA-256 cert pinning, Makefile, OCSP notes | `tests/revoke_client.sh`, `renew_client_cert.sh`, `pinned_client.py`, `Makefile`, `docs/ocsp_notes.md` |

Every phase lives on its own `feature/phase-X-<name>` branch and adds
independent commits on top — `git log --oneline` reads as a progression.

## Security invariants (audited in code)

* ED25519 keys only. No RSA, no ECDSA — checked via `openssl` output and
  by project rules.
* `ssl.CERT_REQUIRED` is the only accepted verify mode. `CERT_NONE` /
  `CERT_OPTIONAL` / `verify=False` are banned everywhere (tests included).
* `PROTOCOL_TLS_SERVER` and `TLSVersion.TLSv1_2` minimum on the server
  side. Uvicorn's auto-built SSLContext is explicitly *replaced* with
  the audited one from `tls.build_server_context()`.
* Private keys live only in `pki/**/*.key` and are `chmod 600`. Git blocks
  them two ways — `.gitignore` and a pre-commit hook that greps PEM
  private-key headers.
* Handshake failures are logged with a reason classifier only (never the
  exception detail), so a misbehaving peer can't probe our trust store
  via log diffing.
* Cert pinning (`pinned_client.py`) hashes the raw DER bytes — never the
  parsed `getpeercert()` dict, which is a lossy representation.

## Running the test suite

The Python test surface is driven by **pytest** with two primary
layers, selectable by marker:

| Marker | What runs | Typical time |
|--------|-----------|--------------|
| `unit` | Pure-function tests in `tests/test_middleware.py`. No sockets, no subprocess. | < 1s |
| `integration` | Starts a real `server.py` subprocess behind mTLS (session-scoped fixture) and hits every endpoint with `requests.Session` and `httpx.AsyncClient`. | ~5s cold |

Common invocations (all via the Makefile, or `pytest` directly):

```bash
make test-unit            # fast unit layer
make test-integration     # live server + real mTLS
make test-all             # both, sequentially
make test-cov             # full pytest with branch coverage (fail_under=70)
make test                 # pytest + legacy curl matrix + negative tests
```

Additional markers — `slow`, `security`, `performance`, `e2e` — are
registered in `pytest.ini` and populated by later test-expansion phases
(T2 onward). Run a single marker with `pytest -m <marker>`; combine
markers with boolean expressions (`pytest -m "unit and not slow"`).

Coverage is configured in `.coveragerc`:

* Scope: `server.py`, `middleware.py`, `tls.py`, `config.py` (the
  server-side surface).
* Branch coverage enabled; the T1 baseline floor is **70%**.
  Each subsequent phase must hold or raise it.
* HTML report at `htmlcov/index.html` after `make test-cov`.

Server fixture behaviour — the integration suite will pick a random
free loopback port via `MTLS_API_PORT` when 8443 is already bound,
so tests are safe to run alongside a backgrounded `make server`.

## Day-2 operations

| Task | How |
|------|-----|
| Rotate the client cert to a fresh 24h-lived one | `make renew` (cron: `0 */12 * * *` → `renew_client_cert.sh`) |
| Revoke the current client cert and update the CRL | `make revoke` (then `make stop && make server` to apply) |
| Extract the server's SHA-256 pin into `pki/server/server.fingerprint` | `make pin` |
| Start a pinned-client demo run | `python pinned_client.py` (uses the file from `make pin`) |
| Wipe everything except source | `make clean` |

## Non-obvious design choices

Documented in-code with `# SECURITY:` comments — a few worth calling out
at README level:

* **Forced `loop="asyncio"`** in `server.py`. uvloop (bundled with
  `uvicorn[standard]`) has its own C-level SSL implementation that
  bypasses `asyncio.sslproto`, which is where the TLS-handshake-failure
  logging hook lives. At our scale, perf loss is a rounding error;
  visibility is not.
* **Monkey-patch of `asyncio.sslproto.SSLProtocol._fatal_error`**.
  stdlib silently swallows `SSLError` because `SSLError` inherits from
  `OSError`. A minimal wrapper emits a single WARNING line with
  `reason=PEER_DID_NOT_RETURN_A_CERTIFICATE` or similar before
  delegating to the original close sequence. Failing fast on import if
  the stdlib API moves in a future Python.
* **Leaf signing via `openssl ca`, not `openssl x509 -req`**. The
  former writes to `pki/ca/index.txt` so `openssl ca -revoke` can find
  the cert by serial and flip it to R(evoked). Plain `x509 -req` does
  not register, so a CRL flow would not work.

## OCSP vs CRL

Short version: this project uses CRL because the stdlib `ssl` module
supports it natively and OCSP stapling would require PyOpenSSL
(banned by project rules). Full trade-off analysis, plus a minimal
OCSP responder recipe for local experimentation, is in
[`docs/ocsp_notes.md`](docs/ocsp_notes.md).

## Directory layout

```
.
├── server.py              # FastAPI app, mTLS middleware wired in
├── tls.py                 # SSLContext factory + cert-aware uvicorn protocol
├── middleware.py          # ClientIdentityMiddleware (CN allowlist + 403)
├── config.py              # ALLOWED_CLIENT_CNS
├── pki_setup.sh           # Initial PKI bootstrap (Ed25519, 10y CA, 1y leaves)
├── renew_client_cert.sh   # Rotate client cert to 24h-lived (cron target)
├── pinned_client.py       # stdlib-only SHA-256 cert pinning demo
├── Makefile               # Lifecycle automation (pki/server/test/revoke/renew/pin/clean)
├── requirements.txt       # Runtime deps (fastapi/uvicorn/pydantic)
├── requirements-dev.txt   # Test deps (+ requests, httpx)
├── pki/
│   ├── openssl.cnf        # CA + v3_{ca,server,client} extensions + CA_default for `openssl ca`
│   ├── ca/                # (gitignored) ca.key, ca.crt, ca.crl, index.txt, …
│   ├── server/            # (gitignored) server.{key,crt}
│   └── client/            # (gitignored) client.{key,crt}
├── tests/
│   ├── curl_tests.sh      # 6-scenario curl matrix
│   ├── negative_tests.sh  # TLS-layer negative assertions
│   ├── revoke_client.sh   # `openssl ca -revoke` + CRL regen
│   ├── client_test.py     # sync requests client
│   ├── client_async.py    # async httpx client
│   └── test_middleware.py # unittest stubs for cert parsing
└── docs/
    └── ocsp_notes.md      # CRL vs OCSP trade-offs
```

## Requirements

* Python 3.11+ (tested on 3.12)
  — 3.11 is the floor because `server.py` uses `datetime.UTC` and
  `asyncio.Runner`, both added in that release.
* OpenSSL 3.x (tested on 3.0.13)
* GNU make (macOS ships it as `/usr/bin/make`)
* Bash 4+ (all scripts start with `set -euo pipefail`; `shellcheck` clean)

## License

Private lab project — not yet open-sourced. Add a license file before
external sharing.
