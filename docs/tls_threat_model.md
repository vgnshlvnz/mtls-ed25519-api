# TLS Threat Model

One-page walkthrough of every attack exercised by
`tests/test_tls_attacks.py` (T2). Each row names the attack, why it
matters for an mTLS service, and the specific server-side invariant
that keeps it from succeeding.

The tests are the executable form of this document — if any row below
stops being true, the corresponding test in
`tests/test_tls_attacks.py` turns red.

## Attacker model

A remote, network-capable adversary who:

* can speak raw TCP to `127.0.0.1:8443` (or whatever bind the server
  is on),
* can compose arbitrary `ClientHello` messages (custom protocol
  versions, cipher lists, extensions),
* can generate unlimited Ed25519 keys and produce certificates signed
  by a CA of their choosing, and
* may have temporarily possessed a client cert that has since
  expired or been revoked.

The adversary does NOT have:

* the project CA's private key (`pki/ca/ca.key`),
* the server's private key (`pki/server/server.key`),
* the ability to modify server-side configuration at runtime.

Everything below is what stops that adversary from impersonating a
legitimate client.

---

## Group A — Protocol downgrade

| # | Attack | Why it matters | Server defence |
|---|--------|----------------|----------------|
| A1 | Force TLS 1.0 (`s_client -tls1`) | Known-broken ciphers, BEAST/CRIME primitives available in v1.0 | `SSLContext.minimum_version = TLSVersion.TLSv1_2` in `tls.build_server_context` — OpenSSL refuses the ClientHello before any handshake state is built |
| A2 | Force TLS 1.1 (`s_client -tls1_1`) | Same family of weaknesses as 1.0; RFC 8996 formally deprecated both | Same `minimum_version` gate |
| A3 | Force TLS 1.2 | Sanity: our declared minimum must still negotiate | `minimum_version = TLSv1_2` allows 1.2; default cipher list includes modern ECDHE AEAD suites |
| A4 | Force TLS 1.3 | Sanity: modern default path must work | `PROTOCOL_TLS_SERVER` + the stdlib's default 1.3 cipher list |

## Group B — Cipher suite attacks

| # | Attack | Why it matters | Server defence |
|---|--------|----------------|----------------|
| B1 | Offer only `aNULL` ciphers | Authenticated but **unencrypted** channel — mTLS theatre over plaintext | OpenSSL's default `SECLEVEL=2` excludes NULL ciphers from the enabled set; negotiation fails with `no_shared_cipher` |
| B2 | Offer an EXPORT-grade cipher | 40-bit export ciphers are trivially breakable (FREAK, Logjam) | OpenSSL 3.x removed EXPORT suites from the library — there is no code path on the host that can negotiate one. Test skips with a sentinel so the absence itself is auditable |
| B3 | Negotiate `TLS_AES_256_GCM_SHA384` | Sanity: a strong modern suite must still succeed, to attribute B1 failures correctly | TLS 1.3 + AEAD via stdlib defaults |

## Group C — Certificate chain attacks

Each attack leaf is generated into a tempdir by fixtures in
`tests/conftest.py`; the real `pki/ca/` is never touched. C1/C2/C4
leaves chain to a tempdir mirror of the project CA so the TLS
rejection is attributable to the specific leaf-level defect rather
than "unknown issuer".

| # | Attack | Why it matters | Server defence |
|---|--------|----------------|----------------|
| C1 | Expired client cert (`notAfter` in the past) | A leaked cert that has since "timed out" must not still authenticate — validity is a cheap, mandatory revocation signal | OpenSSL's built-in `X509_V_ERR_CERT_HAS_EXPIRED` check fires during the handshake's chain verification |
| C2 | Not-yet-valid cert (`notBefore` in the future) | Pre-issuance: an adversary who intercepts a cert before its activation window must not be able to use it | `X509_V_ERR_CERT_NOT_YET_VALID` check; enabled by default |
| C3 | Untrusted 3-level chain (rogue root → rogue intermediate → leaf) | The chain looks structurally legitimate; trust must come from the path's anchor, not its shape | Server's SSLContext loads only `pki/ca/ca.crt` as a trust anchor. The chain's terminal root is unknown → `X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY` |
| C4 | Key Usage = `dataEncipherment` instead of `digitalSignature` | TLS 1.2/1.3 CertificateVerify is a signature; a cert not licensed to sign must not authenticate | OpenSSL's KU check rejects the cert during verification; `critical` flag on the KU extension makes this enforcement non-optional |
| C5 | Self-signed client cert | Zero-trust baseline: no chain to a trusted CA at all | Same as C3 — issuer unknown to the server's trust store |

## Group D — Handshake manipulation

| # | Attack | Why it matters | Server defence |
|---|--------|----------------|----------------|
| D1 | ClientHello without SNI | Legacy / embedded clients omit SNI; the server must not crash or 400 | Server binds a single IP and does not dispatch on SNI; stdlib `ssl` tolerates a missing `server_name` extension |
| D2 | 50 concurrent valid clients | Serialising handshakes or leaking per-connection state is a DoS primitive and a cross-session confusion risk | Uvicorn runs on asyncio with a thread-safe SSLContext; each connection gets an independent `SSLObject`. The test asserts 50 concurrent 200s inside 30s |
| D3 | Bare TCP connect, nothing sent | Slowloris-style: hold a socket half-open to pin a worker | The server keeps serving legitimate clients while the idle socket is open; the test proves the accept loop is not serialised on handshake completion |

## Group E — Replay & session attacks

| # | Attack | Why it matters | Server defence |
|---|--------|----------------|----------------|
| E1 | Session resumption from a different process | If resumption bypasses client-cert verification, an attacker who records a ticket could replay it without ever holding the cert | The test records the observable behaviour on this host (fresh handshake or clean resumption) and asserts the client still presents the cert. Neither stdlib `ssl` nor our SSLContext strips client-cert verification on resumption |
| E2 | Two certs with the same serial number | CRL entries identify certs by (issuer, serial); a collision could let a revoked serial also suppress a legitimate cert, or vice-versa | The project CA uses `openssl ca` with a sequential `serial` file — collisions are structurally impossible in normal operation. The test documents the invariant by generating colliding leaves via `openssl x509 -set_serial` (outside the CA DB) and proving the CRL pipeline still produces a parseable CRL |

---

## Where the defences live in source

| Defence | File | Notable line |
|---------|------|-------------|
| TLS min version, CERT_REQUIRED, CA trust store | `tls.py` | `build_server_context` |
| CRL loading and `VERIFY_CRL_CHECK_LEAF` | `tls.py` | `ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF` |
| CRL freshness at server start | `server.py` | `_refresh_crl()` |
| Handshake-failure logging (reason code only, no cert detail) | `server.py` | `_logging_fatal_error` |
| CN allowlist (layered on top of TLS verification) | `middleware.py` | `ClientIdentityMiddleware.dispatch` |

If you change any of these, re-run `make test-cov` and
`bash tests/tls_attack_matrix.sh`. A green run is this document's
executable proof.
