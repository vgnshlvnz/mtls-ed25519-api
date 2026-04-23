# CRL vs OCSP Stapling — Design Notes

This project ships **CRL-based revocation** (Phase 5). These notes explain
what OCSP stapling would buy you, why we did not ship it here, and how to
experiment with an OCSP responder locally if you want to.

## The three revocation strategies, compared

| Property | CRL (our choice) | OCSP (client pulls from responder) | OCSP stapling (server stamps) |
|---|---|---|---|
| Freshness | Stale between regenerations (`default_crl_days = 7` here) | Real-time query | Real-time at TLS time |
| Size on the wire | Full list, grows with revocations | Small per-cert response | Small per-cert response |
| Client-side extra RTT | 0 (CRL loaded once at server start) | 1 extra TCP/HTTPS round-trip per handshake | 0 — stapled into handshake |
| Leaks client identity to a 3rd party? | No | Yes — the responder sees who is calling whom | No |
| Server reload cost | Restart / SIGHUP hook | None | None (response attached per handshake) |
| Python stdlib support | Yes (`ssl.VERIFY_CRL_CHECK_LEAF`) | N/A (server doesn't care) | **No** — would need PyOpenSSL |

## Why this project uses CRL

Three project constraints forced the choice:

1. **Stdlib-only server TLS** — the skills file bans PyOpenSSL on the
   server side. Python's stdlib `ssl.SSLContext` has:
    * `load_verify_locations(cadata=<crl_pem>)` — works
    * `verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF` — works
    * No method for attaching a stapled OCSP response to the handshake.
   So CRL is the only in-band revocation mechanism we can wire in
   without either adding PyOpenSSL (prohibited) or offloading TLS to a
   front-end proxy (out of scope for a "small FastAPI app" demo).
2. **Single-tenant, closed-world mTLS** — clients are `client-01` /
   `client-02`, not random internet users. Revocation events are rare
   and operator-driven. A CRL refreshed on operator action (or weekly
   via cron) is sufficient; real-time revocation would be overkill.
3. **Ops simplicity** — CRL is a static file, signed by the CA, that
   the server reads at startup. An OCSP responder is a long-running
   network service that itself needs an HA story, a signing key, and
   (with stapling) a periodic task on the main server to refresh the
   stapled response.

## Trade-off: what we give up by not doing OCSP stapling

* **Revocation freshness**: with a 7-day CRL window, a revoked cert
  still works until the next CRL regen + server restart. Phase 5
  partially mitigates this: `renew_client_cert.sh` issues 24-hour
  certs, so the *maximum window* a revoked cert can authenticate is
  roughly `min(CRL_freshness, cert_lifetime)` — and in our default
  config that's ≤24h.
* **Scale**: CRL sizes grow with revocation history. At our scale
  (single-digit clients) this is irrelevant.

## Minimal OCSP responder for local experimentation

If you still want to stand up a local responder for testing, OpenSSL
ships one:

```bash
# Terminal 1 — start the responder on port 2560.
openssl ocsp \
  -index pki/ca/index.txt \
  -CA pki/ca/ca.crt \
  -rsigner pki/ca/ca.crt \
  -rkey pki/ca/ca.key \
  -port 2560 \
  -text

# Terminal 2 — query it for the client cert's status.
openssl ocsp \
  -CAfile pki/ca/ca.crt \
  -issuer pki/ca/ca.crt \
  -cert pki/client/client.crt \
  -url http://127.0.0.1:2560 \
  -resp_text
```

With the CRL-world setup from `pki_setup.sh`, the responder reads
`index.txt` directly and reports status V (good) / R (revoked). Running
`./tests/revoke_client.sh` before querying will flip the status.

## When would we switch?

Any of these would tip the balance toward OCSP stapling:

* A large and churning client fleet (tens of thousands of certs)
  where CRL size becomes a real cost.
* Regulatory requirements for sub-minute revocation propagation.
* Willingness to either (a) relax the stdlib-only rule and depend on
  PyOpenSSL, or (b) front the FastAPI app with a TLS-terminating
  reverse proxy (nginx/HAProxy) that supports stapling natively.

None of these are true for the current project scope, so we stay on
CRL — documented here so the next maintainer doesn't wonder why.
