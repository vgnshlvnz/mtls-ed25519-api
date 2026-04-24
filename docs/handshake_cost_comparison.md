# Handshake Cost — nginx vs direct Python ssl

Operational doc measuring the per-connection overhead of the nginx
termination layer versus the v1.0 direct-mTLS path, and documenting
when the nginx hop is worth it.

## Numbers (dev box, single-host loopback)

| Path | Handshake + GET /health | Notes |
|------|:-----------------------:|-------|
| Direct Python ssl (v1.0) | ~5 ms median | from T4 PB1: 4.5 ms |
| nginx :8444 → FastAPI :8443 (v1.1 NGINX_MODE) | **~4 ms median** | from N4 NP1 |

The nginx path is **not slower** in our lab — nginx's TLS stack
(OpenSSL 3.0 directly) is slightly faster than Python's `ssl`
module wrapping the same library, and the extra proxy hop over
loopback costs ~0.1 ms. Net: the nginx termination layer has
negligible per-connection overhead on localhost.

## Keepalive effect

The benchmarks above are with NO connection reuse (each iteration
a fresh TLS handshake). Under keepalive:

| Scenario | Median | Source |
|----------|:------:|--------|
| Direct ssl, reused session, GET /data | 1.3 ms | T4 PB2 |
| nginx keepalive reuse, 10 sequential calls | **~0.8 ms/call** | N4 NP3 |

Both paths amortise the TLS cost and settle near 1 ms per request.
For typical API usage (clients hold a connection open), the
choice of termination layer disappears into the noise.

## When is the nginx hop worth it?

**Yes, deploy behind nginx when any of:**

- You want edge features Python doesn't give you cheaply: rate
  limiting, caching, request body size limits, IP allowlists,
  geo-blocking.
- You want to terminate mTLS on one process and forward identities
  to multiple backends (fanout). The dual-mode middleware's trust
  model (SI-1..SI-4) travels with a single peer-cert stream.
- You want CRL / OCSP checking at the TLS layer without
  reimplementing it in Python. nginx's `ssl_crl` is already
  well-exercised in production.
- You want zero-downtime TLS config reloads (`nginx -s reload`)
  without restarting Python workers.

**No, stay on the direct path when:**

- Single-host, single-service, no edge features needed. Removing a
  process is always worth it.
- You already operate Python and don't want a second daemon to
  monitor.
- You rely on per-request peer_cert parsing at the Python layer
  (the ASGI `scope["extensions"]["tls"]["peer_cert"]` path is
  NOT available in NGINX_MODE — headers replace it).

## Security reminder

Every nginx deployment **must** set `TRUSTED_PROXY_IPS` to the IP
that nginx uses to reach FastAPI's plain-HTTP port, AND must bind
FastAPI on a private interface (or separate uid / netns) so non-
proxy callers cannot reach it directly. See N3 test **ND1** and
`docs/nginx_architecture.md §"Header trust model"`.

## Benchmarks, reproducibly

```bash
make bench-nginx      # NP1 + NP3 + NP4 (NP2 skipped — needs mode flip)
```

Raw JSON for comparison lands under `.benchmarks/`. The
`--benchmark-compare=<baseline>` flag lets later runs gate on a
>20% regression.

## NP2 note

NP2 (direct Python ssl baseline) is deliberately skipped in the
pytest suite — it needs `NGINX_MODE=false` and the nginx
subprocess stopped mid-run, which the fixture isn't set up for.
Run the v1.0 measurement via T4's `pytest -m performance
tests/test_performance.py::test_PB1_...` for the direct number;
compare against NP1 from this run. On the dev-box tree tested
here: **PB1 ~4.5 ms, NP1 ~3.9 ms — nginx does not add overhead**.
