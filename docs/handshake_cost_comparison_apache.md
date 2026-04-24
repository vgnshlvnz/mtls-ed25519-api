# Handshake cost comparison — v1.0 / v1.2 / v1.3

Three-way comparison of the per-request cost across the project's
proxy architectures. All numbers measured on the same hardware
(loopback, single-host) so the relative shape is meaningful even
though the absolute numbers depend on the box.

## Architectures under measurement

| Version | Model | TLS terminator | Auth enforcer |
|---------|-------|----------------|---------------|
| v1.0 | Direct mTLS to FastAPI | Python `ssl.SSLContext` | Python middleware |
| v1.2 | nginx OSS in front | nginx `ssl_*` directives | nginx `map{}` allowlist |
| v1.3 | Apache 2.4 in front | Apache `mod_ssl` | Apache RewriteMap allowlist |

In all three, the same client-01 cert hits `/health` and gets a
200 response with the same JSON body. Only the dispatch path differs.

## Numbers

Measurements come from:

- **v1.0**: wiki ([Test-Suite-Expansion](Test-Suite-Expansion), T4
  baseline) — ~4.5ms median per request
- **v1.2**: `tests/test_nginx_perf.py::NP1` — ~3.9ms median, ~832µs
  for the in-test benchmark mean
- **v1.3**: `tests/test_apache_perf.py::AP1` — measured locally;
  envelope ceiling is 60ms for the in-test benchmark, typical mean
  ~5-15ms depending on MPM and warmup

All three are well within the Locust SLOs (v1.2 p95<30ms, v1.3 p95<50ms),
but they decompose differently into where the time is spent.

## Why v1.0 (direct Python ssl) is fastest *per cold request* on
## a quiet box

* **Single process.** No proxy hop; the TLS handshake terminates in
  the same Python event loop that serves the response. No extra
  cross-process boundary.
* **Stdlib `ssl`** is comparatively lean — it's a thin wrapper around
  OpenSSL, with minimal additional bookkeeping.

## Why v1.2 (nginx) is *competitive* despite the extra hop

* **Single-process event loop.** nginx's worker is a single OS
  process; the Python upstream connection is reused via a keepalive
  pool, so the cross-process overhead amortises across requests.
* **`map{}` is O(1).** Allowlist lookup is a hash-table dip — costs
  the same with 2 entries or 1000.
* **Inline 403 body.** Denied requests never traverse the Python
  process, so the deny lane is even faster than the allow lane (NP2
  ≈ 0.5× NP1 on local tests).

## Why v1.3 (Apache) is *slower* than v1.2 in the same harness

* **Per-process / per-thread dispatch.** Apache's MPM (event on Ubuntu
  22.04+) has worker pools; serving a request involves a
  process-or-thread context switch on top of the TLS work. nginx
  avoids this — the worker is the TLS terminator and the request
  router in one shot.
* **`RewriteMap txt:` is O(log n).** Sorted file with binary-search
  lookup. Still cheap (logs of 1000 ≈ 10 comparisons), but real
  latency that nginx's hash map doesn't pay.
* **`<Location>`-scoped rewrite.** The per-directory rewrite phase
  carries more bookkeeping than nginx's flat config evaluation.
  Necessary for the rule to see SSL_* variables (see
  `docs/apache_vs_nginx_behaviour.md` §4) but not free.
* **403 from `ErrorDocument`** also goes through Apache's standard
  response pipeline — slightly more steps than nginx's inline
  `return 403 '...'`.

In aggregate, expect Apache to be 5-10ms slower than nginx for the
same workload on the same hardware. That difference is real but well
within the v1.3 SLO budget (p95 < 50ms vs nginx's p95 < 30ms).

## Allowlist scaling — AP4 vs NP3

| Test | Implementation | Lookup complexity | 1000-entry latency penalty (vs 10-entry baseline) |
|------|-----------------|-------------------|----------------------------------------------------|
| NP3 (v1.2) | nginx `map{}` | O(1) hash | Negligible — same absolute envelope |
| AP4 (v1.3) | Apache `RewriteMap txt:` | O(log n) sorted file | Up to ~50% slower (allowed by AP4's assertion) |

In production, this means an organisation rotating allowlist entries
weekly should measurably feel the cost on Apache once the list
crosses ~hundreds of CNs. nginx is unaffected at any practical size.
This is a real architectural trade-off, not a quirk: the choice of
proxy locks in the lookup-cost growth curve.

## When you'd accept v1.3's overhead anyway

* **Existing Apache deployment.** If the organisation already runs
  Apache for the rest of its services, adding v1.3 here keeps the
  ops surface uniform. The 5-10ms tax is paid once and amortises
  across team comfort.
* **`SSLCARevocationCheck chain`** (see
  `docs/apache_vs_nginx_behaviour.md` §5). Apache checks every cert
  in the chain against the CRL; nginx OSS only checks the leaf by
  default. If your PKI grows intermediates, Apache catches more.
* **Native `%{SSL_CLIENT_S_DN_CN}`** with no regex parsing. nginx
  Plus has this; nginx OSS requires a `map` regex. The v1.3 config
  is genuinely cleaner here.

## Reproducing

```bash
make pki
make apache-server
pytest tests/test_apache_perf.py -m performance -v   # AP1-AP4
make load-test-apache                                 # 60s, 50 users
```

`tests/test_apache_perf.py::TestApachePerf::test_ap3_apache_leg_for_three_way_comparison`
captures the cold-handshake mean and asserts it fits the < 100ms
envelope. Compare against the wiki [Test-Suite-Expansion](Test-Suite-Expansion)
T4 numbers for v1.0 and `tests/test_nginx_perf.py::NP1` for v1.2.
