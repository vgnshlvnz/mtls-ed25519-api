# Apache vs nginx — observed behavioural differences

Pairs with `docs/apache_vs_nginx_cn_extraction.md`. That doc covers
the *configuration* mechanics; this one covers the *runtime
observable* differences that surfaced while building and testing
the v1.3 (Apache) integration alongside the v1.2 (nginx) one.

## TL;DR

Apache 2.4.58 + OpenSSL 3.0.13 is **not** a drop-in nginx replacement.
Six places where the two diverge in ways that need to be visible to
the test matrix:

| # | Surface | nginx (v1.2) | Apache (v1.3) |
|---|---------|--------------|----------------|
| 1 | No client cert presented | HTTP 400 (handshake completes; nginx checks verify after) | TLS 1.3: handshake alert (`tlsv13 alert certificate required`); TLS 1.2: handshake failure |
| 2 | ErrorDocument body interpolation | Inline `$ssl_client_cn` in `return 403 '...'` | Static text only — surface CN via response header |
| 3 | Allowlist reload | `nginx -s reload` — instant for new requests on existing connections | `apachectl graceful` — multi-process drain; existing connections stay on old workers |
| 4 | RewriteRule + SSL vars | n/a (nginx uses single-phase variable system) | Server-level RewriteRule cannot see SSL_* vars; must wrap in `<Location>` |
| 5 | CRL chain depth | `ssl_crl` checks leaf only by default | `SSLCARevocationCheck chain` checks the full chain |
| 6 | Concurrency model | single-process event loop | MPM (event/worker/prefork); per-process state |

## 1. No client cert response code

Apache's `SSLVerifyClient require` instructs mod_ssl to demand a
client cert during the handshake. With TLS 1.2 this is part of the
initial handshake: if the client doesn't present a cert, the server
sends a fatal alert and the connection closes. With TLS 1.3 this is
a post-handshake CertificateRequest; absence triggers the same
fatal alert (`certificate required`).

The phase prompt asserted Apache returns HTTP 403 here. In practice,
on Ubuntu 22.04+ with Apache 2.4.58 and OpenSSL 3, the connection
**doesn't survive long enough** for an HTTP response — curl sees
exit 56 with the OpenSSL alert message.

**Test impact:** `test_ab1_no_client_cert` and
`test_af2_no_cert_response_code` both accept either form of
rejection (TLS abort OR HTTP 4xx) and assert that the upstream
FastAPI never sees the request. The architectural invariant is
preserved either way; only the observable response shape differs
from the prompt.

nginx's behaviour is HTTP 400 with a static body
("No required SSL certificate was sent"). The handshake succeeds,
nginx then evaluates `$ssl_client_verify` and returns 400 because
the var is "NONE". This is what `tests/test_nginx_auth.py::TestGroupBDenied::test_b1_no_client_cert_returns_400`
locks in.

## 2. ErrorDocument cannot interpolate SSL variables

nginx:

```nginx
return 403 '{"error":"forbidden","cn":"$ssl_client_cn","reason":"cn_not_allowlisted"}';
```

The `$ssl_client_cn` is expanded at response time — the body literally
contains the CN of the rejected client.

Apache:

```apache
ErrorDocument 403 '{"error":"forbidden","reason":"cn_not_allowlisted"}'
```

mod_ssl does **not** expand `%{SSL_CLIENT_S_DN_CN}` inside ErrorDocument
arguments. Apache treats the body as literal text. To preserve
operator visibility, we surface the rejected CN via a response header:

```apache
Header always set X-Rejected-CN "%{SSL_CLIENT_S_DN_CN}s" env=!REDIRECT_STATUS
```

Tests assert both pieces: the JSON body matches the canonical schema
(without the CN field), and the X-Rejected-CN header is present and
correct.

## 3. Graceful reload semantics

nginx's `-s reload` SIGHUPs the master, which then forks fresh worker
processes. Existing connections continue on old workers, but those
old workers immediately stop accepting new connections. Once their
in-flight requests complete, they exit. New requests on existing
connections are still served by old workers (until those connections
close), so the policy change is immediate for new connections only.

Apache's `apachectl graceful` is similar in spirit but with one
practical difference: the new workers read the cn_allowlist.txt file
at startup (RewriteMap txt: caches), and old workers retain the
**file's contents at their startup time**. So:

- An existing keep-alive connection on an old worker continues using
  the old allowlist until the connection closes or the request count
  hits MaxKeepAliveRequests.
- New TCP connections can land on either an old or new worker
  depending on accept queueing — usually new workers, but not
  guaranteed.

For the AC5 test, we mint a fresh client cert (so no prior connection
exists) after the graceful reload, which forces a new TCP connection
and lands on a new worker with the updated allowlist.

## 4. Server-level RewriteRule cannot see SSL_* variables

A Subtle Apache trap. mod_rewrite has two phases:

- **URL translation** (server-level / `<VirtualHost>` rules) — runs
  early, before mod_ssl populates the request env.
- **Fixup** (per-directory / `<Location>` / `<Directory>` rules) —
  runs late, after mod_ssl has populated everything.

A `RewriteRule` at `<VirtualHost>` scope checking `%{SSL:SSL_CLIENT_S_DN_CN}`
will see an empty string and reject every cert with HTTP 403, even
valid ones. The fix is to wrap the rule in `<Location "/">`:

```apache
RewriteEngine On
RewriteMap cn_allowed "txt:..."

<Location "/">
    RewriteEngine On
    RewriteCond "${cn_allowed:%{SSL:SSL_CLIENT_S_DN_CN}}" "^$"
    RewriteRule .* - [F,L]
</Location>
```

Per-directory rewrite engines fire at fixup phase, so the variable
is correctly expanded.

nginx's variable system is unified across phases — `$ssl_client_s_dn`
is reliably populated everywhere a directive can read it. This is
one place where Apache's two-phase model leaks unwelcome complexity.

## 5. CRL chain depth

`ssl_crl` (nginx) uses OpenSSL's `X509_V_FLAG_CRL_CHECK` by default,
which only checks the **leaf** cert against the CRL. Intermediates
are not consulted unless `X509_V_FLAG_CRL_CHECK_ALL` is also set —
nginx OSS doesn't expose a directive for this.

`SSLCARevocationCheck chain` (Apache) sets both flags. Every cert in
the presented chain is checked against the loaded CRL. If you ever
introduce an intermediate CA and that intermediate is compromised
+ revoked, Apache catches certs issued by the revoked intermediate
even when the leaf itself isn't on the CRL.

For our single-tier CA this distinction is academic, but it becomes
important the moment the PKI grows. Documented here because the
`apache.conf` directive choice (`chain` over `leaf`) is a deliberate
strengthening — nginx parity would require dropping to `leaf`, which
is strictly weaker.

The AF5 test exists to exercise this path but is currently skipped:
generating a 3-level chain requires multi-CA fixtures that aren't
yet in the suite. The directive is verified by config inspection
(`grep SSLCARevocationCheck apache/apache.conf`).

## 6. Concurrency model

| MPM | How requests are dispatched | Per-process state |
|-----|------------------------------|----------------------|
| prefork | One process per request | Each worker has its own SSL session cache (sized by `SSLSessionCache` shmcb) |
| worker | Threads per process, multiple processes | Threads share the worker process's memory; SSL cache is shared via shmcb |
| event | Like worker but async-keepalive | Same as worker; idle connections don't tie up threads |

Ubuntu's apache2 package defaults to **event** (verified locally:
`apache2ctl -V \| grep MPM`). This is the closest match to nginx's
event-loop model and what AE1/AE2/AF3 exercise.

A `prefork`-based deployment would need to bump `MaxRequestWorkers`
to handle the test's 20-concurrent-clients workload. This isn't a
defect — it's an architectural choice for the deployment. The tests
adapt by using modest concurrency (≤ 30 clients) so all three MPMs
can pass on a default-tuned host.

## Cross-reference

- `apache/apache.conf` — the live config that encodes these decisions
- `tests/test_apache_auth.py` — Group F locks in 1, 2, 3, 4, 6
- `docs/apache_vs_nginx_cn_extraction.md` — companion config-mechanics page
