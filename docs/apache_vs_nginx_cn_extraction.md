# Apache vs nginx — CN extraction & allowlist mechanics

The v1.2 (nginx) and v1.3 (Apache) integrations encode the same auth
boundary but use very different primitives. This page is the
side-by-side reference for the choices each one makes.

## Feature comparison

| Concern | nginx OSS (v1.2) | Apache mod_ssl (v1.3) |
|---------|-------------------|------------------------|
| **Subject CN variable** | `$ssl_client_s_dn_cn` (Plus only) — OSS users parse `$ssl_client_s_dn` via a `map` regex | `%{SSL_CLIENT_S_DN_CN}` — built-in, returns the CN component cleanly |
| **Allowlist mechanism** | `map $ssl_client_cn $cn_allowed { ... }` block in nginx.conf | `RewriteMap cn_allowed "txt:.../cn_allowlist.txt"` + RewriteCond/RewriteRule |
| **Allowlist storage** | Inline in nginx.conf | Separate text file (`apache/cn_allowlist.txt`) |
| **Lookup complexity** | O(1) hash table | O(log n) sorted file scan |
| **Allowlist reload** | `nginx -s reload` — in-process, instant for new connections | `apachectl graceful` — multi-process drain; existing connections keep old allowlist until close |
| **CRL directive** | `ssl_crl /path/to/ca.crl;` (leaf check by default) | `SSLCARevocationFile /path/to/ca.crl` + `SSLCARevocationCheck chain` (full chain) |
| **403 body** | `return 403 '{"error":"forbidden","cn":"$ssl_client_cn",...}';` (inline + variable interpolation) | `ErrorDocument 403 '{"error":"forbidden",...}'` — **cannot interpolate SSL vars in the body**; CN surfaced via `Header always set X-Rejected-CN` instead |
| **Server-version hiding** | `server_tokens off;` | `ServerTokens Prod` |
| **Session cache** | `ssl_session_cache shared:SSL:10m;` (HTTP block) | `SSLSessionCache "shmcb:..."` (server-config scope; rejected inside `<VirtualHost>`) |
| **No-cert handling with `verify_client require/on`** | HTTP 400 ("No required SSL certificate was sent") | TLS 1.3: handshake alert (`tlsv13 alert certificate required`); TLS 1.2: handshake failure |

## Why nginx needs a regex for CN extraction

OSS nginx exposes only `$ssl_client_s_dn` — the full RFC 2253 Subject DN, e.g. `CN=client-01,O=Lab,C=MY`. The `$ssl_client_s_dn_cn` variable that contains just the CN exists only in nginx Plus (the commercial build). To work around that, v1.2 uses a `map` regex:

```nginx
map $ssl_client_s_dn $ssl_client_cn {
    ~(?:^|,)\s*CN=(?<cn>[^,]+) $cn;
    default                    "";
}
```

That regex strips the `CN=` prefix and any leading comma/whitespace, then captures everything up to the next comma. The result is a clean string usable for the allowlist lookup.

## Why Apache doesn't need it

mod_ssl populates `%{SSL_CLIENT_S_DN_CN}` directly with the parsed CN — no regex required:

```apache
RewriteCond "${cn_allowed:%{SSL:SSL_CLIENT_S_DN_CN}}" "^$"
RewriteRule .* - [F,L]
```

The `SSL:` prefix in `%{SSL:SSL_CLIENT_S_DN_CN}` tells mod_rewrite to look up the variable through mod_ssl's variable provider, which is reliably populated by request-handling time. Contrast with `%{SSL_CLIENT_S_DN_CN}` directly — that *also* works, but only at the top-level CondPattern; it does NOT expand inside the inner `${cn_allowed:...}` map-lookup key in some Apache configurations. We use the `SSL:` form to be unambiguous.

This is one place where Apache's older, more featureful mod_ssl integration is genuinely cleaner than nginx OSS.

## Why the RewriteRule must be per-directory

A subtle Apache trap that bit during v1.3 development: server-level mod_rewrite (`RewriteRule` at `<VirtualHost>` scope) fires during the **URL translation** phase, which runs **before** mod_ssl populates the request environment. So a CondPattern like `%{SSL:SSL_CLIENT_S_DN_CN}` evaluates to empty, the lookup misses every cert, and *every* request gets a 403 — even valid `client-01`s.

The fix is to wrap the rule in `<Location "/">`, which forces evaluation at the **fixup** phase:

```apache
RewriteEngine On
RewriteMap cn_allowed "txt:..."

<Location "/">
    RewriteEngine On
    RewriteCond "${cn_allowed:%{SSL:SSL_CLIENT_S_DN_CN}}" "^$"
    RewriteRule .* - [F,L]
</Location>
```

Per-directory rewrite engines run after mod_ssl has populated the request env, so the variable expands correctly. nginx has no equivalent of this — its variable system is unified across all phases.

## Allowlist reload semantics

| Step | nginx | Apache |
|------|-------|--------|
| Edit allowlist | `nginx.conf` (`map { ... }`) | `apache/cn_allowlist.txt` |
| Trigger reload | `nginx -s reload` | `apachectl graceful` (or `-k graceful`) |
| When new policy is live | Immediately, even on existing connections (master forks fresh worker that handles new requests) | New worker processes pick up the new file. Existing connections finish on old workers using the old allowlist until they close |

The Apache "drain" behaviour is the source of the AC5 test in `tests/test_apache_auth.py`: after a graceful reload, requests on the existing keep-alive connection may still see the old allowlist until that connection closes. The test asserts both states observably.

## When you'd pick which approach

* **Small / static allowlist** (handful of CNs that change rarely): both approaches are fine. nginx's `map{}` is slightly more readable; Apache's `SSLRequire` (alternative path documented in `apache.conf`) is even simpler for ≤ 5 CNs.
* **Larger allowlist** (10+ CNs, frequent rotation): nginx still wins on simplicity (one file). Apache's external `cn_allowlist.txt` makes rotation easier (no Apache config diff), but the multi-process drain on reload is real.
* **Operational independence**: Apache lets you change the allowlist without touching the main config. Some teams want this; others want everything in one git diff.

## Cross-reference

- `nginx/nginx.conf` — the v1.2 implementation
- `apache/apache.conf` — the v1.3 implementation
- `apache/cn_allowlist.txt` — the external allowlist file
- `docs/nginx_architecture_v2.md` — v1.2 architecture deep-dive
- `docs/apache_vs_nginx_behaviour.md` — broader behavioural differences (no-cert, error pages, MPM concurrency model, …)
