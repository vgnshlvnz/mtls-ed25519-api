# Deployment Guide — Reverse-Proxy mTLS Pass-Through

The test suite's `server_process` fixture binds directly to a
loopback port. Real deployments typically sit behind a reverse
proxy that terminates (or tunnels) the TLS connection. This doc
collects working configs for the three most common proxies. Each
example matches the server's security posture: mTLS required at
the edge, client identity preserved end-to-end.

Tests RW1/RW2/RW3 in `tests/test_realworld_scenarios.py` cover the
most important invariant from the server's perspective: **the
server MUST NOT trust any injected `X-Client-CN` header** — the
allowlist check is anchored to the TLS peer cert. RW3 verifies
this explicitly and passes today. RW1/RW2 require an in-process
Python proxy fixture and are deferred.

---

## Option A — nginx as a pass-through (TLS tunnel)

In this mode nginx does not terminate TLS; it forwards bytes. The
mTLS handshake happens directly between client and the Python
server, which means ZERO client-identity confusion is possible.

```nginx
stream {
    upstream mtls_backend {
        server 127.0.0.1:8443;
    }
    server {
        listen 443;
        proxy_pass mtls_backend;
        proxy_protocol on;     # preserves client IP
    }
}
```

**Trade-off:** nginx does not inspect the payload, so you lose
HTTP-level features (rate limiting by path, etc.) at the edge.

---

## Option B — nginx mTLS termination + header forwarding

nginx terminates TLS and forwards unencrypted over a trusted
network link to the backend. **Dangerous if the loopback isn't
truly private** — any process on the host can then bypass mTLS
by speaking HTTP directly. The server's CN allowlist is the only
defence.

```nginx
server {
    listen 443 ssl;
    ssl_certificate     /etc/nginx/certs/server.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;
    ssl_client_certificate /etc/nginx/certs/ca.crt;
    ssl_verify_client on;
    ssl_verify_depth 2;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:8443;
        # Forward headers the app MIGHT want. The server IGNORES
        # x-client-cn / x-forwarded-cn for authz — the TLS peer
        # cert is the only source of truth. See test_RW3_* for the
        # lock-in.
        proxy_set_header X-Client-CN       $ssl_client_s_dn_cn;
        proxy_set_header X-Client-Serial   $ssl_client_serial;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    }
}
```

**Critical:** run the Python server bound to `127.0.0.1` only.
Never expose the plain-HTTP backend port on a shared interface.

To fully preserve mTLS at the backend, you need to switch the
plain-HTTP `proxy_pass` to `proxy_pass https://127.0.0.1:8443`
and mint a client cert for nginx itself.

---

## Option C — Caddy as mTLS terminator

Caddy's syntax is shorter. Default is secure:

```caddyfile
api.example.com {
    tls /etc/caddy/certs/server.crt /etc/caddy/certs/server.key {
        client_auth {
            mode require_and_verify
            trusted_ca_cert_file /etc/caddy/certs/ca.crt
        }
    }

    reverse_proxy 127.0.0.1:8443 {
        header_up X-Client-CN     {tls_client_subject}
        header_up X-Client-Serial {tls_client_serial}
    }
}
```

Same security note as nginx Option B — do not trust
`X-Client-CN` in the Python server. It's forwarded for audit
correlation only.

---

## Option D — HAProxy with mTLS

```haproxy
frontend mtls_fe
    bind *:443 ssl crt /etc/haproxy/certs/server.pem \
        verify required ca-file /etc/haproxy/certs/ca.crt
    default_backend mtls_be
    # Expose the peer DN to the backend (as a header).
    http-request set-header X-Client-CN  %[ssl_c_s_dn(CN)]
    http-request set-header X-Client-SHA %[ssl_c_der,sha2(256),hex]

backend mtls_be
    server api 127.0.0.1:8443
```

---

## What the server does NOT trust

| Input                              | Trust level at server |
|------------------------------------|------------------------|
| TLS peer certificate (mTLS chain)  | Full — allowlist source |
| `X-Client-CN` / `X-Forwarded-CN`   | **Never trusted**      |
| `X-Forwarded-For`                  | Informational (logs)   |
| `X-Client-Serial`                  | Audit correlation only |

`test_RW3_server_ignores_untrusted_x_client_cn_header` pins this
explicitly: a valid TLS cert with CN=client-01 + an injected
`X-Client-CN: admin` header still produces 200 and logs
`cn=client-01`. If the test ever fails, an authz bypass has been
introduced — revert immediately.

---

## Deferred tests

RW1 (client→proxy→server identical response) and RW2 (proxy
rejection produces no backend traffic) require a Python mTLS
proxy fixture that is out of scope for T10. Operational
verification of these scenarios is a manual post-deploy check
against the specific proxy you're using.
