"""Runtime configuration for the mTLS REST API.

Values here drive security decisions. Keep this file deliberately small,
readable, and reviewable in a single glance — every entry is a promise
that a specific identity is trusted.
"""

from __future__ import annotations

import os

# Subject CommonNames that are admitted to the API once their certificate
# chain has already been validated by the TLS layer.
#
# A client that passes the TLS handshake (i.e. holds a key whose cert
# chains to pki/ca/ca.crt) but whose CN does NOT appear here is rejected
# with HTTP 403. This is an application-layer authorization check *on top
# of* TLS verification — "the CA says you are X, and we only talk to
# specific Xs".
#
# frozenset chosen for O(1) membership checks and immutability at import
# time, so a runtime bug cannot silently widen the allowlist.
ALLOWED_CLIENT_CNS: frozenset[str] = frozenset({"client-01", "client-02"})


# --- N1: nginx termination mode --------------------------------------------
#
# When NGINX_MODE=true the server expects nginx to sit in front, terminate
# mTLS on :443, and forward plain HTTP to FastAPI with the peer-cert fields
# pinned to request headers (X-Client-CN / X-Client-Verify / etc.).
#
# The middleware trust model (wired in N2) is:
#
#     source_ip in TRUSTED_PROXY_IPS       -> honour X-Client-CN
#     source_ip not in TRUSTED_PROXY_IPS   -> ignore X-Client-CN entirely
#
# With TRUSTED_PROXY_IPS empty, the server refuses to start (fail-closed
# — otherwise an attacker reaching FastAPI's plain-HTTP port directly
# would be able to forge a CN via the header). See SI-4 in N1 §"Security
# invariants".
NGINX_MODE: bool = os.environ.get("NGINX_MODE", "false").strip().lower() == "true"

# Comma-separated list of IPs whose X-Client-* headers are trusted. The
# nginx loopback (127.0.0.1) is the default; override via the
# TRUSTED_PROXY_IPS env var when nginx runs on a different bridge.
TRUSTED_PROXY_IPS: frozenset[str] = frozenset(
    ip.strip()
    for ip in os.environ.get("TRUSTED_PROXY_IPS", "127.0.0.1").split(",")
    if ip.strip()
)
