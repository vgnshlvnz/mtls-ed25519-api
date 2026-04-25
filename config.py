"""Runtime configuration for the mTLS REST API (v1.2).

Intentionally empty.

v1.2 architectural invariant: ALL client authentication and
authorization lives in nginx (see ``nginx/nginx.conf`` — specifically
the ``map $ssl_client_cn $cn_allowed`` allowlist and the
``ssl_verify_client`` / ``ssl_crl`` directives). This process is
auth-blind: it never parses peer certs, never consults an allowlist,
and has no notion of "trusted proxy IPs".

If you find yourself wanting to add an allowlist, a trusted-proxy-IP
list, or an ``NGINX_MODE`` flag here, STOP — that was the v1.1 hybrid
architecture that v1.2 was written to remove. Extend ``nginx.conf``
instead; the structural test suite (``tests/test_v12_structural.py``)
will fail CI if auth state reappears in this module.
"""

from __future__ import annotations
