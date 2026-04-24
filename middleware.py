"""Request middleware for the mTLS REST API.

One middleware class combines two responsibilities:

1. Request-context tagging — assign (or honour) an X-Request-ID, stamp
   every response with it, emit structured start/end log lines.
2. Identity enforcement — extract the client CN (from the TLS peer
   cert or from nginx-forwarded headers, per NGINX_MODE) and check it
   against ALLOWED_CLIENT_CNS; short-circuit non-admitted requests
   to 403 before any route handler runs.

Layering note
-------------
In the v1.0 direct-mTLS path the TLS handshake has already succeeded by
the time this middleware runs — the ssl module rejected "no cert
presented" and "cert signed by unknown CA" at the handshake. This
middleware adds an *additional* identity-based check on top.

In the v1.1 NGINX_MODE path, TLS terminates at nginx and the peer-cert
fields arrive as HTTP headers. The four invariants below keep that
channel from becoming a bypass:

Security invariants (N2)
------------------------
SI-1: X-Client-CN is trusted ONLY when ``request.client.host`` is in
      ``config.TRUSTED_PROXY_IPS``. Anyone reaching FastAPI's plain-HTTP
      port directly with a forged header is denied at the IP gate.
SI-2: ``X-Client-Verify`` must be the literal string ``"SUCCESS"`` —
      defence-in-depth beyond the IP check. Covers the case where
      nginx proxies even when its own ssl_verify_client failed.
SI-3: CN sanitisation rejects embedded CR / LF / NUL and strips
      surrounding whitespace, preventing log-injection forgery of a
      second log line.
SI-4: In NGINX_MODE with empty ``TRUSTED_PROXY_IPS``, the server
      refuses to start (``sys.exit(2)`` in ``server.main``). See
      ``server._main_nginx_mode``.

Logging discipline
------------------
Never log the full peer certificate. We log only the CN and a short hash
of the Subject DN (``subject_fingerprint``) — enough to correlate requests
from the same client without exposing the cert itself.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from config import ALLOWED_CLIENT_CNS, NGINX_MODE, TRUSTED_PROXY_IPS

logger = logging.getLogger(__name__)


# --- Cert inspection helpers ------------------------------------------------


def extract_cn_from_cert(peer_cert: dict[str, Any] | None) -> str | None:
    """Return the Subject CommonName from a stdlib-format peer cert dict.

    Accepts the nested-tuple structure produced by
    ``ssl.SSLSocket.getpeercert()`` (the only format this project cares
    about — we never parse DER ourselves).

    SECURITY: unexpected shapes (wrong nesting depth, non-iterable RDNs)
    are treated as "no CN found" rather than propagating the exception.
    The allowlist check above then denies the request with reason
    ``no_peer_cert`` — a fail-closed posture consistent with the rest
    of the stack.
    """
    if not peer_cert:
        return None
    for rdn in peer_cert.get("subject", ()):
        try:
            for key, value in rdn:
                if key == "commonName":
                    return value
        except (TypeError, ValueError):
            # Malformed RDN — fail closed by skipping, keep scanning.
            continue
    return None


def extract_cn_from_headers(request: Request) -> str | None:
    """Return the CN forwarded by a trusted nginx proxy, or None.

    NGINX_MODE counterpart to ``extract_cn_from_cert``. Used when
    nginx terminates mTLS on :443 and forwards the peer-cert fields
    as HTTP headers to FastAPI on 127.0.0.1:8443 (plain HTTP).

    SECURITY (SI-1): the ``X-Client-CN`` header is trusted ONLY when
    the request's source IP is in ``config.TRUSTED_PROXY_IPS``. Any
    caller reaching this port directly from a non-proxy IP could
    otherwise forge the header and bypass auth entirely.

    Returns None if the IP check fails, the header is absent, or
    anything is off. The caller treats a None return as "no valid
    client identity" and responds with 403.
    """
    client_ip = request.client.host if request.client else "-"
    if client_ip not in TRUSTED_PROXY_IPS:
        logger.warning(
            "untrusted_proxy_cn_header_blocked mode=nginx client_ip=%s",
            client_ip,
        )
        return None

    # SECURITY (SI-2): nginx sets X-Client-Verify to the string
    # ``SUCCESS`` only when ssl_verify_client succeeded — it will be
    # ``NONE`` / ``FAILED:<reason>`` otherwise. A defence-in-depth
    # belt-and-braces check beyond the IP trust gate: if nginx
    # forwarded the request but marks verification as failed, we
    # refuse to honour the CN.
    verify = request.headers.get("X-Client-Verify", "")
    if verify != "SUCCESS":
        logger.warning(
            "nginx_cert_verify_not_success mode=nginx value=%r client_ip=%s",
            verify,
            client_ip,
        )
        return None

    raw_cn = request.headers.get("X-Client-CN")
    if raw_cn is None:
        return None

    # SECURITY (SI-3): even though the IP trust gate keeps most
    # adversaries out, a bug in nginx's sanitisation or a future
    # config mistake could put a forged CN into this path. Reject
    # anything that could forge a second log line or truncate
    # downstream: embedded newlines, carriage returns, or NUL
    # bytes. Whitespace is stripped; the resulting empty string
    # is also a reject (empty CN is meaningless for the allowlist).
    cn = raw_cn.strip()
    if not cn or "\n" in cn or "\r" in cn or "\x00" in cn:
        logger.warning(
            "cn_sanitisation_failed mode=nginx reason=%s client_ip=%s",
            "empty" if not cn else "control_char",
            client_ip,
        )
        return None

    return cn


def resolve_client_cn(
    request: Request,
    peer_cert: dict[str, Any] | None,
) -> str | None:
    """Dispatch to the right CN extractor based on ``NGINX_MODE``.

    - ``NGINX_MODE=true``  → trust nginx-forwarded headers (gated by
       IP / X-Client-Verify / sanitisation in ``extract_cn_from_headers``).
    - ``NGINX_MODE=false`` → parse the cert dict handed up by the
       stdlib ``ssl`` module (the v1.0 direct-mTLS path).

    Module-level constant ``NGINX_MODE`` is read from the config
    module — tests monkeypatch ``middleware.NGINX_MODE`` directly to
    exercise both branches.
    """
    if NGINX_MODE:
        return extract_cn_from_headers(request)
    return extract_cn_from_cert(peer_cert)


def subject_fingerprint(peer_cert: dict[str, Any] | None) -> str:
    """Short SHA-256 of the Subject DN — safe to log, stable across runs."""
    if not peer_cert:
        return "-"
    subject = peer_cert.get("subject", ())
    flat = "/".join(f"{key}={value}" for rdn in subject for key, value in rdn)
    return hashlib.sha256(flat.encode("utf-8")).hexdigest()[:16]


# --- 403 helper -------------------------------------------------------------


def _forbidden(cn: str | None, reason: str, request_id: str) -> JSONResponse:
    # SECURITY: body schema is fixed by project rules — error/cn/reason.
    # No stack traces, no TLS details, no allowlist contents echoed back.
    # Including the CN lets ops correlate denial events; the client already
    # knows their own CN, so nothing is leaked that they don't already have.
    body = {
        "error": "forbidden",
        "cn": cn or "",
        "reason": reason,
    }
    response = JSONResponse(status_code=403, content=body)
    response.headers["X-Request-ID"] = request_id
    return response


# --- Middleware -------------------------------------------------------------


class ClientIdentityMiddleware(BaseHTTPMiddleware):
    """Attach request context and enforce the CN allowlist.

    Placement: must run BEFORE any route handler. Installed with
    ``app.add_middleware(ClientIdentityMiddleware)`` in server.py.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        peer_cert: dict[str, Any] | None = (
            request.scope.get("extensions", {}).get("tls", {}).get("peer_cert")
        )
        client_cn = resolve_client_cn(request, peer_cert)
        fingerprint = subject_fingerprint(peer_cert)
        peer_addr = request.client.host if request.client else "-"

        # Always attach context to request.state so route handlers and error
        # paths alike see the identity.
        request.state.request_id = request_id
        request.state.client_cn = client_cn
        request.state.subject_fingerprint = fingerprint

        logger.info(
            "req_start method=%s path=%s cn=%s subj=%s reqid=%s peer=%s",
            request.method,
            request.url.path,
            client_cn or "-",
            fingerprint,
            request_id,
            peer_addr,
        )

        # SECURITY: in normal operation the TLS layer guarantees a verified
        # peer cert is present by the time we get here. If peer_cert is
        # absent, something upstream is mis-configured — fail closed.
        if client_cn is None:
            logger.warning(
                "authz_reject reason=no_peer_cert reqid=%s peer=%s",
                request_id,
                peer_addr,
            )
            return _forbidden(None, "no_peer_cert", request_id)

        # SECURITY: allowlist check — a cert that chains to our CA is not
        # sufficient; the identity must also be on the admit list.
        if client_cn not in ALLOWED_CLIENT_CNS:
            logger.warning(
                "authz_reject reason=cn_not_allowlisted cn=%s subj=%s reqid=%s peer=%s",
                client_cn,
                fingerprint,
                request_id,
                peer_addr,
            )
            return _forbidden(client_cn, "cn_not_allowlisted", request_id)

        try:
            response = await call_next(request)
        except Exception as exc:
            # SECURITY: log internally, respond generically; never leak
            # stack traces or internal detail across the TLS boundary.
            logger.exception("req_error reqid=%s :: %s", request_id, exc)
            response = JSONResponse(
                status_code=500,
                content={"error": "internal_error", "request_id": request_id},
            )

        response.headers["X-Request-ID"] = request_id
        logger.info(
            "req_end   method=%s path=%s cn=%s reqid=%s status=%d",
            request.method,
            request.url.path,
            client_cn,
            request_id,
            response.status_code,
        )
        return response


__all__ = [
    "ClientIdentityMiddleware",
    "extract_cn_from_cert",
    "extract_cn_from_headers",
    "resolve_client_cn",
    "subject_fingerprint",
]
