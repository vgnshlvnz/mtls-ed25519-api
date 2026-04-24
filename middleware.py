"""Request middleware for the mTLS REST API.

One middleware class combines two responsibilities:

1. Request-context tagging — assign (or honour) an X-Request-ID, stamp
   every response with it, emit structured start/end log lines.
2. Identity enforcement — extract the peer cert's Subject CommonName and
   check it against ALLOWED_CLIENT_CNS; short-circuit non-admitted
   requests to 403 before any route handler runs.

Layering note
-------------
By the time this middleware runs, the TLS handshake has already succeeded:
the ssl module rejected "no cert presented" and "cert signed by unknown
CA" at the handshake. This middleware adds an *additional* identity-based
check on top of that TLS verification.

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

from config import ALLOWED_CLIENT_CNS

logger = logging.getLogger(__name__)


# --- Cert inspection helpers ------------------------------------------------


def extract_cn(peer_cert: dict[str, Any] | None) -> str | None:
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


_CONTROL_CHARS = {chr(c) for c in range(32)} | {chr(127)}


def _safe_for_log(value: str | None) -> str:
    """Return a version of ``value`` safe to interpolate into a log line.

    Replaces control characters (incl. newline, null byte, ANSI
    escape's ESC) with ``\\u00XX``-style hex, so a forged CN
    cannot inject colour codes or newlines into the log stream.
    Used by ``dispatch`` when building the structured log lines;
    the underlying CN value on ``request.state.client_cn`` is
    UNCHANGED — only the logged form is neutered.
    """
    if value is None:
        return "-"
    return "".join(c if c not in _CONTROL_CHARS else f"\\x{ord(c):02x}" for c in value)


def subject_fingerprint(peer_cert: dict[str, Any] | None) -> str:
    """Short SHA-256 of the Subject DN — safe to log, stable across runs."""
    if not peer_cert:
        return "-"
    subject = peer_cert.get("subject", ())
    flat = "/".join(f"{key}={value}" for rdn in subject for key, value in rdn)
    return hashlib.sha256(flat.encode("utf-8")).hexdigest()[:16]


def cert_serial(peer_cert: dict[str, Any] | None) -> str:
    """Return the peer cert's serial number (hex string) for audit logs.

    Returns ``"-"`` when no peer cert is available. The serial is the
    closest thing to a stable unique identifier for a single issued
    cert — operators need it to correlate revocation events with
    log lines (T10 CA3).
    """
    if not peer_cert:
        return "-"
    # stdlib getpeercert() exposes serial under "serialNumber" as a hex
    # string (upper-case, no 0x). Keep that format verbatim for
    # correlation with `openssl x509 -noout -serial` output.
    return str(peer_cert.get("serialNumber", "-"))


def cert_not_after(peer_cert: dict[str, Any] | None) -> str:
    """Return the peer cert's notAfter string for audit logs.

    stdlib formats this as a GMT datetime string (``"Apr 24 00:00:00
    2027 GMT"``). Pass through as-is; callers that want ISO 8601
    parse on their end.
    """
    if not peer_cert:
        return "-"
    return str(peer_cert.get("notAfter", "-"))


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
        client_cn = extract_cn(peer_cert)
        fingerprint = subject_fingerprint(peer_cert)
        serial = cert_serial(peer_cert)
        not_after = cert_not_after(peer_cert)
        peer_addr = request.client.host if request.client else "-"

        # Always attach context to request.state so route handlers and error
        # paths alike see the identity.
        request.state.request_id = request_id
        request.state.client_cn = client_cn
        request.state.subject_fingerprint = fingerprint

        logger.info(
            "req_start",
            extra={
                "event": "req_start",
                "method": request.method,
                "path": request.url.path,
                "cn": _safe_for_log(client_cn),
                "subj": fingerprint,
                "cert_serial_number": serial,
                "cert_not_after": not_after,
                "reqid": request_id,
                "peer": peer_addr,
            },
        )

        # SECURITY: in normal operation the TLS layer guarantees a verified
        # peer cert is present by the time we get here. If peer_cert is
        # absent, something upstream is mis-configured — fail closed.
        if client_cn is None:
            logger.warning(
                "authz_reject",
                extra={
                    "event": "authz_reject",
                    "reason": "no_peer_cert",
                    "reqid": request_id,
                    "peer": peer_addr,
                },
            )
            return _forbidden(None, "no_peer_cert", request_id)

        # SECURITY: allowlist check — a cert that chains to our CA is not
        # sufficient; the identity must also be on the admit list.
        if client_cn not in ALLOWED_CLIENT_CNS:
            logger.warning(
                "authz_reject",
                extra={
                    "event": "authz_reject",
                    "reason": "cn_not_allowlisted",
                    "cn": _safe_for_log(client_cn),
                    "subj": fingerprint,
                    "reqid": request_id,
                    "peer": peer_addr,
                },
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
            "req_end",
            extra={
                "event": "req_end",
                "method": request.method,
                "path": request.url.path,
                "cn": _safe_for_log(client_cn),
                "reqid": request_id,
                "status": response.status_code,
            },
        )
        return response


__all__ = [
    "ClientIdentityMiddleware",
    "cert_not_after",
    "cert_serial",
    "extract_cn",
    "subject_fingerprint",
]
