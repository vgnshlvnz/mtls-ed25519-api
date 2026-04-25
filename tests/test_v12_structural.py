"""test_v12_structural.py — ST1/ST2/ST3 structural tests for v1.2.

These tests are deliberately different from every other test in the
suite: they do NOT run the server. They read the repo's source and
assert that certain modules, symbols, and imports **do not exist**.

Why: v1.2's core invariant is stated in negative form — *"FastAPI is
auth-blind; all auth lives in nginx.conf"* — and negative invariants
are notoriously easy to regress. A well-meaning refactor that
"helpfully" reads the X-Client-CN header would slip past every
positive test in the suite while completely unwinding the architecture.
These tests fail that refactor at CI time.

    ST1   Deleted modules (middleware.py, tls.py) stay deleted.
    ST2   config.py has no auth configuration (allowlist, proxy IP list,
          NGINX_MODE flag, …).
    ST3   server.py contains no TLS setup, no cert parsing, and does
          not read any X-Client-* header — those are nginx's concern.

If one of these fails, the right move is usually to back out whichever
commit added the offending code. If the addition is genuinely needed,
argue for it in the PR description and update this file explicitly in
the same change so the reviewer sees the invariant shifting.

Run:
    pytest tests/test_v12_structural.py -v
"""
# ruff: noqa: F811

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


# ============================================================================
# ST1 — deleted modules stay deleted
# ============================================================================


@pytest.mark.unit
@pytest.mark.security
def test_st1_middleware_module_absent() -> None:
    """middleware.py held v1.0/v1.1 auth. v1.2 deleted it.

    Its reappearance means someone is reviving the hybrid architecture
    (nginx + FastAPI both enforcing). That path is unsupported; the
    allowlist moves to nginx.conf's map{} block exclusively.
    """
    mw = REPO_ROOT / "middleware.py"
    assert not mw.exists(), (
        f"middleware.py reappeared at {mw}. v1.2 architecture puts ALL "
        "auth in nginx/nginx.conf. If you need a new auth concern, extend "
        "the map{} allowlist or add a new location{} block — do NOT add "
        "a Python middleware."
    )


@pytest.mark.unit
@pytest.mark.security
def test_st1_tls_module_absent() -> None:
    """tls.py held build_server_context + CertAwareH11Protocol. v1.2
    deleted it because FastAPI no longer terminates TLS (nginx does)."""
    tls_path = REPO_ROOT / "tls.py"
    assert not tls_path.exists(), (
        f"tls.py reappeared at {tls_path}. In v1.2 FastAPI speaks plain "
        "HTTP on 127.0.0.1:8443; all TLS terminates at nginx. If new TLS "
        "knobs are needed, add them to nginx/ssl_params.conf instead."
    )


# ============================================================================
# ST2 — config.py has no auth state
# ============================================================================


# Any of these names, declared at module level, would indicate a drift
# back toward v1.0 / v1.1. Each represents a distinct regression vector:
#   ALLOWED_CLIENT_CNS / ALLOWED_CNS / CLIENT_ALLOWLIST / ALLOWLIST
#       — a second source of truth for who gets in.
#   NGINX_MODE
#       — the v1.1 hybrid flag that toggled header-trust in middleware.
#   TRUSTED_PROXY_IPS / TRUSTED_PROXY_IP
#       — the complement to NGINX_MODE; used to gate the header trust.
_FORBIDDEN_CONFIG_NAMES: frozenset[str] = frozenset(
    {
        "ALLOWED_CLIENT_CNS",
        "ALLOWED_CNS",
        "CLIENT_ALLOWLIST",
        "ALLOWLIST",
        "NGINX_MODE",
        "TRUSTED_PROXY_IPS",
        "TRUSTED_PROXY_IP",
    }
)


@pytest.mark.unit
@pytest.mark.security
def test_st2_config_has_no_auth_module_state() -> None:
    """Parse config.py's AST and verify none of the forbidden names are
    declared at module level (as plain Assign or AnnAssign)."""
    config_src = (REPO_ROOT / "config.py").read_text(encoding="utf-8")
    tree = ast.parse(config_src)

    offenders: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and target.id in _FORBIDDEN_CONFIG_NAMES
                ):
                    offenders.append(target.id)
        elif isinstance(node, ast.AnnAssign):
            if (
                isinstance(node.target, ast.Name)
                and node.target.id in _FORBIDDEN_CONFIG_NAMES
            ):
                offenders.append(node.target.id)

    assert not offenders, (
        f"config.py declares forbidden auth state: {offenders}. In v1.2 "
        "the allowlist lives exclusively in nginx/nginx.conf's map{} "
        "block — there is no Python-side configuration for authz."
    )


# ============================================================================
# ST3 — server.py has no TLS, cert parsing, or X-Client-* trust
# ============================================================================


# (compiled regex, human-readable reason) pairs. Each entry picks one
# failure mode we've seen in prior iterations or that would clearly
# break the v1.2 invariant. Keep the reason short — it lands in the
# assertion message verbatim.
_BANNED_SERVER_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # --- TLS imports / primitives ---
    (re.compile(r"^\s*import\s+ssl\b", re.M), "ssl module imported"),
    (re.compile(r"^\s*from\s+ssl\s+import", re.M), "from ssl import ..."),
    (re.compile(r"\bssl\.SSLContext\b"), "ssl.SSLContext referenced"),
    (re.compile(r"\bSSLContext\s*\("), "SSLContext constructed"),
    (re.compile(r"\bssl_keyfile\b"), "uvicorn ssl_keyfile set"),
    (re.compile(r"\bssl_certfile\b"), "uvicorn ssl_certfile set"),
    (re.compile(r"\bCERT_REQUIRED\b"), "ssl.CERT_REQUIRED referenced"),
    (re.compile(r"\bCERT_OPTIONAL\b"), "ssl.CERT_OPTIONAL referenced"),
    (re.compile(r"\bverify_mode\b"), "TLS verify_mode set"),
    (re.compile(r"\bVERIFY_CRL_CHECK_LEAF\b"), "CRL flag set in Python"),
    # --- Cert parsing / peer-cert handling ---
    (re.compile(r"\bgetpeercert\b"), "peer cert parsed"),
    (re.compile(r"\bCertAwareH11Protocol\b"), "v1.0 cert-aware protocol"),
    (re.compile(r"\bX509\b"), "X509 primitive referenced"),
    (re.compile(r"\bload_verify_locations\b"), "CA loaded in Python"),
    (re.compile(r"\bload_cert_chain\b"), "cert chain loaded in Python"),
    # --- Trusted-header trap (header trust IS auth in disguise) ---
    (re.compile(r'["\']X-Client-CN["\']', re.I), "X-Client-CN header referenced"),
    (re.compile(r'["\']X-Client-Verify["\']', re.I), "X-Client-Verify referenced"),
    (re.compile(r'["\']X-Client-DN["\']', re.I), "X-Client-DN referenced"),
    (re.compile(r'["\']X-Client-Serial["\']', re.I), "X-Client-Serial referenced"),
    (
        re.compile(r'["\']X-Client-Fingerprint["\']', re.I),
        "X-Client-Fingerprint referenced",
    ),
    # --- Old middleware hook-up ---
    (re.compile(r"\bClientIdentityMiddleware\b"), "old middleware referenced"),
    (re.compile(r"\bfrom\s+middleware\s+import"), "import from deleted middleware"),
    (re.compile(r"\bfrom\s+tls\s+import"), "import from deleted tls"),
]


@pytest.mark.unit
@pytest.mark.security
def test_st3_server_has_no_tls_cert_or_header_trust() -> None:
    """Grep server.py for banned tokens. Any hit means the v1.2 invariant
    ("FastAPI is auth-blind") has been violated. The scan is literal
    text matching — no clever parsing — so it catches comments and
    docstring references too. This is intentional: even a comment
    that says "we should check X-Client-CN someday" is a signpost
    toward the wrong architecture."""
    src = (REPO_ROOT / "server.py").read_text(encoding="utf-8")

    offenders: list[str] = []
    for pattern, reason in _BANNED_SERVER_PATTERNS:
        if pattern.search(src):
            offenders.append(reason)

    assert not offenders, (
        f"server.py violates v1.2 structural invariant: {offenders}.\n"
        "FastAPI must remain auth-blind. If a new concern is legitimate, "
        "put it in nginx/nginx.conf or nginx/ssl_params.conf, not in "
        "Python."
    )
