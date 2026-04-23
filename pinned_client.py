"""Certificate-pinned mTLS client — stdlib only.

What this demonstrates
----------------------
On top of normal CA-based validation, the client also verifies that the
server's *exact* leaf certificate matches a known SHA-256 fingerprint
("pinning"). That means a malicious CA (or a compromised-but-still-trusted
intermediate) that issues a fresh cert for the same hostname is still
rejected, because its fingerprint will not match the pin.

SECURITY invariants
-------------------
* Pinning is done over the RAW DER bytes via
  ``ssl.SSLSocket.getpeercert(binary_form=True)``. Never hash the parsed
  dict from ``getpeercert()`` — that discards fields that contribute to
  the identity of the cert.
* Fingerprinting uses ``hashlib.sha256`` — stdlib, no third-party lib.
* Mismatch raises, the script exits non-zero, and the connection is closed
  before any application data flows.

Extracting the server fingerprint
---------------------------------
The expected pin is the SHA-256 over the raw DER of the server cert.
Extract it once after setup::

    openssl x509 -in pki/server/server.crt -noout -fingerprint -sha256

which prints something like::

    SHA256 Fingerprint=4E:A3:...:9F

Feed that into this script one of three ways (first-match wins):

    1. ``--pin <value>`` on the CLI (colons optional, case-insensitive)
    2. ``MTLS_PIN`` environment variable
    3. ``pki/server/server.fingerprint`` file containing the pin
"""

from __future__ import annotations

import argparse
import hashlib
import os
import socket
import ssl
import sys
from pathlib import Path

# --- Paths ------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent
PKI_DIR = REPO_ROOT / "pki"

CA_CERT = PKI_DIR / "ca" / "ca.crt"
CLIENT_CERT = PKI_DIR / "client" / "client.crt"
CLIENT_KEY = PKI_DIR / "client" / "client.key"
PIN_FILE = PKI_DIR / "server" / "server.fingerprint"

SERVER_HOST = "localhost"
SERVER_PORT = 8443


def _normalise_pin(raw: str) -> str:
    """Strip whitespace/colons, drop any ``openssl x509 -fingerprint`` prefix,
    and uppercase.

    Accepts every form the docstring advertises:
      * bare hex                     "AABB...FF"
      * colon-separated              "AA:BB:...:FF"
      * openssl one-line output      "SHA256 Fingerprint=AA:BB:...:FF"
      * same, lowercased             "sha256 Fingerprint=aa:bb:...:ff"

    Splitting on "=" here (rather than only in the file branch) ensures
    --pin and MTLS_PIN accept the literal output of the documented
    extraction recipe too, not just file input.
    """
    s = raw.strip()
    if "=" in s:
        s = s.split("=", 1)[1]
    return s.replace(":", "").replace(" ", "").upper()


def _load_expected_pin(cli_pin: str | None) -> str:
    """Resolve the expected pin from CLI flag, env var, or file — in that order.

    Returns the normalised (hex, uppercase, no colons) pin value.
    """
    if cli_pin:
        return _normalise_pin(cli_pin)
    env = os.environ.get("MTLS_PIN")
    if env:
        return _normalise_pin(env)
    if PIN_FILE.is_file():
        return _normalise_pin(PIN_FILE.read_text())
    raise SystemExit(
        "No pin supplied. Pass --pin, set MTLS_PIN, "
        f"or drop a fingerprint into {PIN_FILE}."
    )


def _build_client_context() -> ssl.SSLContext:
    """Client SSLContext: trust our CA, present our client cert."""
    # SECURITY: purpose=SERVER_AUTH + load_verify_locations(cafile=ca.crt)
    # is what CA-verifies the server. Pinning is an ADDITIONAL check on top.
    # Never replace it — without CA validation, a pin mismatch is the ONLY
    # protection, and a lucky attacker could skip verification entirely.
    ctx = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH, cafile=str(CA_CERT)
    )
    ctx.load_cert_chain(certfile=str(CLIENT_CERT), keyfile=str(CLIENT_KEY))
    return ctx


def _sha256_fingerprint(der_bytes: bytes) -> str:
    """SHA-256 of the raw DER cert bytes, uppercased hex, no colons."""
    return hashlib.sha256(der_bytes).hexdigest().upper()


def _format_with_colons(fp: str) -> str:
    """Render a 64-char hex fp as AA:BB:CC:... (aid for human reading)."""
    return ":".join(fp[i : i + 2] for i in range(0, len(fp), 2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--pin",
        help="Expected SHA-256 fingerprint (colons optional). "
        "Overrides MTLS_PIN env var and pki/server/server.fingerprint.",
    )
    parser.add_argument(
        "--host", default=SERVER_HOST, help="Server hostname (default: localhost)"
    )
    parser.add_argument("--port", type=int, default=SERVER_PORT)
    parser.add_argument("--path", default="/health", help="HTTP path to GET")
    args = parser.parse_args(argv)

    for path in (CA_CERT, CLIENT_CERT, CLIENT_KEY):
        if not path.is_file():
            print(f"[SETUP-FAIL] missing {path}", file=sys.stderr)
            return 2

    try:
        expected_pin = _load_expected_pin(args.pin)
    except SystemExit as exc:
        print(f"[SETUP-FAIL] {exc}", file=sys.stderr)
        return 2

    ctx = _build_client_context()

    # Connect and handshake.
    try:
        with socket.create_connection((args.host, args.port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=args.host) as ssock:
                # SECURITY: binary_form=True returns the raw DER bytes. The
                # parsed dict form is a LOSSY representation and cannot be
                # used for cryptographic identification.
                der = ssock.getpeercert(binary_form=True)
                if not der:
                    print("[ERROR] server presented no cert (impossible under mTLS)")
                    return 1

                got_pin = _sha256_fingerprint(der)
                print(f"expected pin: {_format_with_colons(expected_pin)}")
                print(f"got pin:      {_format_with_colons(got_pin)}")

                # SECURITY: compare with hmac.compare_digest-like timing, but
                # since both strings are already the server-supplied + our
                # known value, timing doesn't leak anything sensitive here.
                # Plain equality is fine.
                if got_pin != expected_pin:
                    print(
                        "[FAIL] fingerprint mismatch — aborting before any "
                        "application data is sent.",
                        file=sys.stderr,
                    )
                    return 1

                print("[PASS] fingerprint matches the pin.")

                # Send a minimal HTTP request to prove the channel is usable.
                req = (
                    f"GET {args.path} HTTP/1.1\r\n"
                    f"Host: {args.host}\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                )
                ssock.sendall(req.encode("ascii"))
                chunks: list[bytes] = []
                while True:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                raw = b"".join(chunks).decode("utf-8", errors="replace")
                status_line = raw.splitlines()[0] if raw else "<empty>"
                body = raw.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in raw else raw
                print(f"\n{args.host}:{args.port}{args.path} -> {status_line}")
                print(f"body: {body.strip()}")

    except ssl.SSLError as exc:
        print(f"[FAIL] TLS error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"[SETUP-FAIL] network error: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
