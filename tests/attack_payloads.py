"""Centralised attack string constants for T6 penetration tests.

Each payload is small, non-ambiguous, and carries a one-line comment
explaining what it probes. Tests import the constants instead of
embedding the strings, so a single change to an adversarial payload
updates every test that uses it.

ASCII-escapes are deliberately spelled out as ``"\\x1b"`` etc. rather
than literal control bytes so the file stays readable and grep-able.
"""

from __future__ import annotations


# --- CN-injection payloads --------------------------------------------------

# ANSI escape sequence that would colourise a naive log line in a TTY.
CN_ANSI_ESCAPE = "\x1b[31mevil\x1b[0m"

# Embedded newline — would forge a second log line if the server
# echoed CN verbatim into logs without sanitising.
CN_WITH_NEWLINE = "client-01\nadmin"

# Legit-looking dotted extension — tests that allowlist match is
# exact, not startswith.
CN_WITH_DOTTED_SUFFIX = "client-01.evil.com"

# Null byte after a legit prefix — a C-level string handler might
# truncate here, making naive comparisons think the CN is "client-01".
CN_WITH_NULL_BYTE = "client-01\x00.evil"

# Leading whitespace — a string-stripping bypass. Allowlist must
# compare the RAW CN, not a trimmed one.
CN_WITH_LEADING_SPACE = " client-01"

# --- Allowlist-bypass payloads ----------------------------------------------

CN_UPPERCASE = "CLIENT-01"
# Unicode hyphen-minus (U+002D) is the same codepoint as ASCII '-';
# this string is byte-equal to "client-01" and should therefore be
# admitted. Used to make the "no unicode normalisation" assertion
# specific — if admission flips to 403, someone added normalisation.
CN_UNICODE_IDENTICAL = "client-01"

# --- Log-injection payloads -------------------------------------------------

XRID_WITH_NEWLINE = "legit-id\n[CRITICAL] fake log entry"

# --- Request-smuggling raw bytes -------------------------------------------
#
# These are raw HTTP requests sent over a TLS socket, so they stay as
# bytes. Content-Length / Transfer-Encoding conflict is the classic
# smuggling primitive; the server must refuse to process them.

SMUGGLE_CL_AND_TE = (
    b"POST /data HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: 50\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n"
    b"0\r\n\r\n"
)

SMUGGLE_LINE_FOLDING = (
    b"GET /health HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"X-Custom: line1\r\n"
    b" line2-continuation\r\n"
    b"\r\n"
)

SMUGGLE_TE_ZERO_CHUNK = (
    b"POST /data HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"Content-Type: application/json\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n"
    b"0\r\n\r\n"
)
