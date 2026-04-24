"""Throwaway-PKI helpers for TLS attack tests.

Every routine here writes into an isolated ``tempfile.mkdtemp()`` that
the caller supplies. Nothing in this module touches ``pki/`` — the
project's real PKI is off-limits to attack-cert generation.

SKILL-01 rules apply: ED25519 only. No RSA/ECDSA keys are ever
generated here, including in throwaway CAs.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


# Minimal OpenSSL config for throwaway CAs. Paths inside ``[CA_default]``
# are intentionally relative so we can ``cd`` into the per-CA tempdir
# and let openssl compute everything from there.
_CA_CONFIG = """\
[req]
distinguished_name = req_dn
prompt             = no

[req_dn]

[v3_ca]
basicConstraints     = critical, CA:TRUE
keyUsage             = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[v3_client]
basicConstraints       = CA:FALSE
keyUsage               = critical, {key_usage}
extendedKeyUsage       = {eku}
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid, issuer

[ca]
default_ca = CA_default

[CA_default]
dir               = .
certs             = .
crl_dir           = .
new_certs_dir     = ./newcerts
database          = ./index.txt
serial            = ./serial
crlnumber         = ./crlnumber
certificate       = ./ca.crt
private_key       = ./ca.key
crl               = ./ca.crl
unique_subject    = no
default_md        = default
default_days      = 365
default_crl_days  = 7
policy            = policy_any
copy_extensions   = none

[policy_any]
commonName              = supplied
organizationName        = optional
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationalUnitName  = optional
emailAddress            = optional
"""


def _run(args: list[str], *, cwd: Path) -> subprocess.CompletedProcess:
    """Run openssl (or any subprocess) and fail with full context."""
    result = subprocess.run(
        args,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{args!r} failed ({result.returncode}):\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result


@dataclass(frozen=True)
class Leaf:
    """A signed leaf cert + the key that owns it."""

    cert: Path
    key: Path


class RogueCA:
    """Throwaway ED25519 CA isolated in a single tempdir.

    Usage::

        ca = RogueCA(Path("/tmp/attack-abc"))
        leaf = ca.sign_client("client-01", key_usage="digitalSignature")
        # ... use leaf.cert, leaf.key ...
        ca.cleanup()

    Prefer the ``rogue_ca_factory`` pytest fixture from ``conftest.py``
    — it drives this class and handles cleanup automatically.
    """

    def __init__(self, root: Path, *, cn: str = "rogue-CA") -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "newcerts").mkdir(exist_ok=True)
        (self.root / "index.txt").touch()
        (self.root / "serial").write_text("01\n")
        (self.root / "crlnumber").write_text("01\n")

        self.config = self.root / "openssl.cnf"
        self._write_config(key_usage="digitalSignature", eku="clientAuth")

        self.ca_key = self.root / "ca.key"
        self.ca_cert = self.root / "ca.crt"

        _run(
            ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(self.ca_key)],
            cwd=self.root,
        )
        self.ca_key.chmod(0o600)
        _run(
            [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-key",
                str(self.ca_key),
                "-out",
                str(self.ca_cert),
                "-days",
                "3650",
                "-subj",
                f"/CN={cn}/O=RogueLab/C=MY",
                "-config",
                str(self.config),
                "-extensions",
                "v3_ca",
            ],
            cwd=self.root,
        )

    def _write_config(self, *, key_usage: str, eku: str) -> None:
        self.config.write_text(_CA_CONFIG.format(key_usage=key_usage, eku=eku))

    def sign_client(
        self,
        cn: str,
        *,
        days: int = 365,
        start: str | None = None,
        end: str | None = None,
        key_usage: str = "digitalSignature",
        eku: str = "clientAuth",
    ) -> Leaf:
        """Sign a client leaf using this CA.

        ``start``/``end`` accept OpenSSL ``YYMMDDHHMMSSZ`` syntax; when
        supplied they override ``days`` and are what enables the
        "expired" and "not yet valid" attack scenarios. ``key_usage``
        and ``eku`` go straight into the v3_client section of the
        temp config so we can emit, for example, ``dataEncipherment``
        leaves that violate the server's implicit KU expectations.
        """
        # Rewrite the config so the extension sections reflect the
        # requested key_usage/eku for this particular signing call.
        self._write_config(key_usage=key_usage, eku=eku)

        slug = cn.replace("/", "_").replace(" ", "_")
        key = self.root / f"{slug}.key"
        csr = self.root / f"{slug}.csr"
        cert = self.root / f"{slug}.crt"

        _run(
            ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)],
            cwd=self.root,
        )
        key.chmod(0o600)
        _run(
            [
                "openssl",
                "req",
                "-new",
                "-key",
                str(key),
                "-out",
                str(csr),
                "-subj",
                f"/CN={cn}/O=RogueLab/C=MY",
                "-config",
                str(self.config),
            ],
            cwd=self.root,
        )

        sign_args = [
            "openssl",
            "ca",
            "-config",
            str(self.config),
            "-batch",
            "-notext",
            "-in",
            str(csr),
            "-out",
            str(cert),
            "-extensions",
            "v3_client",
        ]
        if start is not None and end is not None:
            sign_args += ["-startdate", start, "-enddate", end]
        else:
            sign_args += ["-days", str(days)]
        _run(sign_args, cwd=self.root)
        cert.chmod(0o644)

        return Leaf(cert=cert, key=key)

    def sign_client_with_serial(self, cn: str, serial: int) -> Leaf:
        """Sign a leaf using ``openssl x509 -set_serial`` so we can force
        a specific serial number — two leaves with the same serial
        are the input to the CRL-confusion test (E2).
        """
        slug = f"{cn}-{serial:x}".replace("/", "_").replace(" ", "_")
        key = self.root / f"{slug}.key"
        csr = self.root / f"{slug}.csr"
        cert = self.root / f"{slug}.crt"

        _run(
            ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)],
            cwd=self.root,
        )
        key.chmod(0o600)
        _run(
            [
                "openssl",
                "req",
                "-new",
                "-key",
                str(key),
                "-out",
                str(csr),
                "-subj",
                f"/CN={cn}/O=RogueLab/C=MY",
                "-config",
                str(self.config),
            ],
            cwd=self.root,
        )
        _run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(csr),
                "-CA",
                str(self.ca_cert),
                "-CAkey",
                str(self.ca_key),
                "-set_serial",
                str(serial),
                "-days",
                "365",
                "-out",
                str(cert),
                "-extfile",
                str(self.config),
                "-extensions",
                "v3_client",
            ],
            cwd=self.root,
        )
        cert.chmod(0o644)
        return Leaf(cert=cert, key=key)

    def revoke_and_regen_crl(self, leaf: Leaf) -> Path:
        """Mark ``leaf`` as revoked in this CA's DB and rebuild its CRL."""
        _run(
            [
                "openssl",
                "ca",
                "-config",
                str(self.config),
                "-revoke",
                str(leaf.cert),
            ],
            cwd=self.root,
        )
        crl = self.root / "ca.crl"
        _run(
            [
                "openssl",
                "ca",
                "-config",
                str(self.config),
                "-gencrl",
                "-out",
                str(crl),
            ],
            cwd=self.root,
        )
        return crl

    def cleanup(self) -> None:
        """Remove the entire tempdir. Safe to call more than once."""
        if self.root.exists():
            shutil.rmtree(self.root, ignore_errors=True)


def mirror_existing_ca(
    src_cert: Path,
    src_key: Path,
    dir: Path,
) -> RogueCA:
    """Build a ``RogueCA`` around an existing CA cert/key pair.

    The CA identity (public key, DN, self-signature) is unchanged —
    we only give it a fresh ``index.txt`` / ``serial`` / ``crlnumber``
    so tests can call ``openssl ca`` without touching the real CA's
    database in ``pki/ca/``.

    Use this to sign attack leaves (expired, not-yet-valid, wrong KU)
    that still chain to the project CA, so the TLS rejection is
    attributable to the specific leaf-level defect rather than
    "unknown issuer".
    """
    dir.mkdir(parents=True, exist_ok=True)
    # Start by constructing a normal throwaway CA, then overwrite its
    # ca.key/ca.crt with copies of the real ones.
    ca = RogueCA(dir, cn="mirror-placeholder")
    shutil.copyfile(str(src_cert), str(ca.ca_cert))
    shutil.copyfile(str(src_key), str(ca.ca_key))
    ca.ca_key.chmod(0o600)
    ca.ca_cert.chmod(0o644)
    # Reset the DB state that the placeholder-CA's self-signing left
    # behind so serials start fresh.
    (ca.root / "index.txt").write_text("")
    (ca.root / "serial").write_text("01\n")
    (ca.root / "crlnumber").write_text("01\n")
    newcerts = ca.root / "newcerts"
    if newcerts.exists():
        shutil.rmtree(newcerts)
    newcerts.mkdir()
    return ca


def make_self_signed_client(dir: Path, cn: str) -> Leaf:
    """Produce a standalone self-signed client cert (no CA chain at all).

    Used for C5: the server must reject a peer whose cert does not
    chain to any trusted CA, even if the peer DN looks legitimate.
    """
    dir.mkdir(parents=True, exist_ok=True)
    key = dir / "selfsigned.key"
    cert = dir / "selfsigned.crt"
    _run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)], cwd=dir)
    key.chmod(0o600)
    _run(
        [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-key",
            str(key),
            "-out",
            str(cert),
            "-days",
            "365",
            "-subj",
            f"/CN={cn}/O=SelfSigned/C=MY",
        ],
        cwd=dir,
    )
    cert.chmod(0o644)
    return Leaf(cert=cert, key=key)
