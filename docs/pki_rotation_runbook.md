# PKI Rotation Runbook

Operational guide for the project's ED25519 PKI. Each section maps
to a T5 test ID; the test is the executable form of the behaviour
documented here.

## 1. Initial PKI bootstrap

```bash
./pki_setup.sh           # idempotent; leaves existing certs alone
./pki_setup.sh --force   # wipe and regenerate
```

Produces the full tree under `pki/`:

| Role   | Cert                    | Key                    | Days |
|--------|-------------------------|------------------------|:----:|
| CA     | `pki/ca/ca.crt`         | `pki/ca/ca.key`        | 3650 |
| Server | `pki/server/server.crt` | `pki/server/server.key`| 365  |
| Client | `pki/client/client.crt` | `pki/client/client.key`| 365  |

CA DB files (`index.txt`, `serial`, `crlnumber`, `newcerts/`) are
initialised too so `openssl ca` is ready for CRL operations.

## 2. CRL lifecycle

### Normal operation

`server.py::_refresh_crl` regenerates `pki/ca/ca.crl` on every
server start (`openssl ca -gencrl`). This resets `nextUpdate` to
`now + 7 days` (see `default_crl_days` in `pki/openssl.cnf`).

As long as the server is restarted at least weekly, the CRL stays
fresh.

### Revoke a client

```bash
./tests/revoke_client.sh   # revokes pki/client/client.crt; regenerates CRL
make stop && make server   # pick up the new CRL (restart required)
```

### Safety invariants (enforced by tests)

| Scenario                                   | Behaviour                                      | Test  |
|--------------------------------------------|------------------------------------------------|-------|
| CRL file expired (nextUpdate in the past)  | Context still flags VERIFY_CRL_CHECK_LEAF; subsequent handshakes fail at OpenSSL's CRL_HAS_EXPIRED check | CR1   |
| CRL path missing                           | `build_server_context` raises `FileNotFoundError` — NEVER silent fail-open | CR2   |
| CRL from wrong CA                          | Loads; has no authority over the real CA's certs | CR3   |
| Empty CRL                                  | Valid clients admitted                         | CR4   |
| 1000-entry CRL                             | Context builds in < 2s                         | CR5   |

**Time-bomb alert (ultrareview bug004):** do NOT disable the
startup `_refresh_crl()` call — it is the only thing keeping the
CRL's `nextUpdate` from rolling into the past after a week.

## 3. Certificate expiry

### Client cert

`make renew` rotates `pki/client/client.crt` to a fresh 24-hour
cert; schedule via cron (e.g. `0 */12 * * *`). The script uses
`os.replace()` for atomicity.

### Server cert

Currently rotated by hand. `server.py` emits a WARNING log line at
startup if the server cert is within 7 days of `notAfter`:

```
WARN mtls_api :: server_cert_near_expiry remaining_days=4.3 not_after=...
```

### CA cert

10-year validity. When the CA cert itself is within one year of
expiry, plan a CA rotation (§4).

### Invariants

| Scenario                            | Behaviour                     | Test |
|-------------------------------------|-------------------------------|------|
| Client cert expires mid-session     | OpenSSL rejects at connection time | EX1  |
| Server cert near expiry at startup  | WARNING logged                | EX2 (server.py::_warn_if_server_cert_near_expiry) |
| CA cert already expired             | Chain verification fails      | EX3  |
| Client cert with future notBefore   | OpenSSL rejects (clock-skew attack) | EX4 |

## 4. CA key rotation

### Full rotation (old CA compromised)

1. Generate a new CA (`pki_setup.sh --force` with renamed output paths).
2. Sign new leaves against the new CA for every client and the server.
3. Deploy new leaves to clients and the server.
4. Remove the old CA cert from `pki/ca/ca.crt` — clients will stop
   trusting leaves still signed by the old CA.
5. Restart the server.

### Cross-signing (gradual migration)

To allow clients to keep using old leaves while transitioning:

1. Mint the new CA.
2. Build a bundle: `cat old/ca.crt new/ca.crt > pki/ca/ca.crt`.
3. Restart the server. Both old and new leaves are trusted.
4. Migrate clients one at a time.
5. When all clients have been migrated, remove the old CA from the
   bundle and restart.

### Invariants

| Scenario                                   | Behaviour                              | Test |
|--------------------------------------------|----------------------------------------|------|
| Full rotation, old leaf                    | Rejected (unknown issuer)              | CA1  |
| Cross-sign period, old leaf                | Accepted                               | CA2  |
| CA removed from trust bundle               | Every leaf signed by it is rejected    | CA3  |

## 5. Server cert rotation

| Scenario                                      | Behaviour                                  | Test |
|-----------------------------------------------|--------------------------------------------|------|
| New server cert, same CA                      | Clients continue to admit                  | SR2  |
| Multi-CA bundle, leaves from either trusted   | Both leaves verify                         | SR3  |

**Deferred features (skipped tests, tracked here):**

- **SR1 — Hot server-cert rotation via SIGHUP.** Current flow is
  stop + swap file + start. A SIGHUP handler that rebuilds
  `tls_ctx` via `build_server_context()` and re-installs it on
  uvicorn's running config would give zero-downtime rotation.
- **SR4 — Concurrent rotation atomicity.** The rotation-under-
  load correctness test is SR1-dependent.
- **CR6 — CRL regeneration mid-flight.** SSLContext caches CRL
  data at load. A reload hook (same SIGHUP target as SR1) would
  close this gap.

## 6. Allowlist management

`config.ALLOWED_CLIENT_CNS` is a `frozenset[str]` loaded at
import time. Changes require editing `config.py` and restarting
the server.

### Invariants

| Scenario                                     | Behaviour                                | Test |
|----------------------------------------------|------------------------------------------|------|
| 1000-CN allowlist lookup time                | O(1); 100k lookups < 0.5s                | AL3  |
| Allowlist data structure is `frozenset`      | Locked in by AL3                         | AL3  |

**Deferred features:**

- **AL1 / AL2 — Runtime allowlist reload.** Same SIGHUP target.
  Would read `config.py` off disk and replace
  `config.ALLOWED_CLIENT_CNS` atomically. The frozenset invariant
  (AL3) must be preserved across reloads.

## 7. Implementing the deferred features

The deferred features (SR1, SR4, CR6, AL1, AL2) all converge on a
single SIGHUP reload handler. Sketch:

```python
# server.py, inside main()
import signal

def _reload(signum, frame):
    # Rebuild SSLContext and replace uvicorn's cached one.
    new_ctx = build_server_context(SERVER_CERT, SERVER_KEY, CA_CERT, CA_CRL)
    uvicorn_server.config.ssl = new_ctx
    # Re-import config module to pick up allowlist edits.
    importlib.reload(config)

signal.signal(signal.SIGHUP, _reload)
```

Caveats:

* uvicorn's active connections keep using the OLD SSLContext until
  they close — new connections pick up the new one. Fine for
  rotation but means "hot" rotation still drains.
* The `importlib.reload` path loses references held by other
  modules (e.g. middleware's cached `ALLOWED_CLIENT_CNS`). The
  cleanest fix is to expose a `config.get_allowlist()` function
  that always reads the current frozenset.

When implemented, re-enable the deferred tests in
`tests/test_pki_lifecycle.py`.
