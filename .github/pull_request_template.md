## Summary

<!-- One paragraph describing what this PR changes and why. -->

## Test checklist

- [ ] `ruff check .` clean
- [ ] `ruff format --check .` clean
- [ ] `shellcheck` clean on any changed `.sh`
- [ ] `pytest -m unit` passes
- [ ] `pytest -m integration` passes
- [ ] `pytest -m security` passes (if touching middleware / tls.py / server.py)
- [ ] `make test-cov` meets the 85% coverage gate
- [ ] New behaviour covered by a new / updated test
- [ ] `docs/` updated if an API contract, log event, or operational
      workflow changed

## Security checklist

- [ ] No private keys committed — `git log -- '*.key'` clean on this branch
- [ ] No `ssl.CERT_NONE`, `CERT_OPTIONAL`, or `verify=False`
- [ ] No `curl -k` / `--insecure` outside tests that specifically assert
      that flag's behaviour
- [ ] Every generated key is ED25519 (no RSA / ECDSA — see CLAUDE.md)
- [ ] No secret-ish strings in test fixtures (`tests/conftest.py`,
      `tests/_pki_factory.py` generate into `tempfile.mkdtemp()`)

## Handoff notes for downstream consumers

<!--
If this PR changes an API contract, log event schema, or operational
command surface, list the consumer that needs to know (next-phase
branch, release notes, runbook).
-->

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)
