# CI Architecture

Single-page map of the CI pipeline in `.github/workflows/`. Use
this to understand which jobs gate which, when each runs, and what
to tweak when a new test marker is added.

## Workflows

| File                                 | Trigger                                             |
|--------------------------------------|-----------------------------------------------------|
| `ci.yml`                             | push to main / develop / feature/** ; PR to main/develop |
| `release.yml`                        | tag push matching `v*.*.*`                           |
| `secret-scan.yml`                    | daily 04:00 UTC cron + push to main/develop         |

## Job DAG (ci.yml)

```
lint
├── pki-smoke
│    └── integration-tests (matrix: ubuntu-22.04, ubuntu-20.04)
│         ├── security-tests
│         ├── performance-regression (main/develop only)
│         └── coverage-gate ◄── unit-tests
└── unit-tests ◄── (coverage-gate joins here)
```

Eight jobs, numbered as in the T8 plan:

1. **lint** — `ruff check` + `ruff format --check` + `shellcheck` +
   `pre-commit`. 10 min.
2. **pki-smoke** — run `pki_setup.sh`, verify chains, assert
   every cert is Ed25519, assert `.key` files are not tracked.
   Caches `pki/` keyed on `pki_setup.sh` + `pki/openssl.cnf`.
   10 min.
3. **unit-tests** — `pytest -m unit` with pytest-xdist (`-n auto`).
   Uploads `coverage-unit.xml` + `junit-unit.xml`. 15 min.
4. **integration-tests** — restores `pki/` cache, runs
   `pytest -m "integration and not slow"` + legacy shell matrices.
   Matrix on ubuntu-22.04 and ubuntu-20.04. 20 min.
5. **security-tests** — `pytest -m security` + TLS attack matrix
   shell wrapper. Zero tolerance. 30 min.
6. **coverage-gate** — downloads all `coverage-*.xml` artifacts,
   enforces the 85% combined gate, posts a PR comment on success.
7. **performance-regression** — runs `pytest -m performance`
   against the stored baseline in `.benchmarks/`; fails on >20%
   median regression. Main / develop only.
8. **release-gate** (release.yml) — only on `v*.*.*` tag. Runs
   the full end-to-end flow (`make clean / pki / server / test /
   stop`) + pytest full suite + per-marker coverage assertion,
   and creates a GitHub Release with generated notes.

Plus the scheduled `secret-scan.yml` job:

- Scans `git log` for any `*.key` file that was ever committed.
- Greps the whole history for PEM private-key headers.
- Runs `gitleaks-action` for broader secret-pattern coverage.

## Concurrency policy

```yaml
concurrency:
  group: ci-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}
```

PR builds cancel in-progress on a new push (saves minutes on force-
pushes); main/develop builds always complete. No `continue-on-error:
true` anywhere in the workflows — every failure blocks the build.

## Cache keys

| Cache | Key                                                        |
|-------|------------------------------------------------------------|
| `pki/` | `pki-${{ hashFiles('pki_setup.sh', 'pki/openssl.cnf') }}` |
| pip   | `requirements-dev.txt` (via `setup-python`'s `cache: pip`) |

A change to `pki_setup.sh` or `openssl.cnf` busts the PKI cache,
so the integration suite always runs against a freshly-generated
chain after a setup-script change.

## When to update this file

- Add a new test marker → `release-gate` asserts at least one
  test under it. Add the marker to the `pytest.ini` registration
  and to the `for m in ...` loop in `release.yml`.
- Add a new job → update the DAG diagram + add a row to the
  table above.
- Raise the coverage gate → update `coverage-gate` job AND
  `docs/performance_baselines.md` (cross-linked from there).

## Badges

Add to `README.md` top of file:

```markdown
[![CI](https://github.com/vgnshlvnz/mtls-ed25519-api/actions/workflows/ci.yml/badge.svg)](https://github.com/vgnshlvnz/mtls-ed25519-api/actions/workflows/ci.yml)
[![Secret scan](https://github.com/vgnshlvnz/mtls-ed25519-api/actions/workflows/secret-scan.yml/badge.svg)](https://github.com/vgnshlvnz/mtls-ed25519-api/actions/workflows/secret-scan.yml)
```
