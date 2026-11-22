# Contributing to Privacyflow

Thanks for helping! Privacyflow performs authorised VPN profile
validation and safe rotation planning: it checks that the VPN
profiles you operate are configured the way you think they are, and
plans rotations without breaking the people who depend on them.

The most valuable contributions are new profile validators, support
for more profile formats, and tests.

## Ground rules

- **Your profiles, your infrastructure.** Privacyflow validates
  profiles the operator owns or is authorised to manage. Do not add
  features for probing third-party VPN endpoints.
- **Validation before rotation.** A rotation plan must never be
  produced for a profile that fails validation — that ordering is a
  safety property, not a preference.
- **Zero runtime dependencies — hard rule.** Python standard library
  only. Never commit a real VPN profile, key or credential; CI runs
  a secret scan (`python scripts/scan-secrets.py .`) and it must
  stay green.

## Development setup

Requires Python 3.11 or newer:

```bash
git clone https://github.com/gravion-ux/privacyflow.git
cd privacyflow
python -m pip install --no-deps -e .
```

The package uses a `src/` layout (`src/privacyflow/`). See
`config.example.toml` for the configuration shape.

## Running the tests

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

That is exactly what CI runs, on Python 3.11, 3.12 and 3.13. CI
also runs the secret scan and static syntax/manifest checks
(`python scripts/syntax-checks.py .`).

## Code style

- Tests are `unittest` test cases in `tests/` — match the existing
  style rather than introducing a second framework.
- Test fixtures are synthetic profiles; sanitise anything derived
  from a real configuration before it goes into a fixture.
- Comments explain *why* a validation rule or rotation step exists.

## Pull request workflow

1. Fork and branch from `main`: `feat/<short-name>`,
   `fix/<short-name>`, `docs/<short-name>`.
2. Run the full test suite locally.
3. Open the PR against `main` with: what changed, why, how you
   tested it.
4. CI must be green — secret scan, syntax checks and the Python
   test matrix.
5. One logical change per PR.
