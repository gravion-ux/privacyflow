# Gravion Privacyflow - repository manifest

Version: 0.1.0
Repository: https://github.com/gravion-ux/privacyflow
Published: 2026-11-05

## Contents

- `src/privacyflow/`: WireGuard profile validator, TOML configuration loader and dry-run rotation planner
- `tests/`: configuration, parser and safety regression tests
- `config.example.toml`: example configuration referencing the demo provider profiles
- `profiles/`: demo-only provider profile templates (`.example` files only)
- `pyproject.toml`: Python package manifest (standard library only)
- `docs/`: shared toolkit documentation
- `scripts/`: secret scanner, static syntax gate, smoke commands and a one-command test runner
- `.github/workflows/ci.yml`: Python 3.11/3.12/3.13 tests, static checks and a secret scan

## Security

No real WireGuard profiles, private keys, API keys, cookies or personal
evaluation datasets are included. The bundled key material is demo-only and
cannot connect to a VPN.

See `docs/PUBLICATION-VERIFICATION.md` for the verified checks and the explicit
environment limitations.
