# Remediation notes — 2026-11, second pass

This file records the second audit pass over the Privacyflow repository in November
2026. It is additive: the earlier `docs/REMEDIATION-2026-11.md` keeps the record of
the first pass and is not modified by this one.

## Method

Every source file, test file and document was read again. Each suspected defect was
confirmed with a regression test before the fix was applied.

## Defects fixed

| Severity | Defect | Fix |
| --- | --- | --- |
| Medium | The package exposed no public API: `load_config`, `validate_wireguard_profile` and `rotation_plan` were only reachable through the private `privacyflow.config` module | The package now re-exports the public API with a sorted `__all__` and a `__version__` |
| Low | `cli.main()` read `sys.argv` directly, so the command could not be called with an argument list and could not be tested as a function | `cli.main(argv)` accepts an argument list and falls back to `sys.argv` when it is omitted |
| Low | `docs/TEST-RESULTS.md` claimed 82/82 tests from the 2026-11-04 run while the suites had grown since | The document now records the verified counts of the current run: 153 tests, 152 passed, 1 skipped, and it marks the old figure as superseded |

## Documentation and spelling corrections

- `LICENSE` shipped a truncated MIT text without the warranty and liability
  clauses. The complete canonical MIT text is now in place.
- Spelling was inconsistent (`authorised` against `authorization` and `normalized`).
  The prose now uses one convention: American English.

## Verification

| Check | Before | After |
| --- | --- | --- |
| Privacyflow tests | 31 passed | 38 passed |
| Documented test total | 82/82 (stale) | 153 tests, 152 passed, 1 skipped |

## Residual limitations

- Validation is static. Privacyflow never installs a WireGuard interface, never
  changes a route, and never proves that a kill switch works.
- The rotation plan is a dry run. It lists the profiles and the interval; it does
  not perform a health check and it does not switch anything.
- The configuration parser accepts a fixed set of WireGuard options. A profile
  that uses any other option is rejected rather than ignored.
