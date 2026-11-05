# Privacyflow remediation — 2026-11-05

This file records a defect audit and the fixes applied on top of the published
v0.1.0 tree. The original `README.md`, `CHANGELOG.md`, `docs/AUDIT-REPORT.md`,
`docs/TEST-RESULTS.md` and `docs/SECURITY.md` are left unchanged so the earlier
audit record stays intact; this file is the new evidence.

Audit method: `src/privacyflow/config.py` was read in full and then exercised
with an adversarial probe covering endpoint forms, section and key syntax,
scalar ranges, TOML shapes and encoding edge cases. Each fix below is covered
by a regression test that fails on the pre-fix code.

## Fixes

### 1. A valid IPv4 literal endpoint was rejected (medium)

* Where: `src/privacyflow/config.py`, `_validate_endpoint`.
* Cause: the hostname branch treated a dotted quad as a hostname and rejected it
  through the "numeric dotted" rule that exists to block values such as
  `1.2.3.4.5`. The tool's own error message said the endpoint "must be a
  hostname or IP followed by a port", so the code contradicted its own contract.
  IPv6 literals were accepted while IPv4 literals were not.
* Fix: the hostname branch now tries `ipaddress.IPv4Address(hostname)` first and
  only falls back to the label rules when the value is not a valid address.
  `1.2.3.4.5` and other numeric-looking non-addresses are still rejected.
* Test: `tests/test_config.py` —
  `test_accepts_ipv4_literal_endpoint`,
  `test_still_rejects_numeric_looking_non_ip_endpoint_hostname`.

### 2. A profile starting with a UTF-8 BOM was rejected (medium)

* Where: `src/privacyflow/config.py`, `validate_wireguard_profile`.
* Cause: the profile was read with plain `utf-8`, which keeps a leading byte
  order mark. The first line therefore no longer started with `[` and the
  parser reported "invalid syntax on line 1" for a file that is otherwise a
  valid WireGuard profile. Windows editors commonly add the mark.
* Fix: the profile is read with `utf-8-sig`, which strips the mark when it is
  present and behaves identically when it is not.
* Test: `tests/test_config.py` — `test_accepts_profile_with_utf8_bom`.

### 3. Empty optional values were silently accepted (medium)

* Where: `src/privacyflow/config.py`, `validate_wireguard_profile`.
* Cause: the optional scalar checks were written as "if the value is non-empty,
  validate it", so a key present with an empty value (`MTU =`, `DNS =`,
  `SaveConfig =`, `Table =`, `ListenPort =`, `FwMark =`,
  `PersistentKeepalive =`) passed validation. `PresharedKey =` was rejected
  while the other empty values were not, so the behaviour was inconsistent and
  the malformed profile was only discovered later, by `wg-quick`.
* Fix: a present-but-empty optional scalar is now rejected with
  `contains an empty <Section>.<Name>`.
* Test: `tests/test_config.py` —
  `test_rejects_empty_optional_interface_scalar_values`,
  `test_rejects_empty_optional_peer_scalar_values`.

### 4. A TOML config starting with a UTF-8 BOM was rejected (low)

* Where: `src/privacyflow/config.py`, `load_config`.
* Cause: same encoding issue as the profile, surfacing as
  `Cannot read TOML config: TOMLDecodeError`.
* Fix: the config is read with `utf-8-sig`.
* Test: `tests/test_config.py` — `test_accepts_toml_config_with_utf8_bom`.

### 5. An out-of-range port produced a misleading message (low)

* Where: `src/privacyflow/config.py`, `_validate_endpoint`.
* Cause: `urlsplit(...).port` raised for a port above 65535 inside the same
  `try` block as the URL split, so the generic "contains an invalid
  Peer.Endpoint" message was used and the specific "must be a hostname or IP
  followed by a port" message was never reached.
* Fix: the port is parsed separately, so an out-of-range port now reports the
  port-specific message.
* Test: `tests/test_config.py` — `test_reports_out_of_range_port_with_the_port_message`.

## Test status after the fixes

| Suite | Before | After |
|---|---|---|
| `tests/test_config.py` | 24 | 31 |

Full local gate on 2026-11-05 (Windows 11, Python 3.15.0): 31/31 tests passed,
`scripts/syntax-checks.py` 7/7 checks passed (JavaScript check skipped — no
JavaScript in this repository), `scripts/scan-secrets.py` clean.

## Known limitations that were deliberately not changed

* A `profiles` entry may point outside the directory that holds the TOML file,
  and an absolute path is accepted. The configuration is operator-authored, so
  this is not a privilege boundary, but it is not a containment guarantee either.
* `AllowedIPs` entries with host bits set are accepted and duplicate entries are
  accepted, because the CIDR check intentionally uses the non-strict form. Both
  match what `wg-quick` accepts.
* A section header with a trailing comment is rejected as invalid syntax, which
  matches `wg-quick`.
* Actual WireGuard connect, disconnect, route changes and DNS or IPv6 leak
  tests were not executed; this release still does not change routes or install
  a firewall kill switch.
