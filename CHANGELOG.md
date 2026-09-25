# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-24

`action-gate-core` 0.2.0 only; `action-gate-types` stays at 0.1.0 (unchanged,
not republished), so consumers keep one shared types version. First consumer:
aicortex spec 047 (shared secret detector convergence), which replaces
aicortex-gate's own detector table with `action_gate_core::secrets` at an
exact pin.

### Added

- `action_gate_core::secrets` (spec 001): a pure, regex-free secret detector
  registry with stable detector ids and byte offsets. Carries aicortex-gate's
  detectors (24 prefix rules, 7 private-key armour markers including
  `-----BEGIN PGP PRIVATE KEY BLOCK-----`, URL credential, JWT, Q16
  fixed-point entropy) plus the `api_key =` assignment rule as
  `credential-assignment`. Always compiled; needs no feature and no `regex`.
- `SecretScanCheck`: a blocking check over the registry whose reason names the
  detector, field and offset, never the value.
- `DenyByDefault` and `GateBuilder::build_deny_by_default()`: an opt-in,
  blocking terminal check that closes the gate. The allow-when-no-check-decides
  default is unchanged.
- `golden-vectors` feature: `secrets::GOLDEN_VECTORS`, 67 detector vectors
  (most ported from aicortex's committed corpus) for parity assertions.

### Unchanged

- `SecretsCheck`'s patterns, reason and `config_fingerprint`, so a recorded
  `Gate::config_hash` over it does not move.

## [0.1.0] - 2026-07-14

### Added

- Initial release of the two-crate workspace.
  - `action-gate-types`: the domain-neutral `ActionContext`, `Decision`,
    `Outcome`, and the `Check` trait (with a `config_fingerprint` default).
  - `action-gate-core`: the `Gate` + `GateBuilder` that run an ordered check
    registry (first `Some` wins, else allow); `Gate::config_hash()` for binding
    a decision to the exact gate configuration; `decision_to_canonical_json`
    over `canonical-keysort-json`; and, behind the optional `checks-common`
    feature, two generic reference checks (`SecretsCheck`, `AllowlistCheck`).
- Extracted and relicensed Apache-2.0 (by the sole copyright holder) from the
  Open Agentic Platform's `crates/policy-kernel/lib.rs`. This is the Case-B
  extraction: OAP's hardcoded six-gate `evaluate()` becomes a pluggable `Check`
  registry over a domain-neutral context. OAP's four domain checks stay in OAP;
  its `PolicyBundle` config model is not adopted (checks self-configure). See
  `NOTICE`.

[0.2.0]: https://github.com/statecrafting/action-gate/releases/tag/v0.2.0
[0.1.0]: https://github.com/statecrafting/action-gate/releases/tag/v0.1.0
