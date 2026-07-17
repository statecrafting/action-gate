# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/statecrafting/action-gate/releases/tag/v0.1.0
