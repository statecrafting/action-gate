---
id: "001-secret-detector-parity"
title: "Secret detector parity: a regex-free detector registry with ids and offsets, and an opt-in deny-by-default terminal check"
status: approved
created: "2026-09-24"
authors: ["action-gate"]
kind: feature
implementation: pending
risk: medium
summary: >
  Converges the family's secret detection upward into action-gate-core.
  aicortex-gate's detectors (aicortex spec 013 B-4: 24 published-prefix
  rules, 7 private-key armour markers including the PGP block, a URL
  credential detector, a JWT detector, and a Q16 fixed-point entropy
  detector) move here with their stable detector ids and byte offsets,
  joined by action-gate's own `api_key =` style assignment rule, as one
  pure, regex-free registry. A new `SecretScanCheck` reports which detector
  fired and where without echoing the value. The published `SecretsCheck`
  and the gate's allow-when-silent default are unchanged; a documented,
  opt-in `DenyByDefault` terminal check lets a consumer close the gate.
  Golden vectors ported from aicortex's corpus ship with the crate so
  aicortex spec 047 can assert parity by vector id. Semver-minor (0.2.0).
depends_on:
  - "000-action-gate-bootstrap"
establishes:
  - { kind: file, path: "crates/core/src/secrets.rs" }
  - { kind: file, path: "crates/core/testdata/secret-vectors.json" }
  - { kind: file, path: "crates/core/tests/secret_vectors.rs" }
  - { kind: file, path: "crates/core/tests/secret_properties.rs" }
extends:
  - { spec: "000-action-gate-bootstrap", unit: "crates/core/src/lib.rs", nature: additive }
  - { spec: "000-action-gate-bootstrap", unit: "crates/core/Cargo.toml", nature: additive }
  - { spec: "000-action-gate-bootstrap", unit: "Cargo.toml", nature: additive }
references:
  - { unit: { kind: file, path: "crates/core/src/checks.rs" }, role: constraint }
  - { unit: { kind: file, path: "CHANGELOG.md" }, role: context }
  - { unit: { kind: file, path: "README.md" }, role: context }
---

# 001: Secret detector parity

## 1. Purpose

Two family repositories refusing credentials with two rule tables will
drift, and the difference is found by the credential that got through. The
owner decided on 2026-09-24 that secret detection converges upward:
aicortex-gate's stronger detectors move into action-gate, and aicortex
(spec 047, statecrafting/aicortex#21) then consumes action-gate at an exact
pin instead of keeping its own table.

At 0.1.0, action-gate's `SecretsCheck` reports only a boolean match as the
fixed reason `gate:deny:secrets:pattern_match`, and its private-key pattern
`-----BEGIN [A-Z ]*PRIVATE KEY-----` does not match
`-----BEGIN PGP PRIVATE KEY BLOCK-----`. aicortex spec 013 B-3 requires a
refusal to name the detector and the byte offset and to carry no part of
the value. This spec gives action-gate a detector registry that meets 013
B-3 and B-4, so the family has one table.

## 2. Scope

In scope:

- A public module `action_gate_core::secrets`: the detector tables as data,
  the detectors that read them, a `scan` function returning a detector id
  and byte offset, and a `SecretScanCheck` that plugs the registry into a
  `Gate`.
- The assignment rule of 0.1.0's `SecretsCheck`, reimplemented without
  `regex` as a registry detector.
- An opt-in `DenyByDefault` terminal check and a builder shorthand for it.
- Golden vectors, ported from aicortex's committed corpus with attribution,
  shipped with the crate under an opt-in feature.

Out of scope:

- **Normalization.** Unicode normalization and removal of bidirectional
  controls before detection (aicortex 013 B-8) stay with the consumer. The
  registry scans the exact text it is given, and offsets index that text.
- **Verdicts, overrides, limits, ledger records.** aicortex keeps its own
  (aicortex 047 B-2).
- **Changing `SecretsCheck` or the allow default.** Both are published
  contracts (section 3.5).

## 3. Behavior

### 3.1 The registry

- **B-1 (detector ids).** Every detector has a stable, kebab-case
  `DetectorId` (a `&'static str` newtype). An id, once shipped, is never
  renamed or reused for a different shape; retiring a detector removes its
  id. `secrets::detector_ids()` lists every id the default rules can
  report, in table order.
- **B-2 (the tables are data).** Prefix rules and armour markers are public
  `const` tables (`PREFIX_RULES`, `PEM_RULES`). Adding a credential shape is
  a table row and a golden vector, not a code path. The URL, JWT, entropy,
  and assignment detectors are named constants with fixed logic.
- **B-3 (the detector set).** The default rules are exactly the union of
  aicortex-gate's rules at aicortex commit `a927f85` and action-gate 0.1.0's
  assignment rule:

  | Detector id | Kind | Shape |
  |---|---|---|
  | `anthropic-api-key` | prefix | `sk-ant-` + 24 base64url |
  | `openai-api-key` | prefix | `sk-` + 20 base64url |
  | `stripe-secret-key` | prefix | `sk_live_` + 16 alphanumeric |
  | `stripe-restricted-key` | prefix | `rk_live_` + 16 alphanumeric |
  | `github-token` | prefix | `ghp_` + 36 alphanumeric |
  | `github-oauth-token` | prefix | `gho_` + 36 alphanumeric |
  | `github-user-token` | prefix | `ghu_` + 36 alphanumeric |
  | `github-server-token` | prefix | `ghs_` + 36 alphanumeric |
  | `github-refresh-token` | prefix | `ghr_` + 36 alphanumeric |
  | `github-fine-grained-token` | prefix | `github_pat_` + 40 base64url |
  | `gitlab-personal-token` | prefix | `glpat-` + 20 base64url |
  | `slack-bot-token` | prefix | `xoxb-` + 24 token |
  | `slack-user-token` | prefix | `xoxp-` + 24 token |
  | `slack-app-token` | prefix | `xapp-` + 24 token |
  | `aws-access-key-id` | prefix | `AKIA` + 16 alphanumeric |
  | `aws-temporary-access-key-id` | prefix | `ASIA` + 16 alphanumeric |
  | `google-api-key` | prefix | `AIza` + 35 base64url |
  | `google-oauth-token` | prefix | `ya29.` + 32 token |
  | `npm-token` | prefix | `npm_` + 36 alphanumeric |
  | `digitalocean-token` | prefix | `dop_v1_` + 60 alphanumeric |
  | `sendgrid-api-key` | prefix | `SG.` + 32 token |
  | `huggingface-token` | prefix | `hf_` + 32 alphanumeric |
  | `shopify-access-token` | prefix | `shpat_` + 32 alphanumeric |
  | `supabase-service-key` | prefix | `sbp_` + 36 alphanumeric |
  | `pem-private-key` | armour | `-----BEGIN PRIVATE KEY-----` |
  | `pem-rsa-private-key` | armour | `-----BEGIN RSA PRIVATE KEY-----` |
  | `pem-ec-private-key` | armour | `-----BEGIN EC PRIVATE KEY-----` |
  | `pem-dsa-private-key` | armour | `-----BEGIN DSA PRIVATE KEY-----` |
  | `pem-encrypted-private-key` | armour | `-----BEGIN ENCRYPTED PRIVATE KEY-----` |
  | `openssh-private-key` | armour | `-----BEGIN OPENSSH PRIVATE KEY-----` |
  | `pgp-private-key` | armour | `-----BEGIN PGP PRIVATE KEY BLOCK-----` |
  | `url-embedded-credential` | token | `scheme://user:password@host`, non-empty password and host |
  | `json-web-token` | token | three base64url segments (signature may be empty) whose header decodes to a JSON object with `alg` or `typ` |
  | `high-entropy-token` | threshold | a maximal run of token characters, at least 24 long, mixing upper case, lower case and digits, with Shannon entropy of at least 4.50 bits per character (Q16 fixed point) |
  | `credential-assignment` | assignment | `api_key`, `api-key`, `apikey`, `secret` or `token` (ASCII case-insensitive), optional whitespace, `:` or `=`, optional whitespace, an optional `'` or `"`, then 24 or more of `A-Z a-z 0-9 _ -` |

  Alphabets: *alphanumeric* is `A-Z a-z 0-9`; *base64url* adds `-` and `_`;
  *token* adds `+ / = - _ .` to alphanumeric. Prefixes and markers are
  case-sensitive.
- **B-4 (tokens).** Prefix, URL, JWT and entropy detectors read *tokens*:
  maximal runs of characters that are neither whitespace nor one of
  `" ' ` , ; ( ) [ ] { } < > | \` and U+FEFF. A prefix rule fires when a
  token starts with the prefix and at least `min_tail` characters of the
  rule's alphabet follow it. The entropy detector measures each maximal run
  of token-alphabet characters inside a token, so punctuation glued onto a
  secret cannot hide it (aicortex 013 D-12). Armour markers and the
  assignment rule read the whole text, because a PEM block spans lines and
  an assignment spans whitespace.
- **B-5 (configuration).** `SecretRules` selects the tables and toggles the
  URL, JWT, assignment and entropy detectors, and carries the entropy
  threshold (`EntropyRule`). `SecretRules::default()` enables everything at
  the shipped threshold. There is no rule set that disables detection
  implicitly; a consumer that narrows the rules does so field by field.

### 3.2 Findings and offsets

- **B-6 (one finding, first position).** `scan(text, &rules)` returns the
  finding with the smallest byte offset, or `None`. At equal offsets an
  armour marker wins over a token detector, and a token detector wins over
  the assignment rule. Within the token detectors, precedence is prefix,
  URL, JWT, entropy; within a table, table order.
- **B-7 (offset semantics).** The offset is a byte index into the scanned
  text, on a UTF-8 character boundary:
  - armour: the first byte of the marker;
  - prefix, URL, JWT: the first byte of the token;
  - entropy: the first byte of the offending run within the token;
  - assignment: the first byte of the assigned value (after any quote), not
    of the key name.
- **B-8 (determinism).** `scan` is a pure function: no clock, randomness,
  I/O, allocation-order dependence, or floating point. The same text and
  rules always yield the same finding on every target.

### 3.3 Redaction-safe reporting

- **B-9 (never echo the secret).** A `Finding` holds only a `DetectorId`
  and an offset. `SecretScanCheck` denies with the reason
  `gate:deny:secrets:<detector-id>:<field>:<offset>`, where `<field>` is
  `summary` or `body` (the `ActionContext` field that matched) and
  `<offset>` is decimal. The reason is built only from registry ids, those
  two field names, and digits, so no surface of the decision (reason,
  `Debug`, canonical JSON) can contain any part of the input. The decision
  is blocking and names the check id `secret-scan`.
- **B-10 (field order).** `SecretScanCheck` scans `payload_summary` first,
  then `payload_body`, and reports the first field with a finding.
- **B-11 (fingerprint).** `SecretScanCheck::config_fingerprint` folds in
  every rule row and toggle and the entropy parameters, so a change to the
  rules changes `Gate::config_hash`.

### 3.4 Dependencies: no `regex`

- **B-12 (regex-free).** The registry, `SecretScanCheck`, and
  `DenyByDefault` compile without the `checks-common` feature and without
  `regex`. aicortex 047 Q-1 asked whether `regex` is acceptable; the answer
  recorded here (D-1) is that it is not needed. `regex` remains an optional
  dependency only for 0.1.0's `SecretsCheck` and its custom-pattern
  constructor.

### 3.5 Backwards compatibility

- **B-13 (additive).** 0.2.0 is semver-minor. `SecretsCheck` keeps its
  patterns, reason, check id and `config_fingerprint` byte for byte, so a
  consumer that records `Gate::config_hash` (rahi-kernel, chancery) sees no
  change. `Gate::evaluate` still allows when no check returns `Some`.
  Nothing public is removed or changes signature.

### 3.6 Deny-by-default terminal check

- **B-14 (opt-in closure).** `DenyByDefault` is a check that always returns
  a blocking deny with reason `gate:deny:default:no_check_decided` and
  check id `deny-by-default`. Registered last, it closes the gate: an
  action is allowed only if an earlier check returns
  `Some(Decision::allow())`. `GateBuilder::build_deny_by_default()` appends
  it and builds. Checks registered after it never run. It is never added
  implicitly.

### 3.7 Golden vectors

- **B-15 (vectors).** `crates/core/testdata/secret-vectors.json` holds
  vectors with a stable `id`, the scanned `text`, and the expected
  `detector` and `offset` (both `null` for a negative vector), plus the
  `secret` substring for positive vectors and a `source` naming where the
  vector came from. Every detector in B-3 has at least one positive vector;
  the benign identifiers of aicortex 013 FR-005 and prose using the word
  "token" are negative vectors. Vectors ported from aicortex cite the
  aicortex fixture file they came from.
- **B-16 (shipped).** The file is packaged with `action-gate-core` and
  exposed as `secrets::GOLDEN_VECTORS` behind the opt-in `golden-vectors`
  feature, so a consumer can assert parity by vector id without copying the
  file.

## 4. Functional requirements

- **FR-001.** Every golden vector yields its recorded detector and offset.
- **FR-002.** For every positive vector, no surface of the
  `SecretScanCheck` decision contains the secret or any 8-byte window of
  it.
- **FR-003.** Property: for generated prose around a generated credential,
  `scan` reports the credential's detector at the credential's offset.
- **FR-004.** Property: for arbitrary input, any finding's offset is a
  character boundary inside the text, and any `SecretScanCheck` reason
  matches the B-9 grammar.
- **FR-005.** No benign identifier, alone or joined into one note, yields a
  finding.
- **FR-006.** `SecretsCheck::default().config_fingerprint()` equals its
  0.1.0 value, asserted by a pinned string.
- **FR-007.** A gate built with `build_deny_by_default()` denies an action
  no check decides and allows one an earlier check allows; an empty gate
  without it still allows.

## 5. Acceptance criteria

- **AC-1.** `cargo fmt --all --check`,
  `cargo clippy --all-targets --all-features --locked -- -D warnings`,
  `cargo build --locked`, and `cargo test --all-features --locked` pass.
- **AC-2.** `cargo test --locked` (default features) passes, proving the
  registry needs no `regex`.

## 6. Resolved decisions

- **D-1 (2026-09-24, under delegation).** No `regex` in the registry.
  aicortex's detectors are already hand-written and pure; the one regex
  rule (assignment) is a short hand-written scanner. This keeps aicortex
  047 B-4's pure path without a new dependency decision there, and keeps
  the matcher's behavior fully specified by B-3 rather than by a regex
  engine's Unicode semantics. Consequence: the assignment keyword match is
  ASCII case-insensitive, where 0.1.0's `(?i)` regex also folded
  non-ASCII case variants (for example U+212A KELVIN SIGN); consumers that
  normalize with NFKC first, as aicortex does, see no difference.
- **D-2 (2026-09-24, under delegation).** A new check rather than a
  stronger `SecretsCheck::default()`. Changing the default would change the
  config hash rahi-kernel records and the decisions chancery tests, which
  B-13 forbids.
- **D-3 (2026-09-24, under delegation).** `DenyByDefault` is blocking. A
  gate its operator explicitly closed must not be reopened by a trust
  layer downstream.
- **D-4 (2026-09-24, under delegation).** Offset in the reason string, not
  a new `Decision` field. `Decision` has public fields, so adding one would
  break struct-literal construction in consumers (semver-major).

## 7. Provenance

The detector tables, the token and entropy algorithms, and the ported
vectors come from aicortex (`crates/aicortex-gate/src/rules.rs`,
`secrets.rs`, `testdata/corpus/`, commit `a927f85`, aicortex spec 013),
contributed by the same copyright holder and relicensed here under
Apache-2.0.

## Verification

```verify:cli
cargo test --all-features --locked
cargo test --locked
```
