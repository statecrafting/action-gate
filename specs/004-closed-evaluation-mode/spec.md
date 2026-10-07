---
id: "004-closed-evaluation-mode"
title: "Closed evaluation mode: deny by default, required checks, and every deny in order"
status: approved
created: "2026-10-07"
authors: ["action-gate"]
kind: feature
implementation: complete
risk: medium
summary: >
  Adds a second, opt-in evaluation mode to the Gate. A closed gate denies
  when no check decides, denies when a required check id names no
  registered check or a required check abstains, and does not stop at an
  allow or a degrade, so a later deny still decides. The gate's own denies
  carry stable reason codes and are blocking. An exhaustive evaluation
  returns every deny in registration order for consumers that report all
  of their reasons. The mode is part of the config hash, so a closed gate
  never hashes like an open one, while every open gate keeps its 0.2.0
  hash and decision bytes. Written so statecraft-envelope's admission
  evaluator (statecraft-cli spec 007, the hosted platform's specs 003 and
  004) and aicortex-gate (aicortex specs 013 and 051) can replace their
  hand-written evaluators with action-gate. Semver-minor (0.3.0).
depends_on:
  - "000-bootstrap"
  - "001-secret-detector-parity"
establishes:
  - { kind: file, path: "crates/core/tests/closed_mode.rs" }
  - { kind: file, path: "crates/core/tests/open_mode_compat.rs" }
  - { kind: file, path: "crates/core/testdata/closed-mode-vectors.json" }
extends:
  - { spec: "000-bootstrap", unit: "crates/core/src/lib.rs", nature: additive }
  - { spec: "000-bootstrap", unit: "Cargo.toml", nature: additive }
references:
  - { unit: { kind: file, path: "CHANGELOG.md" }, role: context }
  - { unit: { kind: file, path: "README.md" }, role: context }
---

# 004: Closed evaluation mode

## 1. Purpose

`Gate::evaluate` allows when no check returns `Some`. That default is
published, recorded in config hashes, and right for a gate that only lists
what it forbids. It is wrong for a gate whose job is to admit only what has
been shown acceptable, and two family consumers wrote their own evaluators
for that reason:

- `statecraft-envelope::admission::evaluate` (statecraft-cli spec 007; the
  hosted platform's specs 003 and 004, B-10 to B-12). The platform's
  architecture record says of action-gate: "its evaluator allows on
  fallthrough; required checks and deny-by-default are the platform's".
- `aicortex-gate`'s `Gate::evaluate` and `Gate::evaluate_claim` (aicortex
  specs 013 and 051), which already depend on `action-gate-core` for the
  secret registry but sequence their own rules.

0.2.0's `DenyByDefault` (spec 001 B-14) closes an open gate, but an earlier
allow still ends the evaluation, nothing makes a check mandatory, and only
the first decision is visible. This spec adds the mode both consumers need
without moving any of their domain types here.

## 2. Scope

In scope:

- `Mode` (`Open`, the default, and `Closed`), selected on the builder.
- Required check ids and the denies for a requirement that is not met.
- The order in which a closed gate combines `Allow`, `Degrade` and `Deny`.
- Stable reason codes for every decision a closed gate makes itself.
- `Gate::evaluate_exhaustive`, which returns the decision and every deny.
- The config hash of a closed gate, and proof that open gates are unchanged.

Out of scope, and left with the consumers as adapters (section 6):

- **Domain reason types.** statecraft-envelope's `RefusalCode` and
  `Admission`, aicortex's `Reason`, `ClaimReason` and `Verdict`. A check
  encodes what it needs in its own `Decision`; the consumer maps back.
- **Typed admission tokens.** aicortex's `Admitted` and `AdmittedClaim` are
  unforgeable because their constructors are private to aicortex-gate. The
  gate returns a `Decision`; minting the token stays in aicortex.
- **Policy identity.** statecraft's policy digest (BLAKE3 over DAG-CBOR) and
  aicortex's `PolicyRef` identify a policy document. `Gate::config_hash`
  identifies a gate assembly. Neither replaces the other.
- **Structured payloads on `Decision`.** `action-gate-types` stays at 0.1.0.
  Adding a field to `Decision` breaks struct-literal construction (spec 001
  D-4), so payloads travel in the reason string or are kept by the adapter.

## 3. Behavior

### 3.1 Modes

- **B-1 (default open).** `Gate::builder()` and `GateBuilder::new()` build
  an open gate. In `Mode::Open`, `Gate::evaluate` is exactly 0.2.0's rule:
  checks run in registration order, the first `Some` is the decision, and a
  gate where no check returns `Some` allows with
  `gate:allow:no_check_triggered`.
- **B-2 (closing).** `GateBuilder::closed()` selects `Mode::Closed`.
  `GateBuilder::require(id)` and `require_all(ids)` add required ids and
  also select `Mode::Closed`: there is no open gate with requirements. A
  requirement may be stated before or after its check is registered.
  `Gate::mode`, `Gate::required_ids` (sorted) and
  `Gate::unregistered_required` (sorted) expose the configuration.

### 3.2 Closed evaluation

- **B-3 (requirements first).** Before any check runs, every required id
  must equal the `id()` of at least one registered check. If any does not,
  the decision is a blocking deny with reason
  `gate:deny:closed:required_unregistered` and `check_ids` listing every
  such id, sorted, and no check runs. A required check is never skipped.
- **B-4 (walk).** Checks run in registration order. A `Deny` ends the walk
  and is the decision, unchanged: later checks do not run. A required check
  that returns `None` is a blocking deny with reason
  `gate:deny:closed:required_undecided` and `check_ids` `[id]`, and ends
  the walk the same way. Every check registered under a required id must
  decide. An `Allow` or a `Degrade` does not end the walk.
- **B-5 (after the walk).** With no deny, the decision is the first
  `Degrade`, unchanged, if any check degraded; otherwise, if at least one
  check allowed, an allow with reason `gate:allow:closed:affirmed`,
  `check_ids` listing the checks that allowed in order, and `blocking`
  false; otherwise a blocking deny with reason
  `gate:deny:closed:no_check_decided` and `check_ids` listing every check
  that ran, in order (empty for a gate with no checks).
- **B-6 (reason codes).** The four codes of B-3 to B-5 are public constants
  in `action_gate_core::closed` (`REQUIRED_UNREGISTERED`,
  `REQUIRED_UNDECIDED`, `NO_CHECK_DECIDED`, `AFFIRMED`). They follow the
  `gate:<outcome>:<source>:<detail>` grammar with source `closed`, and they
  never change within a major version. A check's own decision is returned
  as the check produced it; the gate never rewrites a check's reason,
  `check_ids` or `blocking` flag.
- **B-7 (Degrade).** Degrade remains a signal (000 section 1). In a closed
  gate a degrade outranks an allow and is outranked by any deny, wherever
  each occurs in the order. A required check that degrades has decided.

### 3.3 Exhaustive evaluation

- **B-8 (every deny).** `Gate::evaluate_exhaustive(ctx)` returns an
  `Evaluation { decision, denials }`. `decision` equals `Gate::evaluate(ctx)`.
  Every check runs, and `denials` lists, in registration order, each
  check's own `Deny` and, in closed mode, each `required_undecided` deny at
  its check's position. An unregistered requirement or the no-decision deny
  appears alone. In closed mode the decision is a deny exactly when
  `denials` is non-empty, and is then `denials[0]`. In open mode an earlier
  `Some` can decide before a listed deny is reached.

### 3.4 Config hash

- **B-9 (open unchanged).** An open gate's `config_hash` is
  `sha256:` over the canonical (key-sorted, compact) JSON array of its
  checks' `config_fingerprint`s, in order: the 0.1.0 and 0.2.0 value.
- **B-10 (closed distinct).** A closed gate's `config_hash` is `sha256:`
  over the canonical JSON object
  `{"checks": [fingerprints in order], "mode": "closed", "required": [ids sorted]}`.
  A JSON object never serializes like a JSON array, so no closed gate
  shares a preimage with any open gate. Requirement order and repetition
  do not change the hash; check order does.

### 3.5 Compatibility

- **B-11 (additive).** 0.3.0 is semver-minor for `action-gate-core`.
  Nothing public is removed or changes signature. `Gate`'s new fields are
  private. `DenyByDefault` and `build_deny_by_default()` are unchanged and
  remain open-mode tools; in a closed gate `DenyByDefault` would deny every
  action, which its documentation says. The secret registry and its golden
  vectors (spec 001) are unchanged. `action-gate-types` stays 0.1.0.

## 4. Functional requirements

- **FR-001.** The config hash of six open configurations (empty, two checks,
  the same reordered, `build_deny_by_default`, `SecretScanCheck`, and
  `SecretsCheck` plus `AllowlistCheck`) equals the value 0.2.0 computed,
  pinned as literals captured from 0.2.0.
- **FR-002.** The canonical decision bytes of those gates over seven
  probes equal the 0.2.0 bytes, pinned the same way.
- **FR-003.** Every vector in `crates/core/testdata/closed-mode-vectors.json`
  yields its config hash, decision and denials. The vectors were produced
  by a reference model written separately from the Rust implementation.
- **FR-004.** Open, closed, closed-with-requirements, reordered and
  `build_deny_by_default` gates over the same checks hash pairwise
  differently; requirement order does not change the hash.
- **FR-005.** The default mode is open; `require` closes the gate; the
  accessors report sorted ids.
- **FR-006.** An unregistered requirement denies before any check runs; a
  deny ends `evaluate`; `evaluate_exhaustive` runs every check exactly once,
  in either mode.
- **FR-007.** A degrade before a deny yields the deny; with no deny, the
  first degrade outranks any allow; a required check that degrades passes
  B-4.
- **FR-008.** A check's own decision is returned unchanged; the gate's
  allow and no-decision deny list the documented ids; every closed code
  follows B-6's grammar.
- **FR-009.** Property: for arbitrary scripted gates and requirement sets,
  `evaluate` equals `evaluate_exhaustive(..).decision`; open gates follow
  B-1; closed gates follow B-3 to B-5, never allow unless some check
  allowed, and every gate-made deny is blocking.

## 5. Acceptance criteria

- **AC-1.** `make code` passes: build, `cargo test --workspace
  --all-features --locked`, clippy with `-D warnings` over all targets and
  features, and `cargo fmt --all --check`.
- **AC-2.** `cargo test --locked` (default features) passes.
- **AC-3.** `crates/core/tests/open_mode_compat.rs` passes unmodified
  against 0.2.0's source as well as this one.
- **AC-4.** `make gate` passes.

## 6. Consumer adapters

These are the intended migrations. Each consumer owns its own spec for the
change; nothing here obliges either to adopt.

### 6.1 statecraft-envelope admission

`evaluate(policy, input)` collects every refusal, admits only when there is
none, and its reason order is part of the replayable
`statecraft/policy-eval/v1` claim (platform 004 B-12). The mapping:

- One closed gate per evaluation, built from `(policy, input)`, with every
  check required. Checks are registered in today's reason order: one per
  `require_artifacts` entry, then per verdict in input order its integrity,
  signature, issuer-trust and subject-binding checks, then
  approver-is-submitter, then the approval count. A check whose requirement
  the policy does not set allows, so a permissive policy admits.
- `Gate::evaluate_exhaustive` supplies `denials` in that order; the adapter
  maps each deny back to its `RefusalCode` and builds `Admission`.
- Stays in statecraft-envelope: `AdmissionPolicy` and its digest,
  `RefusalCode` and `Admission` with their serde, `policy_eval_claim`,
  `signature_requirement`, the per-dimension predicates, and the map from a
  deny to a `RefusalCode` (by check id, or by a canonical `RefusalCode`
  carried in the check's reason).
- Gained: deny on fallthrough, a requirement that cannot be dropped
  silently, and one combinator the CLI and the platform both run. The
  gate's `config_hash` varies with the input's shape here, so the policy
  digest remains the policy's identity.

### 6.2 aicortex-gate

`Gate::evaluate` returns the first fault in a fixed order, then decides on
origin (established admits, assertable quarantines, otherwise refuses).
`evaluate_claim` returns the first refusal in nine steps, then holds unless
a ground is found. The mapping:

- One closed gate per `RuleSet`, every step registered and required, in
  the documented order (013: empty, too-large, media, denied-source,
  secrets, origin; 051: vocabulary, secrets, provenance, sources, seed,
  score floor, user level, authority, relations, ground). Each step allows
  when it finds nothing; origin returns allow, degrade or deny; the claim
  ground returns allow or degrade (hold).
- B-4 keeps the ceiling before the scan, because a deny ends the walk.
  B-7 makes the secrets-before-quarantine rule of 013 a property of the
  gate rather than of the order alone. B-3 makes the absence of a "disable
  the gate" switch mechanical: a deployment that drops the secrets step is
  denied, not admitted.
- Stays in aicortex-gate: `Reason`, `ClaimReason`, `Verdict`,
  `ClaimVerdict`, `Admitted` and `AdmittedClaim` with their private
  constructors, `Override` and `evaluate_overridden`, normalization,
  `LedgerEntry`, and the map from a deny (check id plus reason) back to a
  `Reason` with its payload (detector, offset, counts). Building an
  `AdmittedClaim` (relations, conflicts, corrections) stays after the
  gate's allow.

## 7. Resolved decisions

These were taken by the agent drafting this spec. The owner ratifies them by
approving the spec.

- **D-1 (one mode, two toggles).** `closed()` and `require()` share one
  `Mode::Closed` rather than two independent flags. Requirements without
  deny-by-default would let a gate with every requirement met and nothing
  else decided fall through to allow, which neither consumer wants.
- **D-2 (an allow does not end a closed walk).** Otherwise a required check
  after an allowing check would never run, which is the skip B-3 forbids.
  0.2.0's allow-list pattern (an early allow passes the action) stays
  available in open mode with `DenyByDefault`.
- **D-3 (a deny does end a closed walk).** aicortex 013 needs the size
  ceiling to stop the scan. Consumers that need every reason use
  `evaluate_exhaustive`, which is pure and yields the same decision.
- **D-4 (required means decides).** A required check passes by returning
  `Some` that is not a deny. Requiring an explicit allow would turn
  aicortex's quarantine (a degrade from a required step) into a deny.
- **D-5 (gate-made denies are blocking).** As spec 001 D-3: a gate its
  operator closed is not reopened by a trust layer downstream.
- **D-6 (object preimage).** The closed hash uses a JSON object so the open
  preimage, a JSON array, stays byte-identical and the two can never meet.
  Required ids are a set, so they are hashed sorted.
- **D-7 (no `Decision` payload).** Kept out for the reason of spec 001 D-4.
  A payload field is a types 0.2 question for a later spec.

## Verification

```verify:cli
cargo test --all-features --locked
cargo test --locked
```
