---
id: "000-bootstrap"
title: "action-gate bootstrap (pure decision gate over a check registry)"
status: draft
created: "2026-07-14"
authors: ["action-gate"]
kind: tooling
implementation: pending
risk: low
summary: >
  Bootstrap spec for the action-gate repository: a two-crate pure, deterministic
  decision gate that evaluates an ActionContext against an ordered, pluggable
  Check registry and returns Allow/Deny/Degrade. Extracted (relicensed
  Apache-2.0 by the sole copyright holder) from the Open Agentic Platform's
  crates/policy-kernel/lib.rs (the Case-B extraction: OAP's hardcoded six-gate
  evaluate becomes a Check registry over a domain-neutral context). Depends on
  canonical-keysort-json for reproducible decision hashing. This spec
  establishes the workspace skeleton and seeds this repo's own spec corpus,
  governed by the pinned spec-spine library.
depends_on: []
establishes:
  - { kind: file, path: "Cargo.toml" }
  - { kind: file, path: "crates/types/Cargo.toml" }
  - { kind: file, path: "crates/types/src/lib.rs" }
  - { kind: file, path: "crates/core/Cargo.toml" }
  - { kind: file, path: "crates/core/src/lib.rs" }
  - { kind: file, path: "crates/core/src/checks.rs" }
references:
  - { unit: { kind: file, path: "README.md" }, role: context }
  - { unit: { kind: file, path: "NOTICE" }, role: context }
---

# 000: action-gate bootstrap

## 1. Purpose

action-gate is the decision primitive of the `statecrafting`
reusable-primitive family. It answers one question deterministically: given a
proposed action and an ordered set of checks, is the action allowed, denied, or
to be degraded? The gate is a pure function of `(context, checks)`, so the same
decision is reproducible offline and can be bound, by its config hash, to a
recorded ledger entry.

This bootstrap spec exists so the repository has a governed seed: the workspace
compiles, this corpus is non-empty, and spec-spine can dogfood it.

## 2. Scope

In scope, established here:

- `ActionContext`, `Outcome`, `Decision`, and the `Check` trait (with a
  `config_fingerprint` default).
- `Gate` + `GateBuilder`; `Gate::evaluate` (first `Some` wins, else allow);
  `Gate::config_hash` (a stable hash of the ordered check set plus parameters);
  `decision_to_canonical_json`.
- Behind the optional `checks-common` feature: `SecretsCheck` and
  `AllowlistCheck`, the two checks that were already domain-neutral in OAP.

Out of scope:

- **Domain checks.** OAP's destructive-op, spec-status, spec-risk, and diff-size
  checks stay in OAP; chancery's grounding, suppression, fatigue, and injection
  checks stay in chancery. They register into a gate; they are not shipped here.
- **The policy-bundle config model.** OAP's `PolicyBundle` / `PolicyRule` is
  not adopted; each check self-configures.
- **The autonomy decision.** Whether a gate `Decision` becomes auto-proceed,
  review, or block is a separate consumer function of `(decision, trust, tier)`,
  layered on top of the pure gate. A `blocking` decision overrides any trust.

## 3. Provenance

Extracted from OAP `crates/policy-kernel/lib.rs` (AGPL-3.0-or-later there),
relicensed Apache-2.0 by the sole copyright holder. This is the Case-B
extraction (149 OAP-coupling hits in the source): the gate machinery is generic,
but the six checks and the context were OAP-domain and had to be lifted into a
pluggable registry over a domain-neutral context. The interim extraction record
is `chancery/docs/preliminary/00-extraction-overview.md` and `02-action-gate.md`;
a forthcoming OAP extraction spec formalizes the vend.

## 4. Established units

- `Cargo.toml`: the workspace manifest (two members, Apache-2.0, edition 2024,
  forbid-unsafe).
- `crates/types`: the domain-neutral contract.
- `crates/core`: the gate machinery, config hash, canonical serialization, and
  the optional common checks.

## 5. Notes on the generalization

OAP's `evaluate(ctx, bundle)` inlined six checks in a fixed order and read a
code-governance-shaped `ToolCallContext` (diff lines, spec statuses, feature
ids). The generalization makes three moves without changing the outcome enum or
the pure-function property: (1) `ActionContext` replaces `ToolCallContext`, with
domain fields moved into an open `attributes` map; (2) a `Check` trait and an
ordered `GateBuilder` replace the hardcoded gate list; (3) config lives in the
checks, not a global bundle. OAP re-consumes this by registering its four domain
checks plus the two common ones, mapping the generic `Decision` back to its
`PolicyDecision`; OAP's gate tests are the regression guard.

## 6. Owner decisions

- 2026-09-25: this spec's id changed from `000-action-gate-bootstrap` to
  `000-bootstrap`. The Statecraft CI profile `github-actions-rust`
  (revision 7) always offers a starter spec at `specs/000-bootstrap/spec.md`
  and adopts an existing file at that path unchanged. Under any other id the
  starter shares the numeric prefix `000` with this spec, which spec-spine
  refuses (V-004). The owner chose the rename over an upstream change. Only
  the id changes: the status, claims and text of this spec are unchanged,
  and so are the crates it establishes, apart from the
  `[package.metadata.action-gate] spec` key in both crate manifests.
