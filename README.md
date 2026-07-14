# action-gate

A pure, deterministic decision gate over a pluggable check registry.
`evaluate(context, checks)` returns `Allow`, `Deny`, or `Degrade`. It is the
generalized form of a hardcoded policy `evaluate()`: the checks become an
ordered, extensible registry and the context becomes domain-neutral, so the same
gate governs a shell tool call, an email send, or anything else.

```rust
use action_gate_core::{Gate, checks::{AllowlistCheck, SecretsCheck}};
use action_gate_types::ActionContext;

let gate = Gate::builder()
    .check(SecretsCheck::default())              // ship-provided, generic
    .check(AllowlistCheck::new(["email.send"]))  // ship-provided, generic
    // .check(GroundingCheck::new(fact_sheet))   // your own domain check
    .build();

let decision = gate.evaluate(&ActionContext::new("email.send"));
assert!(decision.is_allow());
```

## The shape

- **`ActionContext`**: `action`, `payload_summary`, `payload_body`, and an
  open `attributes` map. The core never inspects `attributes`; only checks do.
  That is what keeps the context domain-neutral.
- **`Check`**: a pure function of the context. `evaluate` returns
  `Some(decision)` to short-circuit or `None` to pass to the next check. A check
  owns its own parameters (a secrets check owns its regexes, an allowlist owns
  its list): there is no global policy-bundle type.
- **`Gate`**: runs checks in registration order, returning the first
  `Some(decision)` or an unconditional allow. `Gate::config_hash()` is a stable
  hash of the ordered check set plus each check's parameters, so a recorded
  decision can be bound to the exact gate that produced it.
- **`Decision`**: `outcome`, a stable `reason` code, `check_ids`, and a
  `blocking` flag (a signal that this must block regardless of any downstream
  trust or autonomy policy).

## Degrade is a signal, not an action

The gate returns `Degrade`; it does not perform a degraded action. The consumer
decides what `Degrade` means (route to a human, require confirmation, drop to
read-only). This is why the gate stays a pure function and never touches the
world. The autonomy decision (auto-proceed vs. review vs. block) is a separate
function of the gate decision, a trust level, and a risk tier, and it lives in
the consumer, not here.

## What ships vs. what you register

The library ships the machinery plus, behind the optional `checks-common`
feature, two genuinely generic checks: `SecretsCheck` (scan the payload for
credential patterns) and `AllowlistCheck` (deny actions not on a list). Domain
checks (destructive-op, spec-status, grounding, suppression, contact-fatigue,
tone) are yours to implement and register.

## Determinism

`Gate::evaluate` is a pure function of `(context, checks)`: no host calls, no
clock. Determinism depends on check ordering being stable, which the builder
guarantees by insertion order. `decision_to_canonical_json` gives a byte-stable
serialization for hashing and comparison.

## Ecosystem

Part of the `stagecraft-ing` reusable-primitive family, extracted from the Open
Agentic Platform (`crates/policy-kernel/lib.rs`) and relicensed Apache-2.0 by
the sole copyright holder (see `NOTICE`). It depends on `canonical-keysort-json`
for reproducible decision serialization. This repo is self-governed by its own
`specs/` corpus, compiled by the pinned `spec-spine` library.

Licensed under Apache-2.0.
