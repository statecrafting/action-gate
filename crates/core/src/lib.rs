// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Bartek Kus
//
// Relicensed from the Open Agentic Platform (crates/policy-kernel/lib.rs,
// AGPL-3.0-or-later) to Apache-2.0 by the sole copyright holder. See NOTICE.

//! `action-gate-core`: a pure, deterministic decision gate over an ordered
//! [`Check`] registry.
//!
//! [`Gate::evaluate`] runs its checks in registration order and returns the
//! first check's `Some(decision)`, or an unconditional [`Decision::allow`] if
//! none triggers. It is a pure function of `(context, checks)`: no host calls,
//! no clock, unit-testable, and byte-stable via [`decision_to_canonical_json`].
//! Determinism depends on check ordering being stable, which the builder
//! guarantees (insertion order).
//!
//! # Config is in the checks, not a global bundle
//!
//! There is no global policy-bundle type here. Each check owns its parameters
//! (a secrets check owns its regex set, an allowlist owns its list). The
//! consumer assembles the gate:
//!
//! ```
//! # #[cfg(feature = "checks-common")] {
//! use action_gate_core::{Gate, checks::{AllowlistCheck, SecretsCheck}};
//! use action_gate_types::ActionContext;
//!
//! let gate = Gate::builder()
//!     .check(SecretsCheck::default())
//!     .check(AllowlistCheck::new(["email.send", "email.draft"]))
//!     .build();
//!
//! let decision = gate.evaluate(&ActionContext::new("email.send"));
//! assert!(decision.is_allow());
//! # }
//! ```
//!
//! # Degrade is a signal, not an action
//!
//! [`Outcome::Degrade`] does not perform a degraded action. The gate returns it;
//! the consumer decides its meaning (route to a human, require confirmation).
//! The gate never touches the world.

pub use action_gate_types::{ActionContext, Check, Decision, Outcome};

use sha2::{Digest, Sha256};

#[cfg(feature = "checks-common")]
pub mod checks;

/// A pure decision gate over an ordered list of checks.
pub struct Gate {
    checks: Vec<Box<dyn Check>>,
}

impl Gate {
    /// Start building a gate.
    pub fn builder() -> GateBuilder {
        GateBuilder::new()
    }

    /// Evaluate `ctx` against the checks in order. The first check to return
    /// `Some` wins; if none does, the gate allows.
    pub fn evaluate(&self, ctx: &ActionContext) -> Decision {
        for check in &self.checks {
            if let Some(decision) = check.evaluate(ctx) {
                return decision;
            }
        }
        Decision::allow()
    }

    /// The ids of the registered checks, in evaluation order.
    pub fn check_ids(&self) -> Vec<&str> {
        self.checks.iter().map(|c| c.id()).collect()
    }

    /// A stable `sha256:<hex>` hash of the gate's configuration: the ordered
    /// list of each check's [`config_fingerprint`](Check::config_fingerprint).
    ///
    /// Record this in a ledger alongside a decision to prove the decision came
    /// from exactly this gate configuration. Because it is order-sensitive and
    /// folds in each check's parameters, a reordered or reconfigured gate hashes
    /// differently.
    pub fn config_hash(&self) -> String {
        let fingerprints: Vec<String> =
            self.checks.iter().map(|c| c.config_fingerprint()).collect();
        let value = serde_json::to_value(&fingerprints).expect("fingerprints serialise to JSON");
        sha256_hex(canonical_keysort_json::to_canonical_string(&value).as_bytes())
    }
}

/// Builds a [`Gate`] by registering checks in evaluation order.
#[derive(Default)]
pub struct GateBuilder {
    checks: Vec<Box<dyn Check>>,
}

impl GateBuilder {
    /// A builder with no checks.
    pub fn new() -> Self {
        Self { checks: Vec::new() }
    }

    /// Register a check. Checks evaluate in the order they are registered.
    #[must_use]
    pub fn check<C: Check + 'static>(mut self, check: C) -> Self {
        self.checks.push(Box::new(check));
        self
    }

    /// Register a pre-boxed check (for dynamically-assembled check sets).
    #[must_use]
    pub fn check_boxed(mut self, check: Box<dyn Check>) -> Self {
        self.checks.push(check);
        self
    }

    /// Finish building.
    pub fn build(self) -> Gate {
        Gate {
            checks: self.checks,
        }
    }
}

/// Serialize a decision to canonical (key-sorted) JSON, for byte-stable hashing
/// and comparison. Two producers serializing the same logical decision produce
/// the same bytes regardless of `serde_json`'s `preserve_order` state.
pub fn decision_to_canonical_json(decision: &Decision) -> String {
    canonical_keysort_json::to_canonical_string(
        &serde_json::to_value(decision).expect("decision serialises to JSON"),
    )
}

/// `sha256:<hex>` over `bytes`. The `sha256:` prefix keeps the hash
/// self-describing, matching the ledger primitive in `attest-ledger`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DenyOn {
        id: String,
        action: String,
    }
    impl Check for DenyOn {
        fn id(&self) -> &str {
            &self.id
        }
        fn evaluate(&self, ctx: &ActionContext) -> Option<Decision> {
            if ctx.action == self.action {
                Some(Decision::deny(
                    format!("gate:deny:{}", self.id),
                    vec![self.id.clone()],
                ))
            } else {
                None
            }
        }
    }

    fn deny_on(id: &str, action: &str) -> DenyOn {
        DenyOn {
            id: id.into(),
            action: action.into(),
        }
    }

    #[test]
    fn empty_gate_allows() {
        let gate = Gate::builder().build();
        assert!(gate.evaluate(&ActionContext::new("anything")).is_allow());
    }

    #[test]
    fn first_matching_check_wins() {
        let gate = Gate::builder()
            .check(deny_on("a", "x"))
            .check(deny_on("b", "x"))
            .build();
        let d = gate.evaluate(&ActionContext::new("x"));
        assert_eq!(d.outcome, Outcome::Deny);
        assert_eq!(d.check_ids, vec!["a"], "first check short-circuits");
    }

    #[test]
    fn non_matching_checks_pass_through_to_allow() {
        let gate = Gate::builder()
            .check(deny_on("a", "x"))
            .check(deny_on("b", "y"))
            .build();
        assert!(gate.evaluate(&ActionContext::new("z")).is_allow());
    }

    #[test]
    fn config_hash_is_stable_and_order_sensitive() {
        let g1 = Gate::builder()
            .check(deny_on("a", "x"))
            .check(deny_on("b", "y"))
            .build();
        let g2 = Gate::builder()
            .check(deny_on("a", "x"))
            .check(deny_on("b", "y"))
            .build();
        assert_eq!(g1.config_hash(), g2.config_hash(), "same config, same hash");
        assert!(g1.config_hash().starts_with("sha256:"));

        let reordered = Gate::builder()
            .check(deny_on("b", "y"))
            .check(deny_on("a", "x"))
            .build();
        assert_ne!(
            g1.config_hash(),
            reordered.config_hash(),
            "order changes the hash"
        );
    }

    #[test]
    fn decision_canonical_json_is_byte_stable() {
        let d = Decision::deny("gate:deny:x", vec!["x".into()]).blocking();
        assert_eq!(
            decision_to_canonical_json(&d),
            decision_to_canonical_json(&d.clone())
        );
        // Keys are sorted regardless of struct field order.
        assert!(decision_to_canonical_json(&d).starts_with("{\"blocking\":true"));
    }
}
