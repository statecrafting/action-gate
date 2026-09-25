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

pub mod secrets;

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

/// A terminal check that denies whatever reached it (spec 001 B-14).
///
/// The gate's published default is to allow when no check returns `Some`.
/// Registering `DenyByDefault` last closes it instead: an action passes only if
/// an earlier check returns `Some(Decision::allow())`. Checks registered after
/// it never run. It is never added implicitly; see also
/// [`GateBuilder::build_deny_by_default`].
///
/// The deny is blocking, so a trust layer downstream cannot reopen a gate its
/// operator explicitly closed.
///
/// ```
/// use action_gate_core::{ActionContext, Check, Decision, Gate};
///
/// struct AllowRead;
/// impl Check for AllowRead {
///     fn id(&self) -> &str { "allow-read" }
///     fn evaluate(&self, ctx: &ActionContext) -> Option<Decision> {
///         (ctx.action == "read").then(Decision::allow)
///     }
/// }
///
/// let gate = Gate::builder().check(AllowRead).build_deny_by_default();
/// assert!(gate.evaluate(&ActionContext::new("read")).is_allow());
/// assert!(!gate.evaluate(&ActionContext::new("write")).is_allow());
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DenyByDefault;

impl DenyByDefault {
    /// The check id, as it appears in a decision's `check_ids`.
    pub const ID: &'static str = "deny-by-default";
    /// The reason of every decision this check returns.
    pub const REASON: &'static str = "gate:deny:default:no_check_decided";
}

impl Check for DenyByDefault {
    fn id(&self) -> &str {
        Self::ID
    }

    fn evaluate(&self, _ctx: &ActionContext) -> Option<Decision> {
        Some(Decision::deny(Self::REASON, vec![Self::ID.into()]).blocking())
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

    /// Register [`DenyByDefault`] as the terminal check and finish building:
    /// the gate denies any action no earlier check decides.
    pub fn build_deny_by_default(self) -> Gate {
        self.check(DenyByDefault).build()
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

    struct AllowOn(&'static str);
    impl Check for AllowOn {
        fn id(&self) -> &str {
            "allow-on"
        }
        fn evaluate(&self, ctx: &ActionContext) -> Option<Decision> {
            (ctx.action == self.0).then(Decision::allow)
        }
    }

    #[test]
    fn deny_by_default_closes_the_gate() {
        let gate = Gate::builder()
            .check(deny_on("a", "x"))
            .check(AllowOn("read"))
            .build_deny_by_default();
        assert!(gate.evaluate(&ActionContext::new("read")).is_allow());
        let d = gate.evaluate(&ActionContext::new("z"));
        assert_eq!(d.outcome, Outcome::Deny);
        assert_eq!(d.reason, DenyByDefault::REASON);
        assert_eq!(d.check_ids, vec!["deny-by-default"]);
        assert!(d.blocking);
        assert_eq!(gate.evaluate(&ActionContext::new("x")).check_ids, vec!["a"]);
        assert_eq!(gate.check_ids(), vec!["a", "allow-on", "deny-by-default"]);
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
