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
//! That is the default, [`Mode::Open`]. A gate built with
//! [`GateBuilder::closed`] or [`GateBuilder::require`] evaluates in
//! [`Mode::Closed`] instead: it denies when no check decides, and every
//! required check must be registered and must decide. See [`Mode`] and the
//! [`closed`] module for the rules and reason codes.
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

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

#[cfg(feature = "checks-common")]
pub mod checks;

pub mod secrets;

/// How a [`Gate`] combines its checks' answers (spec 003).
///
/// The mode is part of [`Gate::config_hash`]: a closed gate never hashes the
/// same as an open one, whatever its checks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Mode {
    /// The 0.1.0 and 0.2.0 behaviour, and the default. Checks run in
    /// registration order; the first `Some` wins, whatever its outcome; when
    /// no check returns `Some`, the gate allows with
    /// `gate:allow:no_check_triggered`.
    #[default]
    Open,
    /// Deny by default, with required checks. Before any check runs, every
    /// required id must name a registered check, or the gate denies with
    /// [`closed::REQUIRED_UNREGISTERED`]. Checks then run in registration
    /// order:
    ///
    /// - a `Deny` ends the evaluation and is the decision; later checks do
    ///   not run;
    /// - a required check that returns `None` is a deny,
    ///   [`closed::REQUIRED_UNDECIDED`], and ends the evaluation the same way;
    /// - an `Allow` or a `Degrade` does **not** end the evaluation, so a later
    ///   check can still deny.
    ///
    /// When every check has run without a deny, the decision is the first
    /// `Degrade` if there was one, else an allow ([`closed::AFFIRMED`]) if at
    /// least one check returned `Allow`, else a deny
    /// ([`closed::NO_CHECK_DECIDED`]). Every deny the gate itself produces is
    /// blocking; a check's own decision is returned unchanged.
    Closed,
}

/// The stable reason codes a [`Mode::Closed`] gate produces itself (spec 003
/// B-6). A check's own decision keeps the check's reason.
pub mod closed {
    /// No check returned `Some`. `check_ids` lists every check that ran, in
    /// order (empty for a gate with no checks).
    pub const NO_CHECK_DECIDED: &str = "gate:deny:closed:no_check_decided";
    /// A required id names no registered check. `check_ids` lists every such
    /// id, sorted; no check ran.
    pub const REQUIRED_UNREGISTERED: &str = "gate:deny:closed:required_unregistered";
    /// A required check ran and returned `None`. `check_ids` is that check's
    /// id.
    pub const REQUIRED_UNDECIDED: &str = "gate:deny:closed:required_undecided";
    /// Every check ran, none denied or degraded, and at least one allowed.
    /// `check_ids` lists the checks that allowed, in order.
    pub const AFFIRMED: &str = "gate:allow:closed:affirmed";
}

/// Everything [`Gate::evaluate_exhaustive`] found: the decision
/// [`Gate::evaluate`] returns, and every deny along the way.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Evaluation {
    /// Equal to [`Gate::evaluate`] on the same context.
    pub decision: Decision,
    /// Every deny, in registration order: each check's own `Deny` and, in
    /// [`Mode::Closed`], each deny the gate produced (an undecided required
    /// check at its position, an unregistered requirement or the no-decision
    /// deny alone). In closed mode the decision is a deny exactly when this is
    /// non-empty, and is then its first element. In open mode an earlier
    /// `Some` can decide before a listed deny is reached.
    pub denials: Vec<Decision>,
}

/// A pure decision gate over an ordered list of checks.
pub struct Gate {
    checks: Vec<Box<dyn Check>>,
    mode: Mode,
    required: BTreeSet<String>,
}

impl Gate {
    /// Start building a gate.
    pub fn builder() -> GateBuilder {
        GateBuilder::new()
    }

    /// Evaluate `ctx` against the checks in order, under the gate's [`Mode`].
    ///
    /// In [`Mode::Open`] (the default) the first check to return `Some` wins;
    /// if none does, the gate allows. [`Mode::Closed`] is documented on the
    /// variant.
    pub fn evaluate(&self, ctx: &ActionContext) -> Decision {
        match self.mode {
            Mode::Open => {
                for check in &self.checks {
                    if let Some(decision) = check.evaluate(ctx) {
                        return decision;
                    }
                }
                Decision::allow()
            }
            Mode::Closed => self.evaluate_closed(ctx, false).decision,
        }
    }

    /// Evaluate `ctx` and also collect every deny (spec 003 B-8).
    ///
    /// Every check runs, including those after the deciding one, so a
    /// consumer that reports all of its reasons can read them in registration
    /// order. The decision is the one [`Gate::evaluate`] returns.
    pub fn evaluate_exhaustive(&self, ctx: &ActionContext) -> Evaluation {
        match self.mode {
            Mode::Open => {
                let denials = self
                    .checks
                    .iter()
                    .filter_map(|c| c.evaluate(ctx))
                    .filter(|d| d.outcome == Outcome::Deny)
                    .collect();
                Evaluation {
                    decision: self.evaluate(ctx),
                    denials,
                }
            }
            Mode::Closed => self.evaluate_closed(ctx, true),
        }
    }

    /// The closed-mode rules of [`Mode::Closed`]. With `exhaustive`, a deny
    /// does not stop the walk; the decision is the same either way.
    fn evaluate_closed(&self, ctx: &ActionContext, exhaustive: bool) -> Evaluation {
        let missing = self.unregistered_required();
        if !missing.is_empty() {
            let deny = Decision::deny(
                closed::REQUIRED_UNREGISTERED,
                missing.into_iter().map(String::from).collect(),
            )
            .blocking();
            return Evaluation {
                decision: deny.clone(),
                denials: vec![deny],
            };
        }

        let mut denials = Vec::new();
        let mut degrade = None;
        let mut allowed = Vec::new();
        let mut ran = Vec::new();
        for check in &self.checks {
            let id = check.id();
            ran.push(id.to_string());
            match check.evaluate(ctx) {
                Some(d) if d.outcome == Outcome::Deny => denials.push(d),
                Some(d) if d.outcome == Outcome::Degrade => {
                    degrade.get_or_insert(d);
                }
                Some(_) => allowed.push(id.to_string()),
                None if self.required.contains(id) => denials.push(
                    Decision::deny(closed::REQUIRED_UNDECIDED, vec![id.to_string()]).blocking(),
                ),
                None => {}
            }
            if !exhaustive && !denials.is_empty() {
                break;
            }
        }

        let decision = if let Some(first) = denials.first() {
            first.clone()
        } else if let Some(d) = degrade {
            d
        } else if !allowed.is_empty() {
            Decision {
                outcome: Outcome::Allow,
                reason: closed::AFFIRMED.into(),
                check_ids: allowed,
                blocking: false,
            }
        } else {
            let deny = Decision::deny(closed::NO_CHECK_DECIDED, ran).blocking();
            denials.push(deny.clone());
            deny
        };
        Evaluation { decision, denials }
    }

    /// The ids of the registered checks, in evaluation order.
    pub fn check_ids(&self) -> Vec<&str> {
        self.checks.iter().map(|c| c.id()).collect()
    }

    /// The gate's evaluation mode.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The required check ids, sorted. Empty for an open gate.
    pub fn required_ids(&self) -> Vec<&str> {
        self.required.iter().map(String::as_str).collect()
    }

    /// The required ids that name no registered check, sorted. A closed gate
    /// with any denies every action ([`closed::REQUIRED_UNREGISTERED`]); a
    /// consumer can call this at startup to refuse the configuration early.
    pub fn unregistered_required(&self) -> Vec<&str> {
        self.required
            .iter()
            .filter(|id| !self.checks.iter().any(|c| c.id() == id.as_str()))
            .map(String::as_str)
            .collect()
    }

    /// A stable `sha256:<hex>` hash of the gate's configuration.
    ///
    /// In [`Mode::Open`] it is taken over the canonical JSON array of each
    /// check's [`config_fingerprint`](Check::config_fingerprint), in order,
    /// exactly as in 0.1.0 and 0.2.0, so a recorded hash does not move. In
    /// [`Mode::Closed`] it is taken over the canonical JSON object
    /// `{"checks": [...], "mode": "closed", "required": [...]}` with the
    /// required ids sorted. An object never serializes like an array, so a
    /// closed gate never hashes the same as an open one.
    ///
    /// Record this in a ledger alongside a decision to prove the decision came
    /// from exactly this gate configuration. Because it is order-sensitive and
    /// folds in each check's parameters, a reordered or reconfigured gate hashes
    /// differently.
    pub fn config_hash(&self) -> String {
        let fingerprints: Vec<String> =
            self.checks.iter().map(|c| c.config_fingerprint()).collect();
        let value = match self.mode {
            Mode::Open => {
                serde_json::to_value(&fingerprints).expect("fingerprints serialise to JSON")
            }
            Mode::Closed => serde_json::json!({
                "checks": fingerprints,
                "mode": "closed",
                "required": self.required,
            }),
        };
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
/// It belongs to [`Mode::Open`]. A [`Mode::Closed`] gate does not stop at an
/// allow, so this check would deny every action there; a closed gate denies
/// undecided actions by itself.
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
    mode: Mode,
    required: BTreeSet<String>,
}

impl GateBuilder {
    /// A builder with no checks, in [`Mode::Open`].
    pub fn new() -> Self {
        Self::default()
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

    /// Evaluate in [`Mode::Closed`]: deny when no check decides.
    ///
    /// ```
    /// use action_gate_core::{closed, ActionContext, Check, Decision, Gate};
    ///
    /// struct AllowRead;
    /// impl Check for AllowRead {
    ///     fn id(&self) -> &str { "allow-read" }
    ///     fn evaluate(&self, ctx: &ActionContext) -> Option<Decision> {
    ///         (ctx.action == "read").then(Decision::allow)
    ///     }
    /// }
    ///
    /// let gate = Gate::builder().check(AllowRead).closed().build();
    /// assert!(gate.evaluate(&ActionContext::new("read")).is_allow());
    /// let d = gate.evaluate(&ActionContext::new("write"));
    /// assert_eq!(d.reason, closed::NO_CHECK_DECIDED);
    /// assert!(d.blocking);
    /// ```
    #[must_use]
    pub fn closed(mut self) -> Self {
        self.mode = Mode::Closed;
        self
    }

    /// Require the check with `id`: it must be registered and must return
    /// `Some` on every evaluation, or the gate denies. Requiring a check puts
    /// the gate in [`Mode::Closed`]; there is no open gate with requirements.
    /// The requirement may be stated before or after the check is registered.
    ///
    /// ```
    /// use action_gate_core::{closed, ActionContext, Check, Decision, Gate};
    ///
    /// struct Scan;
    /// impl Check for Scan {
    ///     fn id(&self) -> &str { "scan" }
    ///     fn evaluate(&self, _ctx: &ActionContext) -> Option<Decision> {
    ///         Some(Decision::allow())
    ///     }
    /// }
    ///
    /// // Required but never registered: every action is denied.
    /// let gate = Gate::builder().require("scan").build();
    /// let d = gate.evaluate(&ActionContext::new("write"));
    /// assert_eq!(d.reason, closed::REQUIRED_UNREGISTERED);
    /// assert_eq!(d.check_ids, vec!["scan"]);
    ///
    /// let gate = Gate::builder().check(Scan).require("scan").build();
    /// assert!(gate.evaluate(&ActionContext::new("write")).is_allow());
    /// ```
    #[must_use]
    pub fn require(mut self, id: impl Into<String>) -> Self {
        self.required.insert(id.into());
        self.mode = Mode::Closed;
        self
    }

    /// Require every id in `ids`; see [`require`](Self::require).
    #[must_use]
    pub fn require_all(self, ids: impl IntoIterator<Item = impl Into<String>>) -> Self {
        ids.into_iter().fold(self, |b, id| b.require(id))
    }

    /// Finish building.
    pub fn build(self) -> Gate {
        Gate {
            checks: self.checks,
            mode: self.mode,
            required: self.required,
        }
    }

    /// Register [`DenyByDefault`] as the terminal check and finish building:
    /// the gate denies any action no earlier check decides. An open-mode
    /// shorthand; see [`DenyByDefault`] on combining it with [`closed`](Self::closed).
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
