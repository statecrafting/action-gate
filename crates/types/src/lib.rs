// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Bartek Kus
//
// Relicensed from the Open Agentic Platform (crates/policy-kernel/lib.rs,
// AGPL-3.0-or-later) to Apache-2.0 by the sole copyright holder. See NOTICE.

//! Domain-neutral types for `action-gate`: the [`ActionContext`] an evaluation
//! runs over, the [`Decision`] a check returns, the [`Outcome`] enum, and the
//! [`Check`] trait a consumer implements.
//!
//! This crate holds only the contract; the [`Gate`] that runs a check registry
//! lives in `action-gate-core`. A crate that only defines check implementations
//! can depend on this alone.
//!
//! [`Gate`]: https://docs.rs/action-gate-core

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Everything a [`Check`] needs to make its decision about a proposed action.
///
/// The core never inspects `attributes`; only checks do. That is what keeps the
/// context domain-neutral: OAP's `diff_lines` / `spec_statuses` / `max_spec_risk`
/// and chancery's `fact_sheet_id` / `investor_id` all live in `attributes`,
/// read only by the checks that understand them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionContext {
    /// The action being proposed, e.g. `"email.send"`, `"workspace.write_file"`.
    /// (OAP's `tool_name`.)
    pub action: String,
    /// A canonical string form of the payload, for scanning. (OAP's
    /// `arguments_summary`.)
    #[serde(default)]
    pub payload_summary: String,
    /// The full content under review, when there is one. (OAP's
    /// `proposed_file_content`.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_body: Option<String>,
    /// Everything domain-specific, keyed by name. Checks read what they need.
    #[serde(default)]
    pub attributes: BTreeMap<String, Value>,
}

impl ActionContext {
    /// A context for `action` with an empty payload and no attributes.
    pub fn new(action: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            payload_summary: String::new(),
            payload_body: None,
            attributes: BTreeMap::new(),
        }
    }

    /// Builder: set the payload summary (the string checks scan).
    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.payload_summary = summary.into();
        self
    }

    /// Builder: set the payload body (the full content under review).
    pub fn with_body(mut self, body: impl Into<String>) -> Self {
        self.payload_body = Some(body.into());
        self
    }

    /// Builder: insert a domain attribute.
    pub fn with_attr(mut self, key: impl Into<String>, value: Value) -> Self {
        self.attributes.insert(key.into(), value);
        self
    }

    /// Read an attribute as a string, if present and a string.
    pub fn attr_str(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).and_then(Value::as_str)
    }

    /// Read a raw attribute value.
    pub fn attr(&self, key: &str) -> Option<&Value> {
        self.attributes.get(key)
    }
}

/// The three possible outcomes of a decision.
///
/// `Degrade` is a **signal**, not an action: the gate does not perform a
/// degraded action. The consumer decides what `Degrade` means (route to a
/// human, require confirmation, drop to read-only). Keeping this honest is why
/// the gate is a pure function and never touches the world.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Allow,
    Deny,
    Degrade,
}

/// The result a [`Check`] returns and the [`Gate`](https://docs.rs/action-gate-core)
/// yields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub outcome: Outcome,
    /// A stable, machine-readable reason code, e.g.
    /// `"gate:deny:secrets:pattern_match"`.
    pub reason: String,
    /// The ids consulted for this outcome (may be empty for an unconditional
    /// allow). Consumers that carry their own rule identifiers put them here.
    #[serde(default)]
    pub check_ids: Vec<String>,
    /// When `true`, this decision must block regardless of any downstream trust
    /// level or consumer autonomy policy. A pure signal for the consumer; the
    /// gate itself does not act on it.
    #[serde(default)]
    pub blocking: bool,
}

impl Decision {
    /// The unconditional allow the gate yields when no check triggers.
    pub fn allow() -> Self {
        Self {
            outcome: Outcome::Allow,
            reason: "gate:allow:no_check_triggered".into(),
            check_ids: Vec::new(),
            blocking: false,
        }
    }

    /// A deny with the given reason code and consulted ids.
    pub fn deny(reason: impl Into<String>, check_ids: Vec<String>) -> Self {
        Self {
            outcome: Outcome::Deny,
            reason: reason.into(),
            check_ids,
            blocking: false,
        }
    }

    /// A degrade with the given reason code and consulted ids.
    pub fn degrade(reason: impl Into<String>, check_ids: Vec<String>) -> Self {
        Self {
            outcome: Outcome::Degrade,
            reason: reason.into(),
            check_ids,
            blocking: false,
        }
    }

    /// Mark this decision as blocking (must block regardless of trust/policy).
    pub fn blocking(mut self) -> Self {
        self.blocking = true;
        self
    }

    /// Whether this decision is an allow.
    pub fn is_allow(&self) -> bool {
        self.outcome == Outcome::Allow
    }
}

/// A single gate check.
///
/// A check is a **pure function** of the [`ActionContext`]: it must not call the
/// host, read a clock, or mutate state, so a gate assembled from checks is
/// deterministic and unit-testable. Return `Some(decision)` to short-circuit
/// the gate, `None` to pass to the next check.
pub trait Check: Send + Sync {
    /// A stable identifier for this check (e.g. `"secrets"`, `"grounding"`).
    fn id(&self) -> &str;

    /// Evaluate the context. `Some` short-circuits the gate; `None` passes on.
    fn evaluate(&self, ctx: &ActionContext) -> Option<Decision>;

    /// A stable fingerprint of this check's identity **and parameters**, folded
    /// into the gate's config hash. Defaults to [`id`](Check::id); a check with
    /// tunable parameters should override this to include them, so a recorded
    /// decision can be bound to the exact gate configuration that produced it.
    fn config_fingerprint(&self) -> String {
        self.id().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn context_builder_and_accessors() {
        let ctx = ActionContext::new("email.send")
            .with_summary("hello")
            .with_attr("investor_id", json!("inv-1"));
        assert_eq!(ctx.action, "email.send");
        assert_eq!(ctx.attr_str("investor_id"), Some("inv-1"));
        assert_eq!(ctx.attr_str("missing"), None);
    }

    #[test]
    fn decision_constructors() {
        assert!(Decision::allow().is_allow());
        let d = Decision::deny("gate:deny:x", vec!["x".into()]).blocking();
        assert_eq!(d.outcome, Outcome::Deny);
        assert!(d.blocking);
        assert_eq!(
            Decision::degrade("gate:degrade:y", vec![]).outcome,
            Outcome::Degrade
        );
    }
}
