//! Generic reference checks (feature `checks-common`).
//!
//! Two checks that many consumers want and that carry no domain logic:
//! [`SecretsCheck`] (scan the payload for credential patterns) and
//! [`AllowlistCheck`] (deny actions not on a list). Both were already
//! domain-neutral in OAP. Domain checks (destructive-op, spec-status, grounding,
//! suppression, ...) live in the consumer, not here.

use std::collections::BTreeSet;

use action_gate_types::{ActionContext, Check, Decision};
use regex::Regex;

/// Denies when the payload matches a credential pattern. Blocking: a secret in
/// the payload must stop the action regardless of any trust level.
pub struct SecretsCheck {
    patterns: Vec<Regex>,
}

impl Default for SecretsCheck {
    /// The default pattern set (carried from OAP): OpenAI-style keys, PEM
    /// private-key headers, and `api_key = ...` / `secret = ...` / `token = ...`
    /// assignments with a long value.
    fn default() -> Self {
        Self {
            patterns: vec![
                Regex::new(r"(?i)sk-[a-zA-Z0-9]{20,}").expect("valid regex"),
                Regex::new(r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----").expect("valid regex"),
                Regex::new(r#"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['"]?[a-zA-Z0-9_\-]{24,}"#)
                    .expect("valid regex"),
            ],
        }
    }
}

impl SecretsCheck {
    /// A secrets check with a custom pattern set.
    pub fn with_patterns(patterns: Vec<Regex>) -> Self {
        Self { patterns }
    }
}

impl Check for SecretsCheck {
    fn id(&self) -> &str {
        "secrets"
    }

    fn evaluate(&self, ctx: &ActionContext) -> Option<Decision> {
        let haystack = format!(
            "{}\n{}",
            ctx.payload_summary,
            ctx.payload_body.as_deref().unwrap_or("")
        );
        if self.patterns.iter().any(|re| re.is_match(&haystack)) {
            Some(
                Decision::deny("gate:deny:secrets:pattern_match", vec!["secrets".into()])
                    .blocking(),
            )
        } else {
            None
        }
    }

    fn config_fingerprint(&self) -> String {
        let mut pats: Vec<&str> = self.patterns.iter().map(|r| r.as_str()).collect();
        pats.sort_unstable();
        format!("secrets:[{}]", pats.join(","))
    }
}

/// Denies actions not on the allowlist. An empty allowlist is a no-op (nothing
/// is constrained), matching OAP's behavior.
pub struct AllowlistCheck {
    allowed: BTreeSet<String>,
}

impl AllowlistCheck {
    /// Build from any iterator of allowed action names.
    pub fn new(allowed: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            allowed: allowed.into_iter().map(Into::into).collect(),
        }
    }
}

impl Check for AllowlistCheck {
    fn id(&self) -> &str {
        "allowlist"
    }

    fn evaluate(&self, ctx: &ActionContext) -> Option<Decision> {
        if self.allowed.is_empty() || self.allowed.contains(&ctx.action) {
            None
        } else {
            Some(Decision::deny(
                "gate:deny:allowlist:not_listed",
                vec!["allowlist".into()],
            ))
        }
    }

    fn config_fingerprint(&self) -> String {
        // BTreeSet iterates sorted, so the fingerprint is deterministic.
        format!(
            "allowlist:[{}]",
            self.allowed.iter().cloned().collect::<Vec<_>>().join(",")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_denies_on_match_and_is_blocking() {
        let check = SecretsCheck::default();
        let ctx = ActionContext::new("write").with_summary("sk-123456789012345678901234567890");
        let d = check.evaluate(&ctx).expect("secret matched");
        assert!(d.reason.contains("secrets"));
        assert!(d.blocking);
    }

    #[test]
    fn secrets_passes_clean_payload() {
        let check = SecretsCheck::default();
        assert!(
            check
                .evaluate(&ActionContext::new("write").with_summary("hello world"))
                .is_none()
        );
    }

    #[test]
    fn allowlist_denies_unknown_allows_listed() {
        let check = AllowlistCheck::new(["read", "grep"]);
        assert!(check.evaluate(&ActionContext::new("read")).is_none());
        let d = check
            .evaluate(&ActionContext::new("shell"))
            .expect("not listed");
        assert!(d.reason.contains("not_listed"));
    }

    #[test]
    fn empty_allowlist_is_noop() {
        let check = AllowlistCheck::new(Vec::<String>::new());
        assert!(check.evaluate(&ActionContext::new("anything")).is_none());
    }

    #[test]
    fn fingerprints_are_deterministic() {
        // Insertion order does not change the allowlist fingerprint.
        let a = AllowlistCheck::new(["b", "a"]);
        let b = AllowlistCheck::new(["a", "b"]);
        assert_eq!(a.config_fingerprint(), b.config_fingerprint());
    }
}
