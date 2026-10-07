//! Spec 003 FR-001 and FR-002: the open (0.2.0) evaluation mode is unchanged.
//!
//! Every literal below was captured by running this file, unmodified, against
//! action-gate-core 0.2.0 (commit 6cfa81e) before the closed mode existed.
//! The file uses only the 0.2.0 public API, so it compiles and passes against
//! both versions: a recorded `Gate::config_hash` and a recorded decision's
//! canonical bytes do not move.

use action_gate_core::secrets::SecretScanCheck;
use action_gate_core::{ActionContext, Check, Decision, Gate, decision_to_canonical_json};

struct DenyOn {
    id: &'static str,
    action: &'static str,
}

impl Check for DenyOn {
    fn id(&self) -> &str {
        self.id
    }
    fn evaluate(&self, ctx: &ActionContext) -> Option<Decision> {
        (ctx.action == self.action)
            .then(|| Decision::deny(format!("gate:deny:{}", self.id), vec![self.id.into()]))
    }
}

struct AllowOn(&'static str);

impl Check for AllowOn {
    fn id(&self) -> &str {
        "allow-on"
    }
    fn evaluate(&self, ctx: &ActionContext) -> Option<Decision> {
        (ctx.action == self.0).then(Decision::allow)
    }
    fn config_fingerprint(&self) -> String {
        format!("allow-on:{}", self.0)
    }
}

fn gates() -> Vec<(&'static str, Gate)> {
    let gates = vec![
        ("empty", Gate::builder().build()),
        (
            "two-denies",
            Gate::builder()
                .check(DenyOn {
                    id: "a",
                    action: "x",
                })
                .check(DenyOn {
                    id: "b",
                    action: "y",
                })
                .build(),
        ),
        (
            "two-denies-reordered",
            Gate::builder()
                .check(DenyOn {
                    id: "b",
                    action: "y",
                })
                .check(DenyOn {
                    id: "a",
                    action: "x",
                })
                .build(),
        ),
        (
            "deny-by-default",
            Gate::builder()
                .check(DenyOn {
                    id: "a",
                    action: "x",
                })
                .check(AllowOn("read"))
                .build_deny_by_default(),
        ),
        (
            "secret-scan",
            Gate::builder().check(SecretScanCheck::default()).build(),
        ),
    ];
    gates.into_iter().chain(common_gates()).collect()
}

/// The `checks-common` configuration, when that feature is on.
#[cfg(feature = "checks-common")]
fn common_gates() -> Vec<(&'static str, Gate)> {
    use action_gate_core::checks::{AllowlistCheck, SecretsCheck};
    vec![(
        "checks-common",
        Gate::builder()
            .check(SecretsCheck::default())
            .check(AllowlistCheck::new(["email.send", "email.draft"]))
            .build(),
    )]
}

#[cfg(not(feature = "checks-common"))]
fn common_gates() -> Vec<(&'static str, Gate)> {
    Vec::new()
}

/// `config_hash` of each gate above, as 0.2.0 computed it.
const HASHES: &[(&str, &str)] = &[
    (
        "empty",
        "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    ),
    (
        "two-denies",
        "sha256:0473ef2dc0d324ab659d3580c1134e9d812035905c4781fdd6d529b0c6860e13",
    ),
    (
        "two-denies-reordered",
        "sha256:02d8bc3008a9bb0dcc4b86d7fd3428ced792355c733c19756bec5a56dc61b2c5",
    ),
    (
        "deny-by-default",
        "sha256:056cd69ed6544286f0571da776700c99dd7d0c8f754b28c1e192759ab6fea7d4",
    ),
    (
        "secret-scan",
        "sha256:884b68b06b8ad43e1b53265e0499c8ab7c7e112c60b0b4cba2b97619a185c81d",
    ),
    (
        "checks-common",
        "sha256:2110215b6553eeeb140027c7e8afdeacdd27e6d1782c9c3128b40ce643836742",
    ),
];

/// `(gate, action, summary, canonical decision JSON)` as 0.2.0 produced it.
const DECISIONS: &[(&str, &str, &str, &str)] = &[
    (
        "empty",
        "x",
        "",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "empty",
        "y",
        "",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "empty",
        "read",
        "",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "empty",
        "z",
        "",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "empty",
        "write",
        "key sk-123456789012345678901234567890 here",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "empty",
        "email.send",
        "",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "empty",
        "shell",
        "",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "two-denies",
        "x",
        "",
        r#"{"blocking":false,"check_ids":["a"],"outcome":"deny","reason":"gate:deny:a"}"#,
    ),
    (
        "two-denies",
        "y",
        "",
        r#"{"blocking":false,"check_ids":["b"],"outcome":"deny","reason":"gate:deny:b"}"#,
    ),
    (
        "two-denies",
        "read",
        "",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "two-denies",
        "z",
        "",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "two-denies",
        "write",
        "key sk-123456789012345678901234567890 here",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "two-denies",
        "email.send",
        "",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "two-denies",
        "shell",
        "",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "two-denies-reordered",
        "x",
        "",
        r#"{"blocking":false,"check_ids":["a"],"outcome":"deny","reason":"gate:deny:a"}"#,
    ),
    (
        "two-denies-reordered",
        "y",
        "",
        r#"{"blocking":false,"check_ids":["b"],"outcome":"deny","reason":"gate:deny:b"}"#,
    ),
    (
        "two-denies-reordered",
        "read",
        "",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "two-denies-reordered",
        "z",
        "",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "two-denies-reordered",
        "write",
        "key sk-123456789012345678901234567890 here",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "two-denies-reordered",
        "email.send",
        "",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "two-denies-reordered",
        "shell",
        "",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "deny-by-default",
        "x",
        "",
        r#"{"blocking":false,"check_ids":["a"],"outcome":"deny","reason":"gate:deny:a"}"#,
    ),
    (
        "deny-by-default",
        "y",
        "",
        r#"{"blocking":true,"check_ids":["deny-by-default"],"outcome":"deny","reason":"gate:deny:default:no_check_decided"}"#,
    ),
    (
        "deny-by-default",
        "read",
        "",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "deny-by-default",
        "z",
        "",
        r#"{"blocking":true,"check_ids":["deny-by-default"],"outcome":"deny","reason":"gate:deny:default:no_check_decided"}"#,
    ),
    (
        "deny-by-default",
        "write",
        "key sk-123456789012345678901234567890 here",
        r#"{"blocking":true,"check_ids":["deny-by-default"],"outcome":"deny","reason":"gate:deny:default:no_check_decided"}"#,
    ),
    (
        "deny-by-default",
        "email.send",
        "",
        r#"{"blocking":true,"check_ids":["deny-by-default"],"outcome":"deny","reason":"gate:deny:default:no_check_decided"}"#,
    ),
    (
        "deny-by-default",
        "shell",
        "",
        r#"{"blocking":true,"check_ids":["deny-by-default"],"outcome":"deny","reason":"gate:deny:default:no_check_decided"}"#,
    ),
    (
        "secret-scan",
        "x",
        "",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "secret-scan",
        "y",
        "",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "secret-scan",
        "read",
        "",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "secret-scan",
        "z",
        "",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "secret-scan",
        "write",
        "key sk-123456789012345678901234567890 here",
        r#"{"blocking":true,"check_ids":["secret-scan"],"outcome":"deny","reason":"gate:deny:secrets:openai-api-key:summary:4"}"#,
    ),
    (
        "secret-scan",
        "email.send",
        "",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "secret-scan",
        "shell",
        "",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "checks-common",
        "x",
        "",
        r#"{"blocking":false,"check_ids":["allowlist"],"outcome":"deny","reason":"gate:deny:allowlist:not_listed"}"#,
    ),
    (
        "checks-common",
        "y",
        "",
        r#"{"blocking":false,"check_ids":["allowlist"],"outcome":"deny","reason":"gate:deny:allowlist:not_listed"}"#,
    ),
    (
        "checks-common",
        "read",
        "",
        r#"{"blocking":false,"check_ids":["allowlist"],"outcome":"deny","reason":"gate:deny:allowlist:not_listed"}"#,
    ),
    (
        "checks-common",
        "z",
        "",
        r#"{"blocking":false,"check_ids":["allowlist"],"outcome":"deny","reason":"gate:deny:allowlist:not_listed"}"#,
    ),
    (
        "checks-common",
        "write",
        "key sk-123456789012345678901234567890 here",
        r#"{"blocking":true,"check_ids":["secrets"],"outcome":"deny","reason":"gate:deny:secrets:pattern_match"}"#,
    ),
    (
        "checks-common",
        "email.send",
        "",
        r#"{"blocking":false,"check_ids":[],"outcome":"allow","reason":"gate:allow:no_check_triggered"}"#,
    ),
    (
        "checks-common",
        "shell",
        "",
        r#"{"blocking":false,"check_ids":["allowlist"],"outcome":"deny","reason":"gate:deny:allowlist:not_listed"}"#,
    ),
];

const PROBES: &[(&str, &str)] = &[
    ("x", ""),
    ("y", ""),
    ("read", ""),
    ("z", ""),
    ("write", "key sk-123456789012345678901234567890 here"),
    ("email.send", ""),
    ("shell", ""),
];

#[test]
fn fr001_open_mode_config_hashes_are_the_0_2_0_values() {
    let gates = gates();
    for (name, gate) in &gates {
        let expected = HASHES
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("no pinned hash for {name}"))
            .1;
        assert_eq!(gate.config_hash(), expected, "config_hash of {name} moved");
    }
    // Every pinned configuration is exercised under --all-features.
    if cfg!(feature = "checks-common") {
        assert_eq!(gates.len(), HASHES.len());
    }
}

#[test]
fn fr002_open_mode_decisions_are_the_0_2_0_bytes() {
    let mut seen = 0;
    for (name, gate) in gates() {
        for (action, summary) in PROBES {
            let ctx = ActionContext::new(*action).with_summary(*summary);
            let expected = DECISIONS
                .iter()
                .find(|(n, a, s, _)| *n == name && a == action && s == summary)
                .unwrap_or_else(|| panic!("no pinned decision for {name} on {action}"))
                .3;
            assert_eq!(
                decision_to_canonical_json(&gate.evaluate(&ctx)),
                expected,
                "decision of {name} on {action} moved"
            );
            seen += 1;
        }
    }
    if cfg!(feature = "checks-common") {
        assert_eq!(seen, DECISIONS.len());
    }
}
