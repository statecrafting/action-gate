//! Spec 003: the closed evaluation mode. FR-003 to FR-009.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use action_gate_core::{
    ActionContext, Check, Decision, Gate, GateBuilder, Mode, Outcome, closed,
    decision_to_canonical_json,
};
use proptest::prelude::*;
use serde_json::Value;

const VECTORS: &str = include_str!("../testdata/closed-mode-vectors.json");

/// A check answering from a fixed script: the vectors' check shape.
struct Scripted {
    id: String,
    answers: BTreeMap<String, String>,
}

impl Check for Scripted {
    fn id(&self) -> &str {
        &self.id
    }
    fn evaluate(&self, ctx: &ActionContext) -> Option<Decision> {
        let id = &self.id;
        match self.answers.get(&ctx.action).map(String::as_str) {
            None => None,
            Some("allow") => Some(Decision::allow()),
            Some("deny") => Some(Decision::deny(format!("test:deny:{id}"), vec![id.clone()])),
            Some("degrade") => Some(Decision::degrade(
                format!("test:degrade:{id}"),
                vec![id.clone()],
            )),
            Some(other) => panic!("unknown scripted answer {other}"),
        }
    }
}

fn scripted(id: &str, answers: &[(&str, &str)]) -> Scripted {
    Scripted {
        id: id.into(),
        answers: answers
            .iter()
            .map(|(a, o)| ((*a).into(), (*o).into()))
            .collect(),
    }
}

fn gate_of(vector: &Value) -> Gate {
    let mut builder = Gate::builder();
    for check in vector["checks"].as_array().expect("checks") {
        builder = builder.check(Scripted {
            id: check["id"].as_str().expect("id").into(),
            answers: check["answers"]
                .as_object()
                .expect("answers")
                .iter()
                .map(|(a, o)| (a.clone(), o.as_str().expect("outcome").into()))
                .collect(),
        });
    }
    match vector["mode"].as_str() {
        Some("open") => builder.build(),
        Some("closed") => builder
            .closed()
            .require_all(
                vector["required"]
                    .as_array()
                    .expect("required")
                    .iter()
                    .map(|r| r.as_str().expect("id").to_owned()),
            )
            .build(),
        other => panic!("unknown mode {other:?}"),
    }
}

/// A vector's decision, through `Decision` and the published canonical form.
fn canonical(v: &Value) -> String {
    let d: Decision = serde_json::from_value(v.clone()).expect("a decision");
    decision_to_canonical_json(&d)
}

/// FR-003: every golden vector's config hash, decision and denials.
#[test]
fn fr003_golden_vectors() {
    let doc: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    let vectors = doc["vectors"].as_array().expect("vectors");
    assert!(vectors.len() >= 10);
    for vector in vectors {
        let id = vector["id"].as_str().expect("id");
        let gate = gate_of(vector);
        assert_eq!(
            gate.config_hash(),
            vector["config_hash"].as_str().expect("hash"),
            "{id}: config_hash"
        );
        for case in vector["cases"].as_array().expect("cases") {
            let ctx = ActionContext::new(case["action"].as_str().expect("action"));
            let decision = gate.evaluate(&ctx);
            assert_eq!(
                decision_to_canonical_json(&decision),
                canonical(&case["decision"]),
                "{id} on {}: decision",
                ctx.action
            );
            let evaluation = gate.evaluate_exhaustive(&ctx);
            assert_eq!(evaluation.decision, decision, "{id}: exhaustive decision");
            let denials: Vec<String> = evaluation
                .denials
                .iter()
                .map(decision_to_canonical_json)
                .collect();
            let expected: Vec<String> = case["denials"]
                .as_array()
                .expect("denials")
                .iter()
                .map(canonical)
                .collect();
            assert_eq!(denials, expected, "{id} on {}: denials", ctx.action);
        }
    }
}

/// FR-004: a closed gate never hashes like an open one, and the hash covers
/// the mode, the checks in order and the required set (not its order).
#[test]
fn fr004_config_hash_separates_modes_and_requirements() {
    let open = Gate::builder()
        .check(scripted("a", &[]))
        .check(scripted("b", &[]))
        .build();
    let closed = Gate::builder()
        .check(scripted("a", &[]))
        .check(scripted("b", &[]))
        .closed()
        .build();
    let required = Gate::builder()
        .check(scripted("a", &[]))
        .check(scripted("b", &[]))
        .require("a")
        .build();
    let required_first = Gate::builder()
        .require("a")
        .check(scripted("a", &[]))
        .check(scripted("b", &[]))
        .build();
    let reordered = Gate::builder()
        .check(scripted("b", &[]))
        .check(scripted("a", &[]))
        .require("a")
        .build();
    let deny_by_default = Gate::builder()
        .check(scripted("a", &[]))
        .check(scripted("b", &[]))
        .build_deny_by_default();

    let hashes = [
        open.config_hash(),
        closed.config_hash(),
        required.config_hash(),
        reordered.config_hash(),
        deny_by_default.config_hash(),
    ];
    for (i, a) in hashes.iter().enumerate() {
        for b in &hashes[i + 1..] {
            assert_ne!(a, b);
        }
    }
    assert_eq!(required.config_hash(), required_first.config_hash());
    assert_eq!(
        Gate::builder().closed().build().config_hash(),
        Gate::builder().closed().build().config_hash()
    );
    assert_ne!(
        Gate::builder().closed().build().config_hash(),
        Gate::builder().build().config_hash()
    );
}

/// FR-005: requiring a check closes the gate; the default stays open.
#[test]
fn fr005_modes_and_accessors() {
    assert_eq!(Gate::builder().build().mode(), Mode::Open);
    assert_eq!(GateBuilder::new().build().mode(), Mode::Open);
    assert_eq!(Gate::builder().closed().build().mode(), Mode::Closed);
    let gate = Gate::builder()
        .check(scripted("a", &[]))
        .require_all(["zeta", "a", "beta"])
        .build();
    assert_eq!(gate.mode(), Mode::Closed);
    assert_eq!(gate.required_ids(), vec!["a", "beta", "zeta"]);
    assert_eq!(gate.unregistered_required(), vec!["beta", "zeta"]);
    assert!(Gate::builder().build().required_ids().is_empty());
}

/// Counts its evaluations; answers `answer` for every action.
struct Counting {
    id: &'static str,
    answer: Option<Outcome>,
    calls: Arc<AtomicUsize>,
}

impl Check for Counting {
    fn id(&self) -> &str {
        self.id
    }
    fn evaluate(&self, _ctx: &ActionContext) -> Option<Decision> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.answer.map(|o| match o {
            Outcome::Allow => Decision::allow(),
            Outcome::Deny => Decision::deny("test:deny", vec![self.id.into()]),
            Outcome::Degrade => Decision::degrade("test:degrade", vec![self.id.into()]),
        })
    }
}

fn counting(id: &'static str, answer: Option<Outcome>) -> (Counting, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    (
        Counting {
            id,
            answer,
            calls: Arc::clone(&calls),
        },
        calls,
    )
}

/// FR-006: an unregistered requirement denies before any check runs, and a
/// deny ends `evaluate` while `evaluate_exhaustive` runs every check.
#[test]
fn fr006_what_runs() {
    let (a, a_calls) = counting("a", Some(Outcome::Allow));
    let gate = Gate::builder().check(a).require("missing").build();
    let d = gate.evaluate(&ActionContext::new("x"));
    assert_eq!(d.reason, closed::REQUIRED_UNREGISTERED);
    assert_eq!(d.check_ids, vec!["missing"]);
    assert!(d.blocking);
    let _ = gate.evaluate_exhaustive(&ActionContext::new("x"));
    assert_eq!(a_calls.load(Ordering::SeqCst), 0, "no check ran");

    let (scan, _) = counting("scan", None);
    let (after, after_calls) = counting("after", Some(Outcome::Deny));
    let gate = Gate::builder()
        .check(scan)
        .check(after)
        .require("scan")
        .build();
    let d = gate.evaluate(&ActionContext::new("x"));
    assert_eq!(d.reason, closed::REQUIRED_UNDECIDED);
    assert_eq!(d.check_ids, vec!["scan"]);
    assert!(d.blocking);
    assert_eq!(
        after_calls.load(Ordering::SeqCst),
        0,
        "a deny ends evaluate"
    );
    let e = gate.evaluate_exhaustive(&ActionContext::new("x"));
    assert_eq!(after_calls.load(Ordering::SeqCst), 1, "exhaustive runs on");
    assert_eq!(e.decision, d);
    assert_eq!(e.denials.len(), 2);
    assert_eq!(e.denials[1].check_ids, vec!["after"]);
}

/// FR-007: a degrade does not end a closed evaluation, so a deny after it
/// still decides (the order hazard aicortex 013 B-7 guards by hand); with no
/// deny the first degrade wins over any allow; a required check that degrades
/// has decided.
#[test]
fn fr007_degrade_is_held() {
    let (origin, _) = counting("origin", Some(Outcome::Degrade));
    let (secrets, secrets_calls) = counting("secrets", Some(Outcome::Deny));
    let gate = Gate::builder()
        .check(origin)
        .check(secrets)
        .require_all(["origin", "secrets"])
        .build();
    let d = gate.evaluate(&ActionContext::new("x"));
    assert_eq!(d.outcome, Outcome::Deny);
    assert_eq!(d.check_ids, vec!["secrets"]);
    assert_eq!(secrets_calls.load(Ordering::SeqCst), 1);

    let (origin, _) = counting("origin", Some(Outcome::Degrade));
    let (other, _) = counting("other", Some(Outcome::Degrade));
    let (ok, _) = counting("ok", Some(Outcome::Allow));
    let gate = Gate::builder()
        .check(ok)
        .check(origin)
        .check(other)
        .require("origin")
        .build();
    let d = gate.evaluate(&ActionContext::new("x"));
    assert_eq!(d.outcome, Outcome::Degrade);
    assert_eq!(d.check_ids, vec!["origin"], "the first degrade");
    assert!(
        gate.evaluate_exhaustive(&ActionContext::new("x"))
            .denials
            .is_empty()
    );
}

/// FR-008: a check's own decision is returned unchanged, and the gate's own
/// allow names the checks that allowed.
#[test]
fn fr008_reasons() {
    let gate = Gate::builder()
        .check(scripted("a", &[("x", "allow"), ("y", "allow")]))
        .check(scripted("b", &[("x", "deny")]))
        .check(scripted("c", &[("y", "allow")]))
        .closed()
        .build();
    let d = gate.evaluate(&ActionContext::new("x"));
    assert_eq!(d, Decision::deny("test:deny:b", vec!["b".into()]));
    assert!(!d.blocking, "the check's own decision, not rewritten");
    let d = gate.evaluate(&ActionContext::new("y"));
    assert_eq!(d.outcome, Outcome::Allow);
    assert_eq!(d.reason, closed::AFFIRMED);
    assert_eq!(d.check_ids, vec!["a", "c"]);
    assert!(!d.blocking);
    let d = gate.evaluate(&ActionContext::new("z"));
    assert_eq!(d.reason, closed::NO_CHECK_DECIDED);
    assert_eq!(d.check_ids, vec!["a", "b", "c"]);
    assert!(d.blocking);
    for code in [
        closed::NO_CHECK_DECIDED,
        closed::REQUIRED_UNREGISTERED,
        closed::REQUIRED_UNDECIDED,
        closed::AFFIRMED,
    ] {
        let parts: Vec<&str> = code.split(':').collect();
        assert_eq!(parts.len(), 4, "{code}");
        assert_eq!(parts[0], "gate");
        assert_eq!(parts[2], "closed");
    }
}

// FR-009: properties over arbitrary scripted gates, against a model.

#[derive(Clone, Copy, Debug)]
enum A {
    None,
    Allow,
    Deny,
    Degrade,
}

fn answer() -> impl Strategy<Value = A> {
    prop_oneof![
        Just(A::None),
        Just(A::Allow),
        Just(A::Deny),
        Just(A::Degrade)
    ]
}

struct Fixed {
    id: String,
    answer: A,
}

impl Check for Fixed {
    fn id(&self) -> &str {
        &self.id
    }
    fn evaluate(&self, _ctx: &ActionContext) -> Option<Decision> {
        match self.answer {
            A::None => None,
            A::Allow => Some(Decision::allow()),
            A::Deny => Some(Decision::deny("p:deny", vec![self.id.clone()])),
            A::Degrade => Some(Decision::degrade("p:degrade", vec![self.id.clone()])),
        }
    }
}

proptest! {
    #[test]
    fn fr009_closed_mode_matches_the_model(
        answers in prop::collection::vec(answer(), 0..8),
        required in prop::collection::btree_set(0usize..10, 0..4),
        closed_mode in any::<bool>(),
    ) {
        let ids: Vec<String> = (0..answers.len()).map(|i| format!("c{i}")).collect();
        let mut b = Gate::builder();
        for (id, a) in ids.iter().zip(&answers) {
            b = b.check(Fixed { id: id.clone(), answer: *a });
        }
        if closed_mode {
            b = b.closed();
        }
        let required: Vec<String> = required.iter().map(|i| format!("c{i}")).collect();
        let gate = b.require_all(required.clone()).build();
        let ctx = ActionContext::new("any");
        let d = gate.evaluate(&ctx);
        let e = gate.evaluate_exhaustive(&ctx);
        prop_assert_eq!(&e.decision, &d);

        if gate.mode() == Mode::Open {
            // The 0.2.0 rule.
            let first = answers.iter().position(|a| !matches!(a, A::None));
            match first {
                None => prop_assert_eq!(&d, &Decision::allow()),
                Some(i) => prop_assert_eq!(Some(d.clone()), Fixed { id: ids[i].clone(), answer: answers[i] }.evaluate(&ctx)),
            }
            return Ok(());
        }

        // Closed: deny exactly when denials is non-empty, and then its first.
        prop_assert_eq!(d.outcome == Outcome::Deny, !e.denials.is_empty());
        if let Some(first) = e.denials.first() {
            prop_assert_eq!(first, &d);
        }
        let missing: Vec<&String> = required.iter().filter(|r| !ids.contains(r)).collect();
        let is_required = |i: usize| required.contains(&ids[i]);
        let some_deny = answers
            .iter()
            .enumerate()
            .any(|(i, a)| matches!(a, A::Deny) || (matches!(a, A::None) && is_required(i)));
        let expected = if !missing.is_empty() || some_deny {
            Outcome::Deny
        } else if answers.iter().any(|a| matches!(a, A::Degrade)) {
            Outcome::Degrade
        } else if answers.iter().any(|a| matches!(a, A::Allow)) {
            Outcome::Allow
        } else {
            Outcome::Deny
        };
        prop_assert_eq!(d.outcome, expected);
        // A closed gate never allows without some check allowing.
        if d.is_allow() {
            prop_assert!(answers.iter().any(|a| matches!(a, A::Allow)));
        }
        // Every gate-made deny is blocking and carries a closed reason.
        for den in &e.denials {
            if den.reason.starts_with("gate:") {
                prop_assert!(den.blocking);
                prop_assert!(den.reason.starts_with("gate:deny:closed:"));
            }
        }
    }
}
