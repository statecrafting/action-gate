//! Spec 001 golden vectors: FR-001, FR-002, FR-005, FR-006.

use std::collections::BTreeSet;

use action_gate_core::secrets::{self, SecretRules, SecretScanCheck};
use action_gate_core::{ActionContext, Check, decision_to_canonical_json};
use serde_json::Value;

const VECTORS: &str = include_str!("../testdata/secret-vectors.json");

struct Vector {
    id: String,
    text: String,
    detector: Option<String>,
    offset: Option<usize>,
    secret: Option<String>,
}

fn vectors() -> Vec<Vector> {
    let doc: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    doc["vectors"]
        .as_array()
        .expect("a vectors array")
        .iter()
        .map(|v| Vector {
            id: v["id"].as_str().expect("an id").to_owned(),
            text: v["text"].as_str().expect("a text").to_owned(),
            detector: v["detector"].as_str().map(str::to_owned),
            offset: v["offset"]
                .as_u64()
                .map(|o| usize::try_from(o).expect("offset fits")),
            secret: v["secret"].as_str().map(str::to_owned),
        })
        .collect()
}

#[test]
fn fr001_every_vector_yields_its_detector_and_offset() {
    let rules = SecretRules::default();
    let mut failures = Vec::new();
    for v in vectors() {
        let got =
            secrets::scan(&v.text, &rules).map(|f| (f.detector.as_str().to_owned(), f.offset));
        let want = v.detector.clone().zip(v.offset);
        if got != want {
            failures.push(format!("{}: want {want:?}, got {got:?}", v.id));
        }
    }
    assert!(
        failures.is_empty(),
        "vector mismatches:\n{}",
        failures.join("\n")
    );
}

#[test]
fn vector_ids_are_unique_and_every_detector_has_a_positive_vector() {
    let all = vectors();
    let ids: BTreeSet<&str> = all.iter().map(|v| v.id.as_str()).collect();
    assert_eq!(ids.len(), all.len(), "duplicate vector id");

    let covered: BTreeSet<&str> = all.iter().filter_map(|v| v.detector.as_deref()).collect();
    for id in secrets::detector_ids() {
        assert!(covered.contains(id.as_str()), "no positive vector for {id}");
    }
    for v in &all {
        assert_eq!(
            v.detector.is_some(),
            v.secret.is_some(),
            "{}: secret iff positive",
            v.id
        );
    }
}

#[test]
fn fr002_no_decision_surface_carries_the_secret() {
    let check = SecretScanCheck::default();
    let mut checked = 0usize;
    for v in vectors() {
        let Some(secret) = &v.secret else { continue };
        for ctx in [
            ActionContext::new("write").with_summary(v.text.clone()),
            ActionContext::new("write").with_body(v.text.clone()),
        ] {
            let decision = check
                .evaluate(&ctx)
                .unwrap_or_else(|| panic!("{}: not denied", v.id));
            let finding = secrets::scan(&v.text, check.rules()).expect("a finding");
            let surfaces = [
                decision.reason.clone(),
                format!("{decision:?}"),
                decision_to_canonical_json(&decision),
                format!("{finding:?}"),
                serde_json::to_string(&finding).expect("finding serializes"),
            ];
            for surface in &surfaces {
                for window in secret.as_bytes().windows(8) {
                    let fragment = std::str::from_utf8(window).expect("ascii secrets");
                    assert!(
                        !surface.contains(fragment),
                        "{}: surface carries {fragment:?}: {surface}",
                        v.id
                    );
                }
            }
        }
        checked += 1;
    }
    assert!(checked >= 35, "only {checked} positive vectors");
}

#[test]
fn fr005_no_benign_vector_is_a_finding() {
    let negatives: Vec<Vector> = vectors()
        .into_iter()
        .filter(|v| v.detector.is_none())
        .collect();
    assert!(
        negatives.len() >= 20,
        "only {} negative vectors",
        negatives.len()
    );
    for v in &negatives {
        assert!(
            secrets::scan(&v.text, &SecretRules::default()).is_none(),
            "{}: benign text was a finding",
            v.id
        );
    }
}

#[test]
fn golden_vectors_scan_the_exact_text_deterministically() {
    let rules = SecretRules::default();
    for v in vectors() {
        assert_eq!(
            secrets::scan(&v.text, &rules),
            secrets::scan(&v.text, &rules),
            "{}",
            v.id
        );
    }
}

#[cfg(feature = "golden-vectors")]
#[test]
fn shipped_vectors_are_the_tested_vectors() {
    assert_eq!(secrets::GOLDEN_VECTORS, VECTORS);
}

/// FR-006: the 0.1.0 check is unchanged byte for byte, so a recorded
/// `Gate::config_hash` over it does not move.
#[cfg(feature = "checks-common")]
#[test]
fn fr006_secrets_check_fingerprint_is_the_0_1_0_value() {
    use action_gate_core::checks::SecretsCheck;
    assert_eq!(
        SecretsCheck::default().config_fingerprint(),
        concat!(
            r#"secrets:[(?i)(api[_-]?key|secret|token)\s*[:=]\s*['"]?[a-zA-Z0-9_\-]{24,},"#,
            r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----,",
            r"(?i)sk-[a-zA-Z0-9]{20,}]"
        )
    );
    let ctx = ActionContext::new("write").with_summary("sk-123456789012345678901234567890");
    assert_eq!(
        SecretsCheck::default()
            .evaluate(&ctx)
            .expect("matched")
            .reason,
        "gate:deny:secrets:pattern_match"
    );
}
