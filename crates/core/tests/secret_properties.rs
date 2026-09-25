//! Spec 001 properties: FR-003 (offsets) and FR-004 (boundaries, reason
//! grammar, so no reason can carry input).

use action_gate_core::secrets::{self, PEM_RULES, PREFIX_RULES, SecretRules, SecretScanCheck};
use action_gate_core::{ActionContext, Check};
use proptest::prelude::*;

/// Lowercase words and single spaces: no digit, capital, operator or
/// delimiter, so the prose itself can never fire a detector.
fn prose() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[a-z]{1,8}( [a-z]{1,8}){0,8}").expect("valid regex")
}

/// A token satisfying one prefix rule. Tails are alphanumeric, the alphabet
/// every rule admits, so no tail can turn the token into an earlier rule's.
fn prefixed_credential() -> impl Strategy<Value = (usize, String)> {
    (0..PREFIX_RULES.len()).prop_flat_map(|index| {
        let rule = PREFIX_RULES[index];
        let tail = format!("[A-Za-z0-9]{{{},{}}}", rule.min_tail, rule.min_tail + 24);
        proptest::string::string_regex(&tail)
            .expect("valid regex")
            .prop_map(move |tail| (index, format!("{}{tail}", rule.prefix)))
    })
}

fn reason_is_well_formed(reason: &str, ctx: &ActionContext) -> bool {
    let Some(rest) = reason.strip_prefix("gate:deny:secrets:") else {
        return false;
    };
    let mut parts = rest.split(':');
    let (Some(id), Some(field), Some(offset), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let text = match field {
        "summary" => ctx.payload_summary.as_str(),
        "body" => ctx.payload_body.as_deref().unwrap_or_default(),
        _ => return false,
    };
    secrets::detector_ids().iter().any(|d| d.as_str() == id)
        && !offset.is_empty()
        && offset.bytes().all(|b| b.is_ascii_digit())
        && offset.parse::<usize>().is_ok_and(|o| o < text.len())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn fr003_prefixed_credential_is_found_at_its_offset(
        before in prose(),
        (index, credential) in prefixed_credential(),
        after in prose(),
    ) {
        let text = format!("{before} {credential} {after}");
        let finding = secrets::scan(&text, &SecretRules::default()).expect("a finding");
        prop_assert_eq!(finding.detector, PREFIX_RULES[index].detector);
        prop_assert_eq!(finding.offset, before.len() + 1);
    }

    #[test]
    fn fr003_armour_is_found_at_its_marker(
        before in prose(),
        index in 0..PEM_RULES.len(),
        body in "[A-Za-z0-9+/]{16,64}",
    ) {
        let rule = PEM_RULES[index];
        let text = format!("{before}\n{}\n{body}\n", rule.marker);
        let finding = secrets::scan(&text, &SecretRules::default()).expect("a finding");
        prop_assert_eq!(finding.detector, rule.detector);
        prop_assert_eq!(finding.offset, before.len() + 1);
    }

    #[test]
    fn fr003_assignment_is_found_at_its_value(
        before in prose(),
        // Lowercase keys: a capitalised key glued to its value by `=` makes
        // the whole run mixed-case, and the entropy detector then correctly
        // fires at the earlier key offset (B-6). Uppercase keys are covered by
        // the `assignment-secret-colon` vector.
        key in "(api_key|api-key|apikey|secret|token)",
        op in "( ?[:=] ?)",
        quote in "['\"]?",
        // A leading digit: no prefix rule starts with one, so no token
        // detector can tie with the assignment at the value offset.
        value in "[0-9][a-z0-9_-]{23,47}",
    ) {
        let lead = format!("{before} {key}{op}{quote}");
        let text = format!("{lead}{value}");
        let finding = secrets::scan(&text, &SecretRules::default()).expect("a finding");
        prop_assert_eq!(finding.detector, secrets::CREDENTIAL_ASSIGNMENT);
        prop_assert_eq!(finding.offset, lead.len());
    }

    #[test]
    fn fr004_offsets_are_char_boundaries_inside_the_text(
        text in "[ -~\n\t\u{e9}\u{2028}\u{feff}\u{1f511}]{0,160}",
    ) {
        if let Some(finding) = secrets::scan(&text, &SecretRules::default()) {
            prop_assert!(finding.offset < text.len());
            prop_assert!(text.is_char_boundary(finding.offset));
        }
    }

    #[test]
    fn fr004_arbitrary_text_offsets_are_char_boundaries(text in any::<String>()) {
        if let Some(finding) = secrets::scan(&text, &SecretRules::default()) {
            prop_assert!(finding.offset < text.len());
            prop_assert!(text.is_char_boundary(finding.offset));
        }
    }

    #[test]
    fn fr004_reason_follows_the_grammar(
        summary in "[ -~]{0,80}",
        (_, credential) in prefixed_credential(),
        body in prose(),
        embed in any::<bool>(),
    ) {
        let body = if embed { format!("{body} {credential}") } else { body };
        let ctx = ActionContext::new("write").with_summary(summary).with_body(body);
        if let Some(decision) = SecretScanCheck::default().evaluate(&ctx) {
            prop_assert!(reason_is_well_formed(&decision.reason, &ctx), "{}", decision.reason);
            prop_assert!(decision.blocking);
            prop_assert_eq!(decision.check_ids, vec!["secret-scan".to_owned()]);
        } else {
            prop_assert!(!embed, "an embedded credential was not denied");
        }
    }
}
