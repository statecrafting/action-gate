// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Bartek Kus
//
// The detector tables, token scan and entropy arithmetic are carried from
// aicortex (crates/aicortex-gate/src/rules.rs and secrets.rs, commit a927f85,
// aicortex spec 013), Apache-2.0, same copyright holder. See spec 001.

//! The secret detector registry (spec 001).
//!
//! A pure, regex-free scan that answers *which* detector fired and *where*,
//! never *what*: a [`Finding`] is a [`DetectorId`] and a byte offset, and
//! nothing that reports one carries any part of the matched value (B-9).
//!
//! The prefix and armour detectors are data ([`PREFIX_RULES`],
//! [`PEM_RULES`]): adding a credential shape is a table row and a golden
//! vector, not a code path. The URL, JWT, entropy and assignment detectors are
//! named constants with fixed logic.
//!
//! ```
//! use action_gate_core::secrets::{self, SecretRules};
//!
//! let text = "the key is AKIA4QD7XZLM2VNBKTRW, rotate it";
//! let finding = secrets::scan(text, &SecretRules::default()).expect("a credential");
//! assert_eq!(finding.detector.as_str(), "aws-access-key-id");
//! assert_eq!(finding.offset, 11);
//! ```
//!
//! # What is scanned
//!
//! Exactly the text given: normalization (Unicode forms, bidirectional
//! controls) is the consumer's, and offsets index the text as passed. Armour
//! markers and the assignment rule read the whole text, because a PEM block
//! spans lines and an assignment spans whitespace. Everything else reads
//! *tokens*: maximal runs of characters that are neither whitespace nor one of
//! the delimiters prose puts around a pasted value (B-4).

use action_gate_types::{ActionContext, Check, Decision};

/// The stable name of a detector, as a finding reports it and a vector records
/// it (B-1). Once shipped, an id is never renamed or reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DetectorId(&'static str);

impl DetectorId {
    /// Name a detector.
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    /// The name, as it is reported and recorded.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl core::fmt::Display for DetectorId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

impl serde::Serialize for DetectorId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0)
    }
}

/// Which characters a credential's body is made of, so that a prefix match is
/// not a match on prose that happens to start with the same letters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Charset {
    /// `A-Z a-z 0-9`.
    Alphanumeric,
    /// `A-Z a-z 0-9 - _`, the base64url alphabet without padding.
    Base64Url,
    /// `A-Z a-z 0-9 + / = - _ .`, which is every token alphabet in use.
    Token,
}

impl Charset {
    /// Whether `character` belongs to this alphabet.
    #[must_use]
    pub const fn admits(self, character: char) -> bool {
        match self {
            Self::Alphanumeric => character.is_ascii_alphanumeric(),
            Self::Base64Url => {
                character.is_ascii_alphanumeric() || character == '-' || character == '_'
            }
            Self::Token => {
                character.is_ascii_alphanumeric()
                    || matches!(character, '+' | '/' | '=' | '-' | '_' | '.')
            }
        }
    }

    /// A stable name, used in [`SecretScanCheck`]'s config fingerprint.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Alphanumeric => "alphanumeric",
            Self::Base64Url => "base64url",
            Self::Token => "token",
        }
    }
}

/// A credential recognised by the way it starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrefixRule {
    /// What a finding names.
    pub detector: DetectorId,
    /// The literal the token begins with (case-sensitive).
    pub prefix: &'static str,
    /// How many characters of [`Self::charset`] must follow it. A prefix with
    /// no length requirement matches the word "sky" and every sentence that
    /// contains it.
    pub min_tail: usize,
    /// What those characters may be.
    pub charset: Charset,
}

/// A private key recognised by its armour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PemRule {
    /// What a finding names.
    pub detector: DetectorId,
    /// The armour line, matched as a substring anywhere in the text. A PEM
    /// header is unambiguous: no prose contains one by accident.
    pub marker: &'static str,
}

const fn prefix(
    detector: &'static str,
    prefix: &'static str,
    min_tail: usize,
    charset: Charset,
) -> PrefixRule {
    PrefixRule {
        detector: DetectorId::new(detector),
        prefix,
        min_tail,
        charset,
    }
}

const fn pem(detector: &'static str, marker: &'static str) -> PemRule {
    PemRule {
        detector: DetectorId::new(detector),
        marker,
    }
}

/// The token shapes published by the systems whose credentials people paste.
///
/// Each row is a prefix, a minimum body length, and the alphabet that body is
/// written in. The lengths are the published ones where a system publishes
/// them and a conservative floor where it does not; they lean low, because a
/// floor that is too high costs a leaked credential. Order matters where one
/// prefix extends another: `sk-ant-` precedes `sk-`.
pub const PREFIX_RULES: &[PrefixRule] = &[
    prefix("anthropic-api-key", "sk-ant-", 24, Charset::Base64Url),
    prefix("openai-api-key", "sk-", 20, Charset::Base64Url),
    prefix("stripe-secret-key", "sk_live_", 16, Charset::Alphanumeric),
    prefix(
        "stripe-restricted-key",
        "rk_live_",
        16,
        Charset::Alphanumeric,
    ),
    prefix("github-token", "ghp_", 36, Charset::Alphanumeric),
    prefix("github-oauth-token", "gho_", 36, Charset::Alphanumeric),
    prefix("github-user-token", "ghu_", 36, Charset::Alphanumeric),
    prefix("github-server-token", "ghs_", 36, Charset::Alphanumeric),
    prefix("github-refresh-token", "ghr_", 36, Charset::Alphanumeric),
    prefix(
        "github-fine-grained-token",
        "github_pat_",
        40,
        Charset::Base64Url,
    ),
    prefix("gitlab-personal-token", "glpat-", 20, Charset::Base64Url),
    prefix("slack-bot-token", "xoxb-", 24, Charset::Token),
    prefix("slack-user-token", "xoxp-", 24, Charset::Token),
    prefix("slack-app-token", "xapp-", 24, Charset::Token),
    prefix("aws-access-key-id", "AKIA", 16, Charset::Alphanumeric),
    prefix(
        "aws-temporary-access-key-id",
        "ASIA",
        16,
        Charset::Alphanumeric,
    ),
    prefix("google-api-key", "AIza", 35, Charset::Base64Url),
    prefix("google-oauth-token", "ya29.", 32, Charset::Token),
    prefix("npm-token", "npm_", 36, Charset::Alphanumeric),
    prefix("digitalocean-token", "dop_v1_", 60, Charset::Alphanumeric),
    prefix("sendgrid-api-key", "SG.", 32, Charset::Token),
    prefix("huggingface-token", "hf_", 32, Charset::Alphanumeric),
    prefix("shopify-access-token", "shpat_", 32, Charset::Alphanumeric),
    prefix("supabase-service-key", "sbp_", 36, Charset::Alphanumeric),
];

/// The armour lines of the private-key formats.
pub const PEM_RULES: &[PemRule] = &[
    pem("pem-private-key", "-----BEGIN PRIVATE KEY-----"),
    pem("pem-rsa-private-key", "-----BEGIN RSA PRIVATE KEY-----"),
    pem("pem-ec-private-key", "-----BEGIN EC PRIVATE KEY-----"),
    pem("pem-dsa-private-key", "-----BEGIN DSA PRIVATE KEY-----"),
    pem(
        "pem-encrypted-private-key",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    ),
    pem("openssh-private-key", "-----BEGIN OPENSSH PRIVATE KEY-----"),
    pem("pgp-private-key", "-----BEGIN PGP PRIVATE KEY BLOCK-----"),
];

/// The detector that reports a credential embedded in a URL's userinfo.
pub const URL_CREDENTIAL: DetectorId = DetectorId::new("url-embedded-credential");

/// The detector that reports a JSON Web Token.
pub const JWT: DetectorId = DetectorId::new("json-web-token");

/// The detector that reports an unbroken run of high entropy.
pub const HIGH_ENTROPY: DetectorId = DetectorId::new("high-entropy-token");

/// The detector that reports `api_key = <value>` style assignments (the rule
/// action-gate 0.1.0's `SecretsCheck` carried as a regex).
pub const CREDENTIAL_ASSIGNMENT: DetectorId = DetectorId::new("credential-assignment");

/// The key names the assignment rule recognises, matched ASCII
/// case-insensitively and without a word boundary, as 0.1.0's regex did.
const ASSIGNMENT_KEYS: [&str; 5] = ["api_key", "api-key", "apikey", "secret", "token"];

/// How many value characters an assignment needs to be a credential.
const ASSIGNMENT_MIN_VALUE: usize = 24;

/// How many fractional bits the entropy arithmetic carries.
///
/// Integer arithmetic in Q16 fixed point rather than floating point, so the
/// same text yields the same finding on every target without an argument
/// about rounding (B-8).
pub const ENTROPY_FRACTION_BITS: u32 = 16;

/// One whole bit, in the fixed point [`ENTROPY_FRACTION_BITS`] defines.
pub const ENTROPY_ONE: u64 = 1 << ENTROPY_FRACTION_BITS;

/// `whole.hundredths` bits per character, in Q16.
#[must_use]
pub const fn bits(whole: u64, hundredths: u64) -> u64 {
    whole * ENTROPY_ONE + (hundredths * ENTROPY_ONE) / 100
}

/// The threshold detector: a long unbroken run whose Shannon entropy is above
/// a configurable bound. All three fields are false-positive control.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntropyRule {
    /// The shortest run considered at all. Below this, entropy per character
    /// is noise.
    pub min_len: usize,
    /// Bits per character, in Q16, at or above which a run is a credential.
    pub threshold: u64,
    /// Whether a run must mix upper case, lower case and digits to be
    /// considered. A hex digest, a ULID and a UUID each fail this and so are
    /// never measured.
    pub require_mixed_case_and_digit: bool,
}

impl EntropyRule {
    /// The shipped threshold: 4.50 bits per character over at least 24
    /// characters. A 40-character hex digest measures at most 4.00 by
    /// construction; a random 32-byte secret in base64 measures about 5.50.
    pub const STANDARD: Self = Self {
        min_len: 24,
        threshold: bits(4, 50),
        require_mixed_case_and_digit: true,
    };
}

impl Default for EntropyRule {
    fn default() -> Self {
        Self::STANDARD
    }
}

/// Which detectors run, and how the threshold one is tuned (B-5).
///
/// `non_exhaustive` so a later detector toggle is not a breaking change: start
/// from [`SecretRules::default`] and narrow field by field.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SecretRules {
    /// The prefix table. Defaults to [`PREFIX_RULES`].
    pub prefixes: &'static [PrefixRule],
    /// The armour table. Defaults to [`PEM_RULES`].
    pub pem: &'static [PemRule],
    /// Whether a credential in a URL's userinfo is a finding.
    pub url_credentials: bool,
    /// Whether a JSON Web Token is a finding.
    pub json_web_tokens: bool,
    /// Whether an `api_key = <value>` style assignment is a finding.
    pub assignments: bool,
    /// The threshold detector, or `None` to run only the patterns.
    pub entropy: Option<EntropyRule>,
}

impl Default for SecretRules {
    fn default() -> Self {
        Self {
            prefixes: PREFIX_RULES,
            pem: PEM_RULES,
            url_credentials: true,
            json_web_tokens: true,
            assignments: true,
            entropy: Some(EntropyRule::STANDARD),
        }
    }
}

/// Every detector id the default rules can report, in table order (B-1).
#[must_use]
pub fn detector_ids() -> Vec<DetectorId> {
    PREFIX_RULES
        .iter()
        .map(|rule| rule.detector)
        .chain(PEM_RULES.iter().map(|rule| rule.detector))
        .chain([URL_CREDENTIAL, JWT, HIGH_ENTROPY, CREDENTIAL_ASSIGNMENT])
        .collect()
}

/// A detector's hit: which one, and where. Never the value (B-9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct Finding {
    /// The detector that fired.
    pub detector: DetectorId,
    /// The byte offset into the scanned text, on a character boundary (B-7).
    pub offset: usize,
}

/// The characters that end a token even though they are not whitespace.
const DELIMITERS: [char; 16] = [
    '"', '\'', '`', ',', ';', '(', ')', '[', ']', '{', '}', '<', '>', '|', '\\', '\u{feff}',
];

fn is_boundary(character: char) -> bool {
    character.is_whitespace() || DELIMITERS.contains(&character)
}

/// The tokens of `text`, each with its byte offset.
fn tokens(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut offset = 0usize;
    core::iter::from_fn(move || {
        let rest = text.get(offset..)?;
        let start = offset + rest.find(|c: char| !is_boundary(c))?;
        let tail = text.get(start..)?;
        let len = tail.find(is_boundary).unwrap_or(tail.len());
        offset = start + len;
        tail.get(..len).map(|token| (start, token))
    })
}

/// The first detector to fire on `text`, or `None` when nothing does (B-6).
///
/// The finding with the smallest offset wins; at equal offsets an armour
/// marker beats a token detector, which beats the assignment rule.
#[must_use]
pub fn scan(text: &str, rules: &SecretRules) -> Option<Finding> {
    let armour = rules
        .pem
        .iter()
        .filter_map(|rule| {
            text.find(rule.marker).map(|offset| Finding {
                detector: rule.detector,
                offset,
            })
        })
        .min_by_key(|finding| finding.offset);

    let token = tokens(text).find_map(|(offset, token)| {
        prefix_match(token, rules.prefixes)
            .or_else(|| {
                rules
                    .url_credentials
                    .then(|| url_credential(token))
                    .flatten()
            })
            .or_else(|| {
                rules
                    .json_web_tokens
                    .then(|| json_web_token(token))
                    .flatten()
            })
            .map(|detector| (detector, 0usize))
            .or_else(|| rules.entropy.and_then(|rule| high_entropy(token, &rule)))
            .map(|(detector, within)| Finding {
                detector,
                offset: offset.saturating_add(within),
            })
    });

    let assignment = rules
        .assignments
        .then(|| assignment(text))
        .flatten()
        .map(|offset| Finding {
            detector: CREDENTIAL_ASSIGNMENT,
            offset,
        });

    // `min_by_key` keeps the first of equal minima, which is the precedence.
    [armour, token, assignment]
        .into_iter()
        .flatten()
        .min_by_key(|finding| finding.offset)
}

/// The prefix rule `token` satisfies, if any.
fn prefix_match(token: &str, rules: &[PrefixRule]) -> Option<DetectorId> {
    rules.iter().find_map(|rule| {
        let tail = token.strip_prefix(rule.prefix)?;
        let body: usize = tail.chars().take_while(|c| rule.charset.admits(*c)).count();
        (body >= rule.min_tail).then_some(rule.detector)
    })
}

/// Whether `token` is a URL whose userinfo carries a password:
/// `scheme://user:secret@host`, with a non-empty password and host.
fn url_credential(token: &str) -> Option<DetectorId> {
    let after_scheme = token.split_once("://")?.1;
    let authority = after_scheme.split('/').next()?;
    let (userinfo, host) = authority.rsplit_once('@')?;
    let (_, password) = userinfo.split_once(':')?;
    let credible = !password.is_empty() && !host.is_empty() && !password.contains('@');
    credible.then_some(URL_CREDENTIAL)
}

/// Whether `token` is a JSON Web Token: three base64url segments whose first
/// decodes to a JSON object naming an algorithm or a type. The header decode
/// is what separates a JWT from a dotted identifier.
fn json_web_token(token: &str) -> Option<DetectorId> {
    let mut parts = token.split('.');
    let header = parts.next()?;
    let payload = parts.next()?;
    let signature = parts.next()?;
    if parts.next().is_some() || header.is_empty() || payload.is_empty() {
        return None;
    }
    let base64url =
        |part: &str| !part.is_empty() && part.chars().all(|c| Charset::Base64Url.admits(c));
    if !base64url(header) || !base64url(payload) || (!signature.is_empty() && !base64url(signature))
    {
        return None;
    }
    let decoded = base64url_decode(header)?;
    let text = String::from_utf8(decoded).ok()?;
    let object: serde_json::Value = serde_json::from_str(&text).ok()?;
    let names_a_header = object
        .as_object()
        .is_some_and(|map| map.contains_key("alg") || map.contains_key("typ"));
    names_a_header.then_some(JWT)
}

/// Decode unpadded base64url, or `None` when `part` is not base64url.
fn base64url_decode(part: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(part.len() * 3 / 4);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for character in part.chars() {
        let value = match character {
            'A'..='Z' => u32::from(character as u8 - b'A'),
            'a'..='z' => u32::from(character as u8 - b'a') + 26,
            '0'..='9' => u32::from(character as u8 - b'0') + 52,
            '-' => 62,
            '_' => 63,
            _ => return None,
        };
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let byte = u8::try_from((accumulator >> bits) & 0xff).ok()?;
            out.push(byte);
        }
    }
    Some(out)
}

/// The first high-entropy run inside `token`, and where it starts.
///
/// A *run* of token-alphabet characters rather than the whole token, so that
/// punctuation glued onto a secret (`label:<secret>`, `token~<secret>`) cannot
/// hide it (aicortex 013 D-12).
fn high_entropy(token: &str, rule: &EntropyRule) -> Option<(DetectorId, usize)> {
    let mut start = 0usize;
    for run in token.split(|c: char| !Charset::Token.admits(c)) {
        if is_high_entropy(run, rule) {
            return Some((HIGH_ENTROPY, start));
        }
        // Past this run, then past the (possibly multi-byte) separator.
        let after_run = start.saturating_add(run.len());
        start = token
            .get(after_run..)
            .and_then(|rest| rest.chars().next())
            .map_or(after_run, |sep| after_run.saturating_add(sep.len_utf8()));
    }
    None
}

fn is_high_entropy(run: &str, rule: &EntropyRule) -> bool {
    if run.len() < rule.min_len {
        return false;
    }
    if rule.require_mixed_case_and_digit {
        let mixed = run.chars().any(|c| c.is_ascii_uppercase())
            && run.chars().any(|c| c.is_ascii_lowercase())
            && run.chars().any(|c| c.is_ascii_digit());
        if !mixed {
            return false;
        }
    }
    shannon_bits(run) >= rule.threshold
}

/// The Shannon entropy of `token` in bits per character, in Q16 fixed point.
///
/// `H = log2(n) - (1/n) * sum(c_i * log2(c_i))`, written so that only one
/// division is needed and every term is a non-negative integer.
#[must_use]
pub fn shannon_bits(token: &str) -> u64 {
    let mut counts = [0u32; 256];
    let mut total: u64 = 0;
    for byte in token.bytes() {
        if let Some(slot) = counts.get_mut(usize::from(byte)) {
            *slot = slot.saturating_add(1);
            total = total.saturating_add(1);
        }
    }
    if total < 2 {
        return 0;
    }
    let weighted: u64 = counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| u64::from(*count).saturating_mul(log2_q16(u64::from(*count))))
        .sum();
    log2_q16(total).saturating_sub(weighted / total)
}

/// `log2(x)` in Q16 fixed point, for `x >= 1`, by repeated squaring of the
/// mantissa.
fn log2_q16(x: u64) -> u64 {
    if x == 0 {
        return 0;
    }
    let integer = u64::from(63 - x.leading_zeros());
    let mut mantissa: u128 = if integer >= 32 {
        u128::from(x) >> (integer - 32)
    } else {
        u128::from(x) << (32 - integer)
    };
    let mut fraction: u64 = 0;
    for bit in 0..ENTROPY_FRACTION_BITS {
        mantissa = (mantissa * mantissa) >> 32;
        if mantissa >= (2u128 << 32) {
            fraction |= 1 << (ENTROPY_FRACTION_BITS - 1 - bit);
            mantissa >>= 1;
        }
    }
    (integer << ENTROPY_FRACTION_BITS) | fraction
}

/// The offset of the first assigned value, if any: a key from
/// [`ASSIGNMENT_KEYS`], optional whitespace, `:` or `=`, optional whitespace,
/// an optional quote, then [`ASSIGNMENT_MIN_VALUE`] or more of
/// `A-Z a-z 0-9 _ -`.
fn assignment(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    (0..bytes.len()).find_map(|start| {
        ASSIGNMENT_KEYS.iter().find_map(|key| {
            let end = start.checked_add(key.len())?;
            // An ASCII-only match, so `start` and `end` are char boundaries.
            let candidate = bytes.get(start..end)?;
            if !candidate.eq_ignore_ascii_case(key.as_bytes()) {
                return None;
            }
            assigned_value(text, end)
        })
    })
}

fn assigned_value(text: &str, after_key: usize) -> Option<usize> {
    let rest = text.get(after_key..)?.trim_start();
    let rest = rest.strip_prefix([':', '='])?.trim_start();
    let value = rest.strip_prefix(['\'', '"']).unwrap_or(rest);
    let len = value
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        .count();
    (len >= ASSIGNMENT_MIN_VALUE).then(|| text.len() - value.len())
}

/// The golden vectors of spec 001 B-15, as JSON, for consumers asserting
/// parity by vector id (feature `golden-vectors`).
#[cfg(feature = "golden-vectors")]
pub const GOLDEN_VECTORS: &str = include_str!("../testdata/secret-vectors.json");

/// Denies when [`scan`] finds a credential in the payload, naming the detector,
/// the field and the offset, never the value (B-9, B-10).
///
/// Blocking: a secret in the payload must stop the action regardless of any
/// trust level. Needs no optional feature and no `regex`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecretScanCheck {
    rules: SecretRules,
}

impl SecretScanCheck {
    /// The check id, as it appears in a decision's `check_ids`.
    pub const ID: &'static str = "secret-scan";

    /// A scan check with custom rules.
    #[must_use]
    pub fn new(rules: SecretRules) -> Self {
        Self { rules }
    }

    /// The rules this check scans with.
    #[must_use]
    pub fn rules(&self) -> &SecretRules {
        &self.rules
    }
}

impl Check for SecretScanCheck {
    fn id(&self) -> &str {
        Self::ID
    }

    fn evaluate(&self, ctx: &ActionContext) -> Option<Decision> {
        let fields = [
            ("summary", Some(ctx.payload_summary.as_str())),
            ("body", ctx.payload_body.as_deref()),
        ];
        fields.into_iter().find_map(|(field, text)| {
            let finding = scan(text?, &self.rules)?;
            Some(
                Decision::deny(
                    format!(
                        "gate:deny:secrets:{}:{field}:{}",
                        finding.detector, finding.offset
                    ),
                    vec![Self::ID.into()],
                )
                .blocking(),
            )
        })
    }

    fn config_fingerprint(&self) -> String {
        let prefixes: Vec<String> = self
            .rules
            .prefixes
            .iter()
            .map(|r| {
                format!(
                    "{}|{}|{}|{}",
                    r.detector,
                    r.prefix,
                    r.min_tail,
                    r.charset.as_str()
                )
            })
            .collect();
        let pem: Vec<String> = self
            .rules
            .pem
            .iter()
            .map(|r| format!("{}|{}", r.detector, r.marker))
            .collect();
        let entropy = self.rules.entropy.map_or_else(
            || "none".to_owned(),
            |e| {
                format!(
                    "{}|{}|{}",
                    e.min_len, e.threshold, e.require_mixed_case_and_digit
                )
            },
        );
        format!(
            "{}:v1;prefix=[{}];pem=[{}];url={};jwt={};assignment={};entropy={}",
            Self::ID,
            prefixes.join(","),
            pem.join(","),
            self.rules.url_credentials,
            self.rules.json_web_tokens,
            self.rules.assignments,
            entropy
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(text: &str) -> Option<(&'static str, usize)> {
        scan(text, &SecretRules::default()).map(|f| (f.detector.as_str(), f.offset))
    }

    #[test]
    fn detector_ids_are_unique_and_complete() {
        let ids = detector_ids();
        let unique: std::collections::BTreeSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "duplicate detector id");
        assert_eq!(ids.len(), 24 + 7 + 4);
    }

    #[test]
    fn assignment_reports_the_value_offset() {
        let text = "config: api_key = 'abcdefghijklmnopqrstuvwxyz0123'";
        assert_eq!(detect(text), Some(("credential-assignment", 19)));
        assert_eq!(
            detect("TOKEN:abcdefghijklmnopqrstuvwxyz"),
            Some(("credential-assignment", 6))
        );
    }

    #[test]
    fn assignment_needs_a_long_value_and_an_operator() {
        assert_eq!(detect("the token is abcdefghijklmnopqrstuvwxyz"), None);
        assert_eq!(detect("secret = short"), None);
        assert_eq!(detect("api key = abcdefghijklmnopqrstuvwxyz"), None);
    }

    #[test]
    fn token_detector_wins_a_tie_with_assignment() {
        let text = "token = ghp_RyIdydJp2Ys2SJ2jXUBATskPzpR6QTFGlbDtQ57k";
        assert_eq!(detect(text), Some(("github-token", 8)));
    }

    #[test]
    fn armour_wins_a_tie_and_earliest_offset_wins() {
        let text = "x -----BEGIN PGP PRIVATE KEY BLOCK----- AKIA4QD7XZLM2VNBKTRW";
        assert_eq!(detect(text), Some(("pgp-private-key", 2)));
        let text = "AKIA4QD7XZLM2VNBKTRW -----BEGIN PRIVATE KEY-----";
        assert_eq!(detect(text), Some(("aws-access-key-id", 0)));
    }

    #[test]
    fn toggles_disable_their_detector() {
        let rules = SecretRules {
            assignments: false,
            entropy: None,
            ..SecretRules::default()
        };
        assert!(scan("secret=abcdefghijklmnopqrstuvwxyz", &rules).is_none());
    }

    #[test]
    fn shannon_bits_matches_known_values() {
        assert_eq!(shannon_bits(""), 0);
        assert_eq!(shannon_bits("aaaa"), 0);
        assert_eq!(shannon_bits("ab"), ENTROPY_ONE);
        assert_eq!(shannon_bits("abcd"), 2 * ENTROPY_ONE);
    }

    #[test]
    fn check_reason_names_detector_field_and_offset() {
        let check = SecretScanCheck::default();
        let ctx = ActionContext::new("write")
            .with_summary("clean")
            .with_body("key AKIA4QD7XZLM2VNBKTRW");
        let d = check.evaluate(&ctx).expect("secret in body");
        assert_eq!(d.reason, "gate:deny:secrets:aws-access-key-id:body:4");
        assert_eq!(d.check_ids, vec!["secret-scan"]);
        assert!(d.blocking);
        assert!(check.evaluate(&ActionContext::new("write")).is_none());
    }

    #[test]
    fn fingerprint_changes_with_the_rules() {
        let rules = SecretRules {
            json_web_tokens: false,
            ..SecretRules::default()
        };
        assert_ne!(
            SecretScanCheck::default().config_fingerprint(),
            SecretScanCheck::new(rules).config_fingerprint()
        );
    }
}
