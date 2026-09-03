//! Secret Detector — SDD §4.3.
//!
//! Runs *before* identity extraction. Secrets are redacted one-way and are
//! never restored: round-tripping a live credential back into AI-generated code
//! would be both meaningless and dangerous (Design Review A2).
//!
//! This is a different operation from pseudonymization and shares no code path
//! with it. Secrets are never written to the vault as plaintext — only a salted
//! hash, for idempotency across rescans.

use std::sync::LazyLock;

use regex::Regex;

use crate::edit::Edit;

/// Marker substituted for a detected secret. Deliberately not alias-shaped, so
/// the restore engine can never resolve it.
pub const REDACTION_PREFIX: &str = "<<REDACTED:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// Blocks export until acknowledged (SDD §8 step 3).
    High,
    /// Surfaced for review; does not block.
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub secret_type: &'static str,
    pub confidence: Confidence,
    pub byte_start: usize,
    pub byte_end: usize,
    pub line: usize,
}

impl Finding {
    /// The marker this finding is replaced with.
    pub fn marker(&self) -> String {
        format!("{REDACTION_PREFIX}{}>>", self.secret_type)
    }
}

struct Rule {
    secret_type: &'static str,
    pattern: Regex,
    confidence: Confidence,
}

fn rule(secret_type: &'static str, pattern: &str, confidence: Confidence) -> Rule {
    Rule {
        secret_type,
        pattern: Regex::new(pattern).expect("built-in secret rule is a valid regex"),
        confidence,
    }
}

/// The rule pack. Patterns are anchored on word boundaries or literal prefixes
/// so a rule cannot fire on a fragment of a longer token.
///
/// Where a pattern has a capture group, the *group* is redacted rather than the
/// whole match, so `AWS_SECRET_ACCESS_KEY=` survives into the twin and the file
/// keeps the shape the model needs to see.
static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    use Confidence::{High, Low};
    vec![
        rule("aws_access_key_id", r"\b(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}\b", High),
        rule(
            "aws_secret_access_key",
            r#"(?i)aws_secret_access_key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})"#,
            High,
        ),
        rule("private_key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", High),
        rule(
            "jwt",
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
            High,
        ),
        rule(
            "connection_string",
            r"\b(?:postgres|postgresql|mysql|mongodb|redis|amqp)(?:\+\w+)?://[^\s:/@]+:[^\s@]+@\S+",
            High,
        ),
        rule("stripe_like_key", r"\b[sr]k_(?:test|live)_[A-Za-z0-9]{16,}\b", High),
        rule("webhook_secret", r"\bwhsec_[A-Za-z0-9]{16,}\b", High),
        rule("github_token", r"\bgh[pousr]_[A-Za-z0-9]{16,}\b", High),
        rule("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", High),
        rule("bearer_token", r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{20,}={0,2}", High),
        rule("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", Low),
    ]
});

/// Values that look like secrets but are placeholders. Redacting these is a
/// false positive that trains users to click through the block.
const PLACEHOLDERS: &[&str] = &[
    "your-api-key-here",
    "your_api_key_here",
    "changeme",
    "xxxxxxxx",
    "placeholder",
    "<your",
    "todo",
    "fixme",
];

/// Assignment keywords that make a high-entropy value much more likely to be a
/// credential than an ordinary identifier. Drives the entropy pass, which
/// catches credentials no rule anticipated.
static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        // No leading word boundary: the keyword is routinely a *suffix* of the
        // name, as in `internal_token` or `PAYLANE_WEBHOOK_SECRET`. Requiring
        // `\b` there would miss most real assignments.
        r#"(?i)(?:secret|token|password|passwd|pwd|api_?key|access_?key|auth|credential)\w*\s*[=:]\s*['"]?([A-Za-z0-9+/_=-]{20,})['"]?"#,
    )
    .expect("valid regex")
});

/// Minimum Shannon entropy, in bits per character, for a value to be treated as
/// a credential rather than a name. Prose and identifiers sit around 3.5–4.2;
/// random base64 sits above 4.8.
const ENTROPY_THRESHOLD: f64 = 4.5;

/// Scan for secrets — SDD §4.3.
///
/// Returns findings sorted by position, with overlaps resolved in favour of the
/// higher-confidence, longer match.
pub fn scan(text: &str) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();

    for rule in RULES.iter() {
        for caps in rule.pattern.captures_iter(text) {
            let span = caps.get(1).or_else(|| caps.get(0)).expect("group 0 always matches");
            if is_placeholder(span.as_str()) {
                continue;
            }
            findings.push(Finding {
                secret_type: rule.secret_type,
                confidence: rule.confidence,
                byte_start: span.start(),
                byte_end: span.end(),
                line: line_of(text, span.start()),
            });
        }
    }

    for caps in ASSIGNMENT.captures_iter(text) {
        let Some(value) = caps.get(1) else { continue };
        if is_placeholder(value.as_str()) || shannon_entropy(value.as_str()) < ENTROPY_THRESHOLD {
            continue;
        }
        findings.push(Finding {
            secret_type: "high_entropy_assignment",
            confidence: Confidence::High,
            byte_start: value.start(),
            byte_end: value.end(),
            line: line_of(text, value.start()),
        });
    }

    dedupe_overlaps(findings)
}

/// Replace every finding with its marker. One-way: no mapping is recorded that
/// could reverse it.
pub fn redact(text: &str, findings: &[Finding]) -> String {
    let mut edits: Vec<Edit> = findings
        .iter()
        .map(|f| Edit::new(f.byte_start, f.byte_end, f.marker(), None))
        .collect();
    crate::edit::apply(text, &mut edits).unwrap_or_else(|_| text.to_owned())
}

/// Translate an offset in redacted text back into the original source.
///
/// Everything downstream of [`redact`] works in the redacted text's
/// coordinates, and a marker is almost never the same length as the secret it
/// replaced — so past the first finding those coordinates drift. Silently, and
/// only in files that contained a secret, which is the worst way for an offset
/// to be wrong: it looks right everywhere it is tested.
///
/// It has been wrong in three places. `sanitize` reported alias positions that
/// sliced a string existing nowhere on disk; `specshield scan` printed them;
/// and the corpus grader scored against them, counting a correct detection as
/// both a miss and a false positive whenever a fixture put a name after a
/// secret. Anything that reads an offset out of the redacted text and shows it
/// to a person, or compares it with the original, must come through here.
///
/// `findings` must be sorted by `byte_start` and non-overlapping, which is what
/// [`scan`] returns.
#[must_use]
pub fn source_offset(findings: &[Finding], offset: usize) -> usize {
    let (mut source, mut redacted) = (0usize, 0usize);

    for finding in findings {
        // Text before this marker was copied through unchanged.
        let gap = finding.byte_start.saturating_sub(source);
        if offset < redacted + gap {
            return offset - redacted + source;
        }
        source = finding.byte_end;
        redacted += gap + finding.marker().len();
        if offset < redacted {
            // Inside a marker. Nothing in the source corresponds to a position
            // *within* it, so the secret's own start is the honest answer.
            return finding.byte_start;
        }
    }
    offset - redacted + source
}

/// Does this scan contain anything that must block export? — SDD §8 step 3.
pub fn blocks_export(findings: &[Finding]) -> bool {
    findings.iter().any(|f| f.confidence == Confidence::High)
}

fn is_placeholder(value: &str) -> bool {
    let lower = value.to_lowercase();
    PLACEHOLDERS.iter().any(|p| lower.contains(p))
}

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    #[allow(clippy::cast_precision_loss)]
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            #[allow(clippy::cast_precision_loss)]
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Keep the strongest finding per region: higher confidence first, then longer.
fn dedupe_overlaps(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| {
        a.byte_start
            .cmp(&b.byte_start)
            .then(a.confidence.cmp(&b.confidence))
            .then((b.byte_end - b.byte_start).cmp(&(a.byte_end - a.byte_start)))
    });

    let mut kept: Vec<Finding> = Vec::new();
    for finding in findings {
        if kept.last().is_some_and(|last| finding.byte_start < last.byte_end) {
            continue;
        }
        kept.push(finding);
    }
    kept
}

fn line_of(text: &str, byte: usize) -> usize {
    text[..byte].matches('\n').count() + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The corpus fixture. Every value is a published documentation example.
    const PLANTED: &str = concat!(
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        "DATABASE_URL=postgres://billing_app:hunter2@db.example.test:5432/billing\n",
        "PAYLANE_WEBHOOK_SECRET=whsec_000000000000000000000000000000000000\n",
        "SUPPORT_EMAIL=billing-ops@example.test\n"
    );

    fn types(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.secret_type).collect()
    }

    #[test]
    fn finds_every_planted_secret_class() {
        let found = scan(PLANTED);
        for expected in [
            "aws_access_key_id",
            "aws_secret_access_key",
            "connection_string",
            "webhook_secret",
            "email",
        ] {
            assert!(
                types(&found).contains(&expected),
                "missed {expected}: {:?}",
                types(&found)
            );
        }
    }

    #[test]
    fn api_key_beside_a_dto_is_found() {
        let src = r#"const PAYLANE_KEY = "sk_test_00000000000000000000000000000000";"#;
        assert!(
            types(&scan(src)).contains(&"stripe_like_key"),
            "{:?}",
            types(&scan(src))
        );
    }

    #[test]
    fn redaction_is_one_way_and_leaves_no_mapping() {
        let src = r#"api_key = "sk_live_abcdefghijklmnopqrstuvwx""#;
        let redacted = redact(src, &scan(src));
        assert!(redacted.contains(REDACTION_PREFIX), "{redacted}");
        assert!(!redacted.contains("sk_live_abcdefghijklmnopqrstuvwx"));
    }

    #[test]
    fn the_assignment_keyword_survives_redaction() {
        // Redacting `AWS_SECRET_ACCESS_KEY=...` down to a bare marker would
        // destroy the shape of the file the model needs to see.
        let redacted = redact(PLANTED, &scan(PLANTED));
        assert!(redacted.contains("AWS_SECRET_ACCESS_KEY=<<REDACTED:"), "{redacted}");
    }

    #[test]
    fn high_confidence_findings_block_export() {
        assert!(blocks_export(&scan(PLANTED)));
        assert!(
            !blocks_export(&scan("contact billing-ops@vantor.test")),
            "an email alone is low confidence"
        );
    }

    #[test]
    fn placeholders_are_not_redacted() {
        for benign in [
            r#"api_key = "your-api-key-here""#,
            r#"password = "changeme""#,
            r#"token = "xxxxxxxxxxxxxxxxxxxxxxxx""#,
        ] {
            assert!(
                scan(benign).is_empty(),
                "false positive on {benign}: {:?}",
                types(&scan(benign))
            );
        }
    }

    #[test]
    fn ordinary_code_produces_no_findings() {
        let src = concat!(
            "const MAX_RETRIES = 5;\n",
            "export class CustomerSubscriptionService {\n",
            "  async create(dto: CreateSubscriptionDto): Promise<void> {}\n",
            "}\n"
        );
        assert!(scan(src).is_empty(), "got {:?}", types(&scan(src)));
    }

    #[test]
    fn prose_and_identifiers_stay_below_the_entropy_threshold() {
        assert!(shannon_entropy("CustomerSubscriptionService") < ENTROPY_THRESHOLD);
        assert!(shannon_entropy("the quick brown fox jumps over the lazy dog") < ENTROPY_THRESHOLD);
    }

    #[test]
    fn entropy_catches_an_unanticipated_credential() {
        let src = r#"internal_token = "Kj8vQm2xPz9wRt5nLb3cYd7hFg4sAe6uZi1oXk0p""#;
        let found = scan(src);
        assert!(!found.is_empty(), "entropy pass should catch this");
        assert!(blocks_export(&found));
    }

    #[test]
    fn findings_never_overlap() {
        let found = scan(PLANTED);
        for pair in found.windows(2) {
            assert!(pair[0].byte_end <= pair[1].byte_start, "overlapping findings");
        }
    }

    #[test]
    fn redacted_output_survives_a_restore_pass_unchanged() {
        use crate::restore::{Vocabulary, restore};
        let redacted = redact(PLANTED, &scan(PLANTED));
        let out = restore(&redacted, &Vocabulary::new([("SERVICE_H7K2Q3", "Real")]));
        assert_eq!(out.text, redacted, "redaction markers must never be restored");
    }
}
