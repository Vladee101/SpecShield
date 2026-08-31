//! Export Verification Gate — SDD §8.
//!
//! Nothing leaves the machine without passing this. Detection recall is 0.95 by
//! target (PRD §5), and five percent of entities leaking is a *hundred* percent
//! leak of those entities — so the gate proves the twin is clean rather than
//! assuming detection was complete (Design Review A3).
//!
//! The check is deliberately dumb and independent of the extractor: build an
//! automaton over every real name the vault knows, expanded to case variants,
//! and scan the candidate output. A hit is a hard block.

use aho_corasick::{AhoCorasick, MatchKind};

/// One real name that survived into the twin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leak {
    /// The variant actually found, e.g. `customer_service`.
    pub matched: String,
    /// The vault name it derives from, e.g. `CustomerService`.
    pub real_name: String,
    pub byte_start: usize,
    pub byte_end: usize,
    pub line: usize,
    pub column: usize,
}

/// Outcome of a gate run — SDD §8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Safe to export. Callers must still show the user what was *not* checked
    /// (PRD §4.3): prose business logic, algorithms, architecture shape.
    Clean,
    /// Hard block. Export is refused until every leak is resolved or explicitly
    /// acknowledged, and the acknowledgement is written to the audit log.
    Blocked(Vec<Leak>),
}

impl Verdict {
    pub const fn is_clean(&self) -> bool {
        matches!(self, Self::Clean)
    }
}

/// Prebuilt scanner over the vault's real names.
///
/// Construction is the expensive part, so build once per session and cache
/// against a vault generation counter (SDD §18).
#[derive(Debug)]
pub struct LeakScanner {
    automaton: AhoCorasick,
    /// Parallel to the automaton's pattern ids: which vault name each variant
    /// came from.
    origins: Vec<String>,
    patterns: Vec<String>,
}

impl LeakScanner {
    /// Build a scanner from every real name in the vault.
    pub fn new<I, S>(real_names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut patterns = Vec::new();
        let mut origins = Vec::new();

        for name in real_names {
            let name = name.as_ref();
            if name.len() < MIN_NAME_LEN {
                // Very short names produce runaway false positives ("id", "db")
                // and are not identifying on their own.
                continue;
            }
            for variant in case_variants(name) {
                patterns.push(variant);
                origins.push(name.to_owned());
            }
        }

        let automaton = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)
            .expect("pattern set is well-formed");

        Self {
            automaton,
            origins,
            patterns,
        }
    }

    /// Scan candidate output. Any hit blocks export.
    pub fn scan(&self, twin: &str) -> Verdict {
        let mut leaks: Vec<Leak> = self
            .automaton
            .find_iter(twin)
            .filter(|m| is_whole_token(twin, m.start(), m.end()))
            .map(|m| {
                let (line, column) = line_col(twin, m.start());
                Leak {
                    matched: twin[m.start()..m.end()].to_owned(),
                    real_name: self.origins[m.pattern().as_usize()].clone(),
                    byte_start: m.start(),
                    byte_end: m.end(),
                    line,
                    column,
                }
            })
            .collect();

        if leaks.is_empty() {
            Verdict::Clean
        } else {
            leaks.sort_by_key(|l| l.byte_start);
            Verdict::Blocked(leaks)
        }
    }

    /// Number of variant patterns being matched. Reported in the UI so the user
    /// can see the gate is doing real work.
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

/// Names shorter than this are skipped: they are not identifying, and they
/// match inside unrelated words constantly.
const MIN_NAME_LEN: usize = 3;

/// Reject matches that sit inside a longer identifier, so `Order` does not
/// flag `Reorder` or `OrderedMap`.
fn is_whole_token(haystack: &str, start: usize, end: usize) -> bool {
    let before = haystack[..start].chars().next_back();
    let after = haystack[end..].chars().next();
    let boundary = |c: Option<char>| c.is_none_or(|c| !c.is_alphanumeric() && c != '_');
    boundary(before) && boundary(after)
}

fn line_col(text: &str, offset: usize) -> (usize, usize) {
    let head = &text[..offset];
    let line = head.matches('\n').count() + 1;
    let column = head.rsplit_once('\n').map_or(head.len(), |(_, tail)| tail.len()) + 1;
    (line, column)
}

/// Case variants of a real name — SDD §8 step 1.
///
/// `CustomerService` expands to `customerService`, `CustomerService`,
/// `customer_service`, `customer-service`, `CUSTOMER_SERVICE`,
/// `Customer Service`, and the naive plural of each.
pub fn case_variants(name: &str) -> Vec<String> {
    let words = split_words(name);
    if words.is_empty() {
        return Vec::new();
    }

    let lower: Vec<String> = words.iter().map(|w| w.to_lowercase()).collect();
    let capitalized: Vec<String> = lower.iter().map(|w| capitalize(w)).collect();

    let pascal = capitalized.concat();
    let camel = lower[0].clone() + &capitalized[1..].concat();

    let mut variants = vec![
        name.to_owned(),
        pascal,
        camel,
        lower.join("_"),
        lower.join("-"),
        lower.join("."),
        lower.join(" "),
        lower.join("").to_uppercase(),
        capitalized.join(" "),
        lower.iter().map(|w| w.to_uppercase()).collect::<Vec<_>>().join("_"),
    ];

    // Naive plurals — enough for `subscriptions` / `Subscriptions`.
    let mut plurals: Vec<String> = variants
        .iter()
        .filter(|v| !v.ends_with('s'))
        .map(|v| format!("{v}s"))
        .collect();
    variants.append(&mut plurals);

    variants.sort_unstable();
    variants.dedup();
    variants
}

/// Split an identifier into words on delimiters and camelCase boundaries.
fn split_words(name: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();

    for (i, c) in name.char_indices() {
        if !c.is_alphanumeric() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            continue;
        }
        // Boundary before an uppercase letter that follows a lowercase one, or
        // that starts a new word after an acronym run (`HTTPServer` -> HTTP,
        // Server).
        let starts_word = c.is_uppercase()
            && i > 0
            && !current.is_empty()
            && (current.ends_with(|p: char| p.is_lowercase() || p.is_numeric())
                || name[i..].chars().nth(1).is_some_and(char::is_lowercase));
        if starts_word {
            words.push(std::mem::take(&mut current));
        }
        current.push(c);
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn capitalize(word: &str) -> String {
    let mut chars = word.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().collect::<String>() + chars.as_str()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_twin_passes() {
        let scanner = LeakScanner::new(["CustomerService", "AcmeBank"]);
        assert_eq!(scanner.scan("class SERVICE_H7K2Q3 {}"), Verdict::Clean);
    }

    #[test]
    fn exact_real_name_is_blocked() {
        let scanner = LeakScanner::new(["CustomerService"]);
        let Verdict::Blocked(leaks) = scanner.scan("class CustomerService {}") else {
            panic!("expected a block");
        };
        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0].real_name, "CustomerService");
        assert_eq!(leaks[0].line, 1);
    }

    #[test]
    fn case_variants_are_blocked() {
        let scanner = LeakScanner::new(["CustomerService"]);
        // The realistic miss: the extractor renamed the class but not the
        // snake_case table, the kebab-case filename, or the prose mention.
        for twin in [
            "customer_service",
            "customer-service",
            "CUSTOMER_SERVICE",
            "the customer service owns this",
            "customerService",
        ] {
            assert!(!scanner.scan(twin).is_clean(), "{twin} should be blocked");
        }
    }

    #[test]
    fn plural_forms_are_blocked() {
        let scanner = LeakScanner::new(["Subscription"]);
        assert!(!scanner.scan("returns all subscriptions").is_clean());
    }

    #[test]
    fn substring_matches_inside_larger_identifiers_do_not_block() {
        // `Order` must not flag `Reorder` — false positives here are expensive:
        // they block a legitimate export.
        let scanner = LeakScanner::new(["Order"]);
        assert!(scanner.scan("const reorderBuffer = ReorderedMap;").is_clean());
    }

    #[test]
    fn very_short_names_are_skipped() {
        let scanner = LeakScanner::new(["id", "db"]);
        assert_eq!(scanner.pattern_count(), 0);
        assert!(scanner.scan("const id = db.query()").is_clean());
    }

    #[test]
    fn reports_line_and_column() {
        let scanner = LeakScanner::new(["AcmeBank"]);
        let Verdict::Blocked(leaks) = scanner.scan("line one\nline two\n  AcmeBank here") else {
            panic!("expected a block");
        };
        assert_eq!((leaks[0].line, leaks[0].column), (3, 3));
    }

    #[test]
    fn splits_acronyms_and_camel_case() {
        assert_eq!(split_words("HTTPServer"), ["HTTP", "Server"]);
        assert_eq!(
            split_words("customerSubscriptionService"),
            ["customer", "Subscription", "Service"]
        );
        assert_eq!(split_words("customer_subscription"), ["customer", "subscription"]);
    }
}
