//! Corpus scoring — PRD §5.
//!
//! Measures detection recall and precision against the labelled golden corpus.
//! This is the command CI runs; `--strict` turns the targets into a build gate.
//!
//! Two numbers are reported per project, because they answer different
//! questions:
//!
//! - **rules only** — what the detector finds with no help. This is the honest
//!   cold-start number for a project nobody has curated.
//! - **with dictionary** — what it finds once the user has named the handful of
//!   terms only they can name (PRD FR-10). This is the number that matters in
//!   use, and the gap between the two is the argument for the dictionary flow.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use specshield_core::detect::Detector;
use specshield_core::model::{EntityType, OccurrenceKind};
use specshield_core::secrets;

/// PRD §5 targets.
const RECALL_TARGET: f64 = 0.95;
const PRECISION_TARGET: f64 = 0.90;

#[derive(Debug, Deserialize)]
struct Labels {
    project: String,
    entities: Vec<Entity>,
    #[serde(default)]
    secrets: Vec<Secret>,
    #[serde(default)]
    never_alias: Vec<String>,
    #[serde(default)]
    negative_files: Vec<String>,
    /// Parsers this project needs before its numbers mean anything.
    #[serde(default)]
    requires: Vec<String>,
    /// The milestone that makes those parsers exist.
    #[serde(default)]
    milestone: String,
}

impl Labels {
    /// Can this project be scored meaningfully with the parsers in this build?
    ///
    /// Scoring a SQL project with no SQL parser measures nothing and drags the
    /// aggregate down for a reason that has nothing to do with detection
    /// quality — so those projects are reported but not gated.
    fn is_gated(&self) -> bool {
        let implemented = specshield_parsers::implemented();
        !self.requires.is_empty() && self.requires.iter().all(|r| implemented.contains(&r.as_str()))
    }
}

// Field names mirror the corpus JSON schema and cannot be renamed.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Deserialize)]
struct Entity {
    real_name: String,
    entity_type: String,
    occurrences: Vec<Occurrence>,
}

#[derive(Debug, Deserialize)]
struct Occurrence {
    file: String,
    byte_start: usize,
    byte_end: usize,
}

#[allow(clippy::struct_field_names)]
#[derive(Debug, Deserialize)]
struct Secret {
    file: String,
    byte_start: usize,
    secret_type: String,
}

#[derive(Debug, Default)]
struct Score {
    expected: usize,
    detected: usize,
    /// Detections that match no label, hit a `never_alias` term, or land in a
    /// negative fixture.
    false_positives: usize,
    /// What those detections were. When precision drops, this is the first
    /// question anyone asks, and guessing at it wastes an afternoon.
    unexpected: Vec<(String, String, usize)>,
    /// Labelled occurrences nothing detected — the leaks, in other words.
    missed: Vec<(String, String, usize)>,
    /// Labelled occurrences of names that are a single ordinary word, which the
    /// detector leaves alone on purpose — PRD §4.2 and `core::words`.
    ordinary: usize,
    ordinary_detected: usize,
    /// Labelled occurrences of names that describe **what was built** rather
    /// than **who built it** — PRD §4.1. Left in the twin on purpose, so an
    /// agent can read the architecture it is being asked to work on.
    ///
    /// Counted apart from `expected` rather than deleted from the corpus. They
    /// are still the user's names, and `specshield term` still hides any of them
    /// on request — so what the corpus records is a *default*, and the number
    /// here is what that default costs. Scoring them as misses would make the
    /// headline meaningless; deleting the labels would hide the trade.
    structural: usize,
}

impl Score {
    #[allow(clippy::cast_precision_loss)]
    fn recall(&self) -> f64 {
        if self.expected == 0 {
            1.0
        } else {
            self.detected as f64 / self.expected as f64
        }
    }

    #[allow(clippy::cast_precision_loss)]
    fn precision(&self) -> f64 {
        let total = self.detected + self.false_positives;
        if total == 0 {
            1.0
        } else {
            self.detected as f64 / total as f64
        }
    }
}

/// The two lists that say *why* the numbers are what they are. Printed only on
/// request: they are long, and a CI run reads the summary.
fn print_detail(projects: &[(PathBuf, Labels)]) {
    println!("\n## Missed\n");
    println!("Labelled and not detected. Each one is a name that would reach the model.\n");
    for (dir, labels) in projects {
        let detail = score(dir, labels, true);
        if detail.missed.is_empty() {
            continue;
        }
        println!("**{}** ({} occurrences)\n", labels.project, detail.missed.len());
        for (file, name, offset) in detail.missed.iter().take(12) {
            println!("- `{name}` in `{file}` at {offset}");
        }
        println!();
    }

    println!(
        "
## Unexpected detections
"
    );
    println!("Detected but not in ground truth. Either the detector is over-reaching or the");
    println!("corpus is incomplete — decide which on the merits, never by whichever makes the");
    println!(
        "number look better.
"
    );
    for (dir, labels) in projects {
        let detail = score(dir, labels, true);
        if detail.unexpected.is_empty() {
            continue;
        }
        println!(
            "**{}**
",
            labels.project
        );
        for (file, name, offset) in &detail.unexpected {
            println!("- `{name}` in `{file}` at {offset}");
        }
        println!();
    }
}

pub(crate) fn run(corpus: &Path, strict: bool, verbose: bool) -> Result<()> {
    let projects = load_projects(corpus)?;
    if projects.is_empty() {
        bail!("no labelled projects under {}", corpus.display());
    }

    println!("# Corpus report\n");
    println!("Targets (PRD §5): recall >= {RECALL_TARGET:.2}, precision >= {PRECISION_TARGET:.2}\n");
    println!(
        "Parsers in this build: {}
",
        specshield_parsers::implemented().join(", ")
    );
    println!("| Project | Gated | Entities | Rules-only recall | With dictionary | Precision |");
    println!("|---|:-:|---:|---:|---:|---:|");

    let mut gated = Score::default();
    let mut gated_rules = Score::default();

    for (dir, labels) in &projects {
        let rules = score(dir, labels, false);
        let dict = score(dir, labels, true);
        let is_gated = labels.is_gated();

        println!(
            "| `{}` | {} | {} | {:.0}% | {:.0}% | {:.0}% |",
            labels.project,
            if is_gated {
                "yes".to_owned()
            } else {
                format!("{} ", labels.milestone)
            },
            labels.entities.len(),
            rules.recall() * 100.0,
            dict.recall() * 100.0,
            dict.precision() * 100.0
        );

        if is_gated {
            gated_rules.expected += rules.expected;
            gated_rules.detected += rules.detected;
            gated_rules.false_positives += rules.false_positives;
            gated.expected += dict.expected;
            gated.detected += dict.detected;
            gated.false_positives += dict.false_positives;
            gated.ordinary += dict.ordinary;
            gated.ordinary_detected += dict.ordinary_detected;
            gated.structural += dict.structural;
        }
    }

    println!(
        "| **gated total** | | {} | **{:.1}%** | **{:.1}%** | **{:.1}%** |",
        gated.expected,
        gated_rules.recall() * 100.0,
        gated.recall() * 100.0,
        gated.precision() * 100.0
    );
    println!();
    // The cost of PRD §4, stated rather than assumed. Both numbers are labelled
    // names that reach the model on purpose, and both are recoverable with one
    // `specshield term`.
    println!(
        "Recall above is over the **{} identity occurrence(s)** SpecShield hides by default —",
        gated.expected
    );
    println!("organizations and hosts. Two other buckets are labelled and deliberately left in");
    println!("the twin:");
    println!();
    println!(
        "- **{} structural occurrence(s)** — what was *built*: DTOs, tables, columns, services.",
        gated.structural
    );
    println!("  An agent that cannot read your architecture cannot help you extend it (PRD §4.1).");
    println!(
        "- **{} ordinary-word occurrence(s)** — an org or host whose name is a common word.",
        gated.ordinary
    );
    println!();
    println!("`specshield term <name>` moves any of them back. The corpus is thin on identity");
    println!("fixtures precisely because it was built for the old scope — that is the gap to");
    println!("close next, not the recall number.");
    println!();
    println!("Ungated projects are reported for visibility but excluded from the");
    println!("verdict: their formats have no parser in this build, so their numbers");
    println!("measure the missing milestone rather than detection quality.");

    let total_dict = gated;

    if verbose {
        print_detail(&projects);
    }

    // Secrets are scored separately: they are a different operation with a
    // different failure mode (SDD §4.3).
    let (found, expected, false_positives) = score_secrets(&projects);
    println!("\n## Secrets\n");
    println!("- planted: {expected}, detected: {found}");
    println!("- false positives in clean fixtures: {false_positives}");

    println!("\n## Verdict\n");
    let recall = total_dict.recall();
    let precision = total_dict.precision();
    let recall_ok = recall >= RECALL_TARGET;
    let precision_ok = precision >= PRECISION_TARGET;
    let secrets_ok = found == expected;

    println!("- recall {:.1}% {}", recall * 100.0, pass(recall_ok));
    println!("- precision {:.1}% {}", precision * 100.0, pass(precision_ok));
    println!("- secret detection {found}/{expected} {}", pass(secrets_ok));

    if strict && !(recall_ok && precision_ok && secrets_ok) {
        bail!("corpus targets not met");
    }
    Ok(())
}

const fn pass(ok: bool) -> &'static str {
    if ok { "PASS" } else { "FAIL" }
}

fn load_projects(corpus: &Path) -> Result<Vec<(PathBuf, Labels)>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(corpus).with_context(|| format!("reading {}", corpus.display()))? {
        let dir = entry?.path();
        let labels_path = dir.join("labels.json");
        if !labels_path.is_file() {
            continue;
        }
        let raw = std::fs::read_to_string(&labels_path)?;
        let labels: Labels =
            serde_json::from_str(&raw).with_context(|| format!("parsing {}", labels_path.display()))?;
        out.push((dir, labels));
    }
    out.sort_by(|a, b| a.1.project.cmp(&b.1.project));
    Ok(out)
}

/// Score one project. With `use_dictionary`, the detector is seeded with the
/// labelled Organization names — simulating a user who has done the FR-10 step.
fn score(dir: &Path, labels: &Labels, use_dictionary: bool) -> Score {
    let mut detector = Detector::new();
    if use_dictionary {
        for entity in &labels.entities {
            // Only the types no rule can recognise. Seeding the detector with
            // everything would measure nothing.
            if entity.entity_type == "organization" {
                detector = detector.with_term(&entity.real_name, EntityType::Organization);
            }
        }
    }
    for term in &labels.never_alias {
        // never_alias terms are what the user would have allowlisted, except
        // the alias-shaped ones, which must be rejected by the detector itself.
        detector = detector.with_allowed(term);
    }

    let mut score = Score::default();
    let (expected_spans, labelled_spans) = label_spans(labels);
    score.expected = expected_spans.len();

    // The project's known members, as the vault would supply them after a scan.
    // Without this the TypeScript parser sees each file in isolation and misses
    // every property *reference*, which is most of them.
    let context = specshield_core::parser::ProjectContext::new(
        labels
            .entities
            .iter()
            .filter(|e| e.entity_type == "column")
            .map(|e| e.real_name.clone()),
        labels.entities.iter().map(|e| e.real_name.clone()),
    );

    let negative: HashSet<&str> = labels.negative_files.iter().map(String::as_str).collect();
    let files: HashSet<&str> = labels
        .entities
        .iter()
        .flat_map(|e| e.occurrences.iter().map(|o| o.file.as_str()))
        .chain(negative.iter().copied())
        .collect();

    for file in files {
        let path = dir.join(file);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        // Detection runs on the redacted text, through the same two-source
        // merge as the pipeline: the parser's structural candidates first, then
        // the prose scan for whatever they did not claim. Scoring with only the
        // prose scan would measure a pipeline nobody runs.
        let findings = secrets::scan(&text);
        let redacted = secrets::redact(&text, &findings);
        let parser = specshield_parsers::for_document(&path, &text);
        let mut candidates = parser
            .as_ref()
            .map_or_else(Vec::new, |p| p.structural_candidates_in(&redacted, "project", &context));
        let claimed: Vec<(usize, usize)> = candidates.iter().map(|c| (c.byte_start, c.byte_end)).collect();
        let regions = parser.as_ref().and_then(|p| p.prose_regions(&redacted));
        for candidate in detector.scan_text(&redacted, "project", OccurrenceKind::Reference) {
            let overlaps = claimed
                .iter()
                .any(|(s, e)| candidate.byte_start < *e && *s < candidate.byte_end);
            let in_prose = regions.as_ref().is_none_or(|regions| {
                regions
                    .iter()
                    .any(|(s, e)| candidate.byte_start >= *s && candidate.byte_end <= *e)
            });
            if !overlaps && in_prose {
                candidates.push(candidate);
            }
        }

        // Back into the file's own coordinates before anything is compared with
        // ground truth. A marker is a different length from the secret it
        // replaced, so a fixture with a name after a secret was scored against
        // offsets 12 bytes out of place — counting one correct detection as a
        // miss *and* a false positive at once. See `secrets::source_offset`.
        for candidate in &mut candidates {
            candidate.byte_start = secrets::source_offset(&findings, candidate.byte_start);
            candidate.byte_end = secrets::source_offset(&findings, candidate.byte_end);
        }

        let mut hit: HashSet<(String, usize, usize)> = HashSet::new();
        for candidate in candidates {
            if candidate.confidence < specshield_core::sanitize::AUTO_APPLY_CONFIDENCE {
                continue; // suggestions are not detections
            }
            // The same second bar `sanitize` applies — without it this scores a
            // pipeline nobody runs, which is how the offset bug survived in CI
            // for as long as it did.
            if !detector.should_alias(&candidate.real_name, candidate.entity_type) {
                continue;
            }
            let key = (file.to_owned(), candidate.byte_start, candidate.byte_end);
            if expected_spans.contains(&key) {
                hit.insert(key);
                continue;
            }

            // A detection *inside* a labelled occurrence covers it. An identity
            // is aliased inside the compound that names it, so `VANTOR` at
            // offset 1330 of `VANTOR_BILLING_URL` is a narrower span than the
            // label and the same disclosure: the company name does not reach the
            // model. Scoring it as a false positive would have punished the
            // capability the product now depends on, and scoring the label as
            // missed would have claimed a leak that did not happen.
            let inside = |spans: &HashSet<(String, usize, usize)>| {
                spans
                    .iter()
                    .find(|(f, s, e)| f == file && candidate.byte_start >= *s && candidate.byte_end <= *e)
                    .cloned()
            };
            if let Some(span) = inside(&expected_spans) {
                hit.insert(span);
                continue;
            }
            // Inside a labelled name the product does not claim. Not a hit, and
            // not a mistake either.
            if inside(&labelled_spans).is_some() {
                continue;
            }

            score.false_positives += 1;
            score
                .unexpected
                .push((file.to_owned(), candidate.real_name.clone(), candidate.byte_start));
        }

        // Counted from the set, not incremented per detection: two detections
        // can cover one labelled occurrence — the whole token and the identity
        // inside it — and recall is *occurrences covered*, which cannot exceed
        // the number of them. Incrementing produced 115%.
        score.detected += hit.len();
        tally_labels(labels, file, &hit, &mut score);
    }

    score
}

/// The two span sets scoring needs, because recall and precision ask different
/// questions.
///
/// The first is what recall is measured against: occurrences of the entities
/// SpecShield claims to hide. The second is every occurrence the corpus records,
/// and it exists so a detection *inside* a label is never scored as a false
/// positive — the `VANTOR` in the env var `VANTOR_BILLING_URL` is an identity
/// found inside a structural name, which is exactly right and belongs in neither
/// the miss column nor the wrong one.
type Spans = HashSet<(String, usize, usize)>;

fn label_spans(labels: &Labels) -> (Spans, Spans) {
    let mut expected = Spans::new();
    let mut labelled = Spans::new();
    for entity in &labels.entities {
        for occ in &entity.occurrences {
            let span = (occ.file.clone(), occ.byte_start, occ.byte_end);
            if is_claimed(entity) {
                expected.insert(span.clone());
            }
            labelled.insert(span);
        }
    }
    (expected, labelled)
}

/// Does the label name an identity type — PRD §4.1?
///
/// The corpus writes the serde form of `EntityType`, so this is the same list as
/// [`specshield_core::model::EntityType::is_identity`], reached through the same
/// spelling the labels use.
fn identity_type(label: &str) -> bool {
    serde_json::from_value::<EntityType>(serde_json::Value::String(label.to_owned())).is_ok_and(EntityType::is_identity)
}

/// Is this an entity SpecShield claims to hide by default?
///
/// An identity that is also identifying on its own. An organization called
/// `admin` is a word; a DTO called `CustomerSubscription` is architecture.
fn is_claimed(entity: &Entity) -> bool {
    identity_type(&entity.entity_type) && specshield_core::words::is_identifying(&entity.real_name)
}

/// Everything labelled in one file, against what was actually found.
///
/// A miss is a name that reaches the model. An *ordinary* name is one the
/// detector leaves alone on purpose (PRD §4) — it also reaches the model, and is
/// counted apart so the headline number measures what the product claims rather
/// than what it has stopped claiming.
fn tally_labels(labels: &Labels, file: &str, hit: &HashSet<(String, usize, usize)>, score: &mut Score) {
    {
        for entity in &labels.entities {
            for occ in &entity.occurrences {
                if occ.file != file {
                    continue;
                }
                let found = hit.contains(&(file.to_owned(), occ.byte_start, occ.byte_end));
                if is_claimed(entity) {
                    if !found {
                        score
                            .missed
                            .push((file.to_owned(), entity.real_name.clone(), occ.byte_start));
                    }
                } else if identity_type(&entity.entity_type) {
                    // An organization or host that is a single ordinary word.
                    score.ordinary += 1;
                    score.ordinary_detected += usize::from(found);
                } else {
                    // What was built. Left readable on purpose.
                    score.structural += 1;
                }
            }
        }
    }
}

fn score_secrets(projects: &[(PathBuf, Labels)]) -> (usize, usize, usize) {
    let mut found = 0;
    let mut expected = 0;
    let mut false_positives = 0;

    for (dir, labels) in projects {
        let secret_files: HashSet<&str> = labels.secrets.iter().map(|s| s.file.as_str()).collect();

        for secret in &labels.secrets {
            expected += 1;
            let Ok(text) = std::fs::read_to_string(dir.join(&secret.file)) else {
                continue;
            };
            if secrets::scan(&text)
                .iter()
                .any(|f| f.byte_start <= secret.byte_start && secret.byte_start < f.byte_end)
            {
                found += 1;
            } else {
                eprintln!(
                    "missed secret: {}/{} {} at byte {}",
                    labels.project, secret.file, secret.secret_type, secret.byte_start
                );
            }
        }

        // Any secret finding in a file with no planted secret is a false
        // positive — this is what keeps the entropy heuristic honest.
        for entity in &labels.entities {
            for occ in &entity.occurrences {
                if secret_files.contains(occ.file.as_str()) {
                    continue;
                }
                if let Ok(text) = std::fs::read_to_string(dir.join(&occ.file)) {
                    false_positives += secrets::scan(&text)
                        .iter()
                        .filter(|f| f.confidence == secrets::Confidence::High)
                        .count();
                }
                break;
            }
        }
    }

    (found, expected, false_positives)
}
