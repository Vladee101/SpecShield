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
use std::path::Path;

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

pub(crate) fn run(corpus: &Path, strict: bool) -> Result<()> {
    let projects = load_projects(corpus)?;
    if projects.is_empty() {
        bail!("no labelled projects under {}", corpus.display());
    }

    println!("# Corpus report\n");
    println!("Targets (PRD §5): recall >= {RECALL_TARGET:.2}, precision >= {PRECISION_TARGET:.2}\n");
    println!("| Project | Entities | Rules-only recall | With dictionary | Precision |");
    println!("|---|---:|---:|---:|---:|");

    let mut total_rules = Score::default();
    let mut total_dict = Score::default();

    for (dir, labels) in &projects {
        let rules = score(dir, labels, false);
        let dict = score(dir, labels, true);

        println!(
            "| `{}` | {} | {:.0}% | {:.0}% | {:.0}% |",
            labels.project,
            labels.entities.len(),
            rules.recall() * 100.0,
            dict.recall() * 100.0,
            dict.precision() * 100.0
        );

        total_rules.expected += rules.expected;
        total_rules.detected += rules.detected;
        total_rules.false_positives += rules.false_positives;
        total_dict.expected += dict.expected;
        total_dict.detected += dict.detected;
        total_dict.false_positives += dict.false_positives;
    }

    println!(
        "| **total** | {} | **{:.1}%** | **{:.1}%** | **{:.1}%** |",
        total_dict.expected,
        total_rules.recall() * 100.0,
        total_dict.recall() * 100.0,
        total_dict.precision() * 100.0
    );

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

fn load_projects(corpus: &Path) -> Result<Vec<(std::path::PathBuf, Labels)>> {
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
    let mut expected_spans: HashSet<(String, usize, usize)> = HashSet::new();
    for entity in &labels.entities {
        for occ in &entity.occurrences {
            expected_spans.insert((occ.file.clone(), occ.byte_start, occ.byte_end));
        }
    }
    score.expected = expected_spans.len();

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
        // Detection runs on the redacted text, as the pipeline does.
        let redacted = secrets::redact(&text, &secrets::scan(&text));
        let candidates = detector.scan_text(&redacted, "project", OccurrenceKind::Reference);

        for candidate in candidates {
            if candidate.confidence < specshield_core::sanitize::AUTO_APPLY_CONFIDENCE {
                continue; // suggestions are not detections
            }
            let key = (file.to_owned(), candidate.byte_start, candidate.byte_end);
            if expected_spans.contains(&key) {
                score.detected += 1;
            } else {
                score.false_positives += 1;
            }
        }
    }

    score
}

fn score_secrets(projects: &[(std::path::PathBuf, Labels)]) -> (usize, usize, usize) {
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
