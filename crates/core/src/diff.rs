//! Diff Engine — SDD §13. **M5.**
//!
//! Three versions exist and the difference between them is the whole point:
//!
//! ```text
//! Original            Twin                 AI Twin
//! CustomerService  →  SERVICE_H7K2QX   →   SERVICE_H7K2QX + retry logic
//!                                              ↓ restore
//!                                          CustomerService + retry logic
//! ```
//!
//! Two diffs, kept apart deliberately. Twin → AI-Twin is *what the model did*,
//! in the vocabulary the model was given. Original → Restored is *what will land
//! in the repository*. Merging them into one view hides which side a change came
//! from, and the user needs to know: a line that differs only because restore
//! matched an alias loosely is a very different thing from a line the model
//! rewrote.
//!
//! Fuzzy-restored aliases, unresolved identities, and redaction markers are
//! attached to the hunks they fall inside, so review is per-change rather than a
//! separate list to cross-reference by line number.
//!
//! Staleness (SDD §13.1) is not decided here — `specshield_index` owns the
//! checksums. The diff reports what a patch would do; whether that patch may be
//! applied at all is a question about the file on disk.

use similar::{ChangeTag, TextDiff};

use crate::restore::{self, MatchKind, Outcome, Vocabulary};
use crate::secrets::REDACTION_PREFIX;

/// What happened to a run of lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Removed,
    /// Lines replaced by other lines.
    Changed,
    /// A change that survives normalizing whitespace — the text is the same,
    /// the layout is not.
    ///
    /// Reported rather than dropped. A model that reindents a file produces a
    /// patch that touches every line of it, and the user should be able to see
    /// that is all it did before deciding to throw it away.
    Formatting,
}

impl ChangeKind {
    /// Is this a change in content rather than in layout?
    #[must_use]
    pub const fn is_substantive(self) -> bool {
        !matches!(self, Self::Formatting)
    }
}

/// Which side of the pipeline a line came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Before,
    After,
}

#[derive(Debug, Clone)]
pub struct Line {
    pub side: Side,
    /// 1-based line number on that side.
    pub number: usize,
    pub text: String,
}

/// Something about a hunk a human has to look at before the patch is applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    /// An alias that did not match byte-for-byte — SDD §6.4.
    ///
    /// The model drifted the token and the matcher recovered it. That recovery
    /// is a guess with good evidence, not a certainty, and it writes a real name
    /// into the user's repository.
    Fuzzy {
        found: String,
        real_name: String,
        kind: MatchKind,
    },
    /// An alias-shaped token the vault has never seen — SDD §12.
    ///
    /// The model invented an entity. Nothing is guessed: the token stays in the
    /// restored text until the user names it.
    Unresolved { token: String },
    /// A one-way redaction marker, which restore deliberately leaves standing.
    Redaction { marker: String },
}

/// A run of changed lines, with everything about it that needs review.
#[derive(Debug, Clone)]
pub struct Hunk {
    pub kind: ChangeKind,
    /// 1-based, inclusive-exclusive line range on the "before" side.
    pub before: (usize, usize),
    pub after: (usize, usize),
    pub lines: Vec<Line>,
    pub notes: Vec<Note>,
}

impl Hunk {
    #[must_use]
    pub fn needs_review(&self) -> bool {
        !self.notes.is_empty()
    }
}

/// The result of comparing all three versions.
#[derive(Debug)]
pub struct Review {
    /// The restored text — what a patch would put in the repository.
    pub restored: String,
    /// Original → Restored. What the user is being asked to accept.
    pub changes: Vec<Hunk>,
    /// Twin → AI-Twin. What the model actually did, before restore touched it.
    pub model_changes: Vec<Hunk>,
    /// Every note, with the restored-text line it sits on.
    ///
    /// Hunks carry the subset that falls inside them, for inline display. This
    /// is the complete list, and it has to exist: a fuzzy match can restore to
    /// text identical to the original — `SERVICE_H7K2QXImpl` back to
    /// `CustomerService` — producing no hunk at all. The guess still happened
    /// and still put a real name in the file. Surfacing review only through
    /// hunks would lose exactly the cases where nothing looks wrong.
    pub notes: Vec<(usize, Note)>,
    /// The full restore outcome, for callers that want the raw lists.
    pub outcome: Outcome,
}

impl Review {
    /// Changes that alter content rather than layout.
    pub fn substantive(&self) -> impl Iterator<Item = &Hunk> {
        self.changes.iter().filter(|h| h.kind.is_substantive())
    }

    /// Is there anything here a human must look at before this is applied?
    #[must_use]
    pub fn needs_review(&self) -> bool {
        !self.notes.is_empty()
    }

    /// Unresolved identities block a patch outright — SDD §12.
    ///
    /// Applying a patch that still contains `SERVICE_099` writes an alias into
    /// the user's real repository. There is no safe default: the name is
    /// genuinely unknown, and inventing one is how a wrong identifier gets
    /// committed.
    #[must_use]
    pub fn blocks_patch(&self) -> bool {
        !self.outcome.unresolved.is_empty()
    }
}

/// Compare the three versions and restore the model's output.
///
/// `twin` is what was sent to the model, `ai_twin` what came back. `original` is
/// the real file as it stands — not as it stood when the twin was made. If those
/// differ, the caller is looking at a stale twin, and the extra hunks here are
/// the intervening edits about to be reverted. `specshield_index` is what
/// detects that; this function will happily diff against anything.
#[must_use]
pub fn review(original: &str, twin: &str, ai_twin: &str, vocabulary: &Vocabulary) -> Review {
    let outcome = restore::restore(ai_twin, vocabulary);
    let notes = collect_notes(&outcome);

    Review {
        changes: hunks(original, &outcome.text, &notes),
        model_changes: hunks(twin, ai_twin, &[]),
        restored: outcome.text.clone(),
        notes,
        outcome,
    }
}

/// Every note the restore produced, keyed by the line it sits on in the
/// restored text.
fn collect_notes(outcome: &Outcome) -> Vec<(usize, Note)> {
    let mut notes: Vec<(usize, Note)> = Vec::new();

    for hit in outcome.needs_review() {
        notes.push((
            hit.line,
            Note::Fuzzy {
                found: hit.found.clone(),
                real_name: hit.real_name.clone(),
                kind: hit.match_kind,
            },
        ));
    }
    for hit in &outcome.unresolved {
        notes.push((
            hit.line,
            Note::Unresolved {
                token: hit.token.clone(),
            },
        ));
    }

    // Redaction markers are found in the text rather than reported by the
    // restorer: they were put there by the *sanitize* side, which this half of
    // the pipeline never saw.
    for (i, line) in outcome.text.lines().enumerate() {
        if let Some(start) = line.find(REDACTION_PREFIX) {
            let marker = line[start..].find(">>").map_or_else(
                || line[start..].to_owned(),
                |end| line[start..start + end + 2].to_owned(),
            );
            notes.push((i + 1, Note::Redaction { marker }));
        }
    }

    notes
}

/// Line-level diff, grouped into hunks.
fn hunks(before: &str, after: &str, notes: &[(usize, Note)]) -> Vec<Hunk> {
    let diff = TextDiff::from_lines(before, after);
    let mut out: Vec<Hunk> = Vec::new();
    let mut current: Option<Hunk> = None;

    for change in diff.iter_all_changes() {
        let Some(kind) = tag_kind(change.tag()) else {
            // An unchanged line ends whatever run was open.
            if let Some(hunk) = current.take() {
                out.push(finish(hunk, notes));
            }
            continue;
        };

        let (side, number) = match change.tag() {
            ChangeTag::Delete => (Side::Before, change.old_index().unwrap_or(0) + 1),
            _ => (Side::After, change.new_index().unwrap_or(0) + 1),
        };

        let hunk = current.get_or_insert_with(|| Hunk {
            kind,
            before: (number, number),
            after: (number, number),
            lines: Vec::new(),
            notes: Vec::new(),
        });

        // A run holding both deletions and insertions is a replacement, not two
        // separate edits — that is what the user sees and what a patch does.
        if hunk.kind != kind {
            hunk.kind = ChangeKind::Changed;
        }

        match side {
            Side::Before => {
                if hunk.lines.iter().all(|l| l.side == Side::After) {
                    hunk.before = (number, number);
                }
                hunk.before.1 = number + 1;
            }
            Side::After => {
                if hunk.lines.iter().all(|l| l.side == Side::Before) {
                    hunk.after = (number, number);
                }
                hunk.after.1 = number + 1;
            }
        }

        hunk.lines.push(Line {
            side,
            number,
            text: change.value().to_owned(),
        });
    }

    if let Some(hunk) = current.take() {
        out.push(finish(hunk, notes));
    }
    out
}

const fn tag_kind(tag: ChangeTag) -> Option<ChangeKind> {
    match tag {
        ChangeTag::Delete => Some(ChangeKind::Removed),
        ChangeTag::Insert => Some(ChangeKind::Added),
        ChangeTag::Equal => None,
    }
}

/// Classify a completed hunk and attach the notes that fall inside it.
fn finish(mut hunk: Hunk, notes: &[(usize, Note)]) -> Hunk {
    if hunk.kind == ChangeKind::Changed && is_formatting_only(&hunk) {
        hunk.kind = ChangeKind::Formatting;
    }

    // Notes are positioned in the *restored* text, which is the "after" side.
    let (start, end) = hunk.after;
    for (line, note) in notes {
        if *line >= start && *line < end.max(start + 1) && !hunk.notes.contains(note) {
            hunk.notes.push(note.clone());
        }
    }
    hunk
}

/// Do both sides say the same thing with different whitespace?
fn is_formatting_only(hunk: &Hunk) -> bool {
    let squash = |side: Side| -> String {
        hunk.lines
            .iter()
            .filter(|l| l.side == side)
            .flat_map(|l| l.text.split_whitespace())
            .collect::<Vec<_>>()
            .join(" ")
    };
    let before = squash(Side::Before);
    !before.is_empty() && before == squash(Side::After)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vocabulary() -> Vocabulary {
        Vocabulary::new(vec![
            ("SERVICE_H7K2QX", "CustomerService"),
            ("DTO_AB12CD", "CustomerSubscription"),
        ])
    }

    #[test]
    fn an_untouched_response_produces_no_changes() {
        let original = "class CustomerService {}\n";
        let twin = "class SERVICE_H7K2QX {}\n";
        let review = review(original, twin, twin, &vocabulary());

        assert_eq!(review.restored, original);
        assert!(review.changes.is_empty(), "{:#?}", review.changes);
        assert!(review.model_changes.is_empty());
    }

    #[test]
    fn an_addition_by_the_model_lands_in_real_names() {
        let original = "class CustomerService {}\n";
        let twin = "class SERVICE_H7K2QX {}\n";
        let ai = "class SERVICE_H7K2QX {\n  retry() {}\n}\n";

        let review = review(original, twin, ai, &vocabulary());

        assert_eq!(review.restored, "class CustomerService {\n  retry() {}\n}\n");
        assert!(!review.changes.is_empty());
        assert!(
            !review.model_changes.is_empty(),
            "the model's own edit is shown separately"
        );
    }

    #[test]
    fn reindentation_is_called_formatting_rather_than_hidden() {
        // A model that reindents produces a patch touching every line. The user
        // needs to see that is all it did, not have it silently dropped.
        let original = "class CustomerService {\n  a();\n}\n";
        let twin = "class SERVICE_H7K2QX {\n  a();\n}\n";
        let ai = "class SERVICE_H7K2QX {\n      a();\n}\n";

        let review = review(original, twin, ai, &vocabulary());

        assert_eq!(review.changes.len(), 1, "{:#?}", review.changes);
        assert_eq!(review.changes[0].kind, ChangeKind::Formatting);
        assert_eq!(review.substantive().count(), 0);
    }

    #[test]
    fn a_real_edit_on_a_reindented_line_is_still_substantive() {
        let original = "class CustomerService {\n  a();\n}\n";
        let twin = "class SERVICE_H7K2QX {\n  a();\n}\n";
        let ai = "class SERVICE_H7K2QX {\n      b();\n}\n";

        let review = review(original, twin, ai, &vocabulary());
        assert_eq!(review.substantive().count(), 1, "{:#?}", review.changes);
    }

    #[test]
    fn a_fuzzy_restore_survives_even_when_it_changes_nothing() {
        // The model appended a suffix; the matcher recovered it (SDD §6.4) and
        // the result is byte-identical to the original. There is no hunk to
        // attach a note to — and this is precisely the case that must not slip
        // through, because the guess still wrote a real name.
        let original = "class CustomerService {}\n";
        let twin = "class SERVICE_H7K2QX {}\n";
        let ai = "class SERVICE_H7K2QXImpl {}\n";

        let review = review(original, twin, ai, &vocabulary());

        assert!(review.changes.is_empty(), "nothing changed: {:#?}", review.changes);
        assert!(
            review.notes.iter().any(|(_, n)| matches!(n, Note::Fuzzy { .. })),
            "{:#?}",
            review.notes
        );
        assert!(review.needs_review(), "a guess that writes a real name is reviewable");
    }

    #[test]
    fn a_fuzzy_restore_inside_a_change_is_attached_to_that_hunk() {
        let original = "class CustomerService {}\n";
        let twin = "class SERVICE_H7K2QX {}\n";
        let ai = "class SERVICE_H7K2QXImpl {\n  retry() {}\n}\n";

        let review = review(original, twin, ai, &vocabulary());

        let notes: Vec<&Note> = review.changes.iter().flat_map(|h| &h.notes).collect();
        assert!(
            notes.iter().any(|n| matches!(n, Note::Fuzzy { .. })),
            "{:#?}",
            review.changes
        );
    }

    #[test]
    fn an_unresolved_identity_blocks_the_patch() {
        // SDD §12: the model invented an entity. Nothing is guessed, and the
        // patch cannot be applied while an alias would be written into real
        // source.
        let original = "class CustomerService {}\n";
        let twin = "class SERVICE_H7K2QX {}\n";
        let ai = "class SERVICE_H7K2QX {}\nclass SERVICE_099 {}\n";

        let review = review(original, twin, ai, &vocabulary());

        assert!(review.blocks_patch());
        assert!(review.restored.contains("SERVICE_099"), "the token is left standing");
        let notes: Vec<&Note> = review.changes.iter().flat_map(|h| &h.notes).collect();
        assert!(notes.iter().any(|n| matches!(n, Note::Unresolved { .. })), "{notes:#?}");
    }

    #[test]
    fn a_redaction_marker_is_called_out_where_it_survives() {
        let original = "const k = \"sk-live-abcdef123456\";\n";
        let twin = "const k = \"<<REDACTED:api_key>>\";\n";
        let ai = "const k = \"<<REDACTED:api_key>>\";\nconst n = 1;\n";

        let review = review(original, twin, ai, &vocabulary());
        let notes: Vec<&Note> = review.changes.iter().flat_map(|h| &h.notes).collect();
        assert!(
            notes.iter().any(|n| matches!(n, Note::Redaction { .. })),
            "the secret is not coming back, and the diff has to say so: {notes:#?}"
        );
    }

    #[test]
    fn the_two_diffs_answer_different_questions() {
        // The model changed nothing; restore changed every alias. Folding these
        // into one view would report the model as having rewritten the file.
        let original = "class CustomerService {}\n";
        let twin = "class SERVICE_H7K2QX {}\n";

        let review = review(original, twin, twin, &vocabulary());
        assert!(review.model_changes.is_empty(), "the model did nothing");
        assert!(review.changes.is_empty(), "and restore put back exactly what was there");
    }

    #[test]
    fn a_stale_original_shows_the_edits_a_patch_would_revert() {
        // The twin was made before someone added a line. Restoring on top of the
        // current file would drop it, and the diff is where that becomes visible
        // (SDD §13.1 blocks it separately, on checksums).
        let original = "class CustomerService {}\nconst added = 1;\n";
        let twin = "class SERVICE_H7K2QX {}\n";
        let ai = "class SERVICE_H7K2QX {}\n";

        let review = review(original, twin, ai, &vocabulary());
        assert_eq!(review.substantive().count(), 1);
        assert_eq!(review.changes[0].kind, ChangeKind::Removed);
    }
}
