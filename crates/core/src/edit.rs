//! Byte-range edit lists — SDD §4.2.1.
//!
//! Every transformation in SpecShield is expressed as a list of replacements
//! over byte ranges of the original file, applied by [`apply`]. No parser ever
//! serializes its own tree back to text: that is what destroys formatting,
//! comment placement, and key ordering.
//!
//! Bytes outside the edit ranges are copied through untouched, which is what
//! makes `restore(sanitize(x)) == x` achievable at all.

use uuid::Uuid;

/// One replacement over `[start, end)` of the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edit {
    pub start: usize,
    pub end: usize,
    pub replacement: String,
    /// The identity this edit realizes, if any. `None` for redactions, which
    /// are one-way and have no identity (SDD §4.3).
    pub identity: Option<Uuid>,
}

impl Edit {
    pub fn new(start: usize, end: usize, replacement: impl Into<String>, identity: Option<Uuid>) -> Self {
        Self {
            start,
            end,
            replacement: replacement.into(),
            identity,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EditError {
    #[error("edit range {start}..{end} is inverted")]
    Inverted { start: usize, end: usize },

    #[error("edit range {start}..{end} extends past end of source ({len} bytes)")]
    OutOfBounds { start: usize, end: usize, len: usize },

    #[error("edit {a_start}..{a_end} overlaps {b_start}..{b_end}")]
    Overlap {
        a_start: usize,
        a_end: usize,
        b_start: usize,
        b_end: usize,
    },

    #[error("edit range {start}..{end} does not fall on character boundaries")]
    NotCharBoundary { start: usize, end: usize },
}

/// Apply an edit list to `source`.
///
/// Edits are sorted and validated as non-overlapping, then applied
/// right-to-left so that earlier offsets stay valid as the string is mutated.
/// The input slice is sorted in place; callers may pass edits in any order.
pub fn apply(source: &str, edits: &mut [Edit]) -> Result<String, EditError> {
    edits.sort_by_key(|e| (e.start, e.end));
    validate(source, edits)?;

    let mut out = source.to_owned();
    for edit in edits.iter().rev() {
        out.replace_range(edit.start..edit.end, &edit.replacement);
    }
    Ok(out)
}

/// Check the invariants [`apply`] relies on. Separated out so the sanitizer can
/// validate a planned edit list before committing to it.
pub fn validate(source: &str, sorted_edits: &[Edit]) -> Result<(), EditError> {
    let len = source.len();

    for edit in sorted_edits {
        if edit.start > edit.end {
            return Err(EditError::Inverted {
                start: edit.start,
                end: edit.end,
            });
        }
        if edit.end > len {
            return Err(EditError::OutOfBounds {
                start: edit.start,
                end: edit.end,
                len,
            });
        }
        if !source.is_char_boundary(edit.start) || !source.is_char_boundary(edit.end) {
            return Err(EditError::NotCharBoundary {
                start: edit.start,
                end: edit.end,
            });
        }
    }

    for pair in sorted_edits.windows(2) {
        let (a, b) = (&pair[0], &pair[1]);
        if b.start < a.end {
            return Err(EditError::Overlap {
                a_start: a.start,
                a_end: a.end,
                b_start: b.start,
                b_end: b.end,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edit(start: usize, end: usize, replacement: &str) -> Edit {
        Edit::new(start, end, replacement, None)
    }

    #[test]
    fn applies_multiple_edits_left_to_right_in_the_output() {
        let source = "class CustomerService implements Repo {}";
        let mut edits = vec![edit(6, 21, "SERVICE_H7K2Q3"), edit(33, 37, "IFACE_M4X2Q7")];
        assert_eq!(
            apply(source, &mut edits).unwrap(),
            "class SERVICE_H7K2Q3 implements IFACE_M4X2Q7 {}"
        );
    }

    #[test]
    fn accepts_edits_in_any_order() {
        let source = "aXbYc";
        let mut forward = vec![edit(1, 2, "1"), edit(3, 4, "2")];
        let mut reversed = vec![edit(3, 4, "2"), edit(1, 2, "1")];
        assert_eq!(
            apply(source, &mut forward).unwrap(),
            apply(source, &mut reversed).unwrap()
        );
    }

    #[test]
    fn replacement_length_does_not_disturb_later_offsets() {
        let source = "ab cd ef";
        let mut edits = vec![edit(0, 2, "LONGER_REPLACEMENT"), edit(6, 8, "X")];
        assert_eq!(apply(source, &mut edits).unwrap(), "LONGER_REPLACEMENT cd X");
    }

    #[test]
    fn empty_edit_list_is_the_identity() {
        let source = "unchanged\n\ttext";
        assert_eq!(apply(source, &mut []).unwrap(), source);
    }

    #[test]
    fn rejects_overlapping_edits() {
        let mut edits = vec![edit(0, 5, "a"), edit(3, 8, "b")];
        assert!(matches!(
            apply("0123456789", &mut edits),
            Err(EditError::Overlap { .. })
        ));
    }

    #[test]
    fn adjacent_edits_are_not_overlapping() {
        let mut edits = vec![edit(0, 2, "X"), edit(2, 4, "Y")];
        assert_eq!(apply("abcd", &mut edits).unwrap(), "XY");
    }

    #[test]
    fn rejects_ranges_past_the_end() {
        let mut edits = vec![edit(0, 99, "x")];
        assert!(matches!(apply("short", &mut edits), Err(EditError::OutOfBounds { .. })));
    }

    #[test]
    fn rejects_ranges_that_split_a_multibyte_character() {
        // "é" is two bytes; slicing between them would panic in `apply`.
        let mut edits = vec![edit(0, 1, "x")];
        assert!(matches!(apply("é", &mut edits), Err(EditError::NotCharBoundary { .. })));
    }
}
