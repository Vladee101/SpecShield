//! Clipboard hardening — PRD §10, SDD §17.5, Design Review A5.
//!
//! # The problem this solves
//!
//! SpecShield sends nothing anywhere: the capability set has no network
//! permission. **Windows does.** With Clipboard History and "Sync across your
//! devices" enabled, the OS uploads clipboard text to the user's Microsoft
//! account so it appears on their other machines.
//!
//! That upload happens *after* the verification gate has finished, so it is a
//! route off the machine the gate cannot see. Only a verified twin is ever
//! copied — never original text — but PRD §4.3 is explicit that a verified twin
//! is not non-confidential: it still carries business logic in prose.
//!
//! # How the opt-out works
//!
//! Windows reads three registered clipboard formats set alongside the text.
//! Each is advisory — a cooperating OS and clipboard manager honour them:
//!
//! | Format | Governs |
//! |---|---|
//! | `ExcludeClipboardContentFromMonitorProcessing` | clipboard monitors and loggers |
//! | `CanIncludeInClipboardHistory` | the local Win+V history |
//! | `CanUploadToCloudClipboard` | **cross-device sync to the Microsoft account** |
//!
//! The third is the one that governs the upload. Setting only the first two
//! suppresses local history while leaving sync running — which would look done
//! and fix nothing.
//!
//! # What this does not do
//!
//! These formats are a request, not an enforcement boundary. A clipboard manager
//! that ignores them still captures the text, and nothing prevents the user
//! pasting the twin somewhere themselves. The honest claim is "SpecShield opts
//! out of the platform's clipboard retention", not "the twin cannot be
//! captured".

use std::time::Duration;

use crate::AppError;

/// How long a copied twin stays on the clipboard before being cleared.
///
/// Long enough to switch windows and paste; short enough that a twin is not
/// still sitting there hours later. Surfacing this in settings is UI work that
/// has not been done — the constant is the current answer, not the final one.
pub(crate) const CLEAR_AFTER: Duration = Duration::from_secs(120);

/// Result of a protected clipboard write, so the caller can tell the user what
/// actually happened rather than implying a guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protection {
    /// The opt-out formats were set. History and cloud sync are suppressed on a
    /// cooperating system.
    ///
    /// Only the Windows `platform::write` below constructs this, so off Windows
    /// the variant is matched — `lib.rs` turns it into the audit destination —
    /// and never produced. That is dead code by the letter and the shape of the
    /// design by intent: the caller must be able to name both outcomes on every
    /// platform, or the audit log could not record which exports the OS may
    /// have retained (Threat Model §5.9).
    #[cfg_attr(not(windows), allow(dead_code))]
    OptedOut,
    /// The text was copied, but this platform has no opt-out implemented, so
    /// the OS may retain or sync it.
    NotAvailable,
}

/// Write `text` to the clipboard, opting out of platform retention where we can.
pub(crate) fn write_protected(text: &str) -> Result<Protection, AppError> {
    platform::write(text)
}

/// Clear the clipboard, but only if it still holds `expected`.
///
/// Reads the clipboard first so a later copy by the user is never destroyed —
/// clearing unconditionally would make SpecShield the reason someone lost what
/// they had just copied from another application.
pub(crate) fn clear_if_unchanged(expected: &str) -> Result<bool, AppError> {
    platform::clear_if_unchanged(expected)
}

#[cfg(windows)]
mod platform {
    use super::{AppError, Protection};

    /// Set on every payload so a cooperating Windows suppresses retention.
    ///
    /// All three take a `DWORD 0`. The first is documented as presence-based —
    /// any data works — so a zero `DWORD` keeps the call site uniform.
    const OPT_OUT_FORMATS: [&str; 3] = [
        "ExcludeClipboardContentFromMonitorProcessing",
        "CanIncludeInClipboardHistory",
        "CanUploadToCloudClipboard",
    ];

    pub(super) fn write(text: &str) -> Result<Protection, AppError> {
        use clipboard_win::{Clipboard, Setter, formats, raw, register_format};

        // RAII: the clipboard is closed when this drops, including on the error
        // paths below. Retried because another process may hold it briefly.
        let _clipboard =
            Clipboard::new_attempts(10).map_err(|e| AppError::Message(format!("could not open the clipboard: {e}")))?;

        raw::empty().map_err(|e| AppError::Message(format!("could not clear the clipboard: {e}")))?;

        // Text first. The opt-out formats must survive, and anything that
        // empties the clipboard after them would drop them.
        formats::Unicode
            .write_clipboard(&text)
            .map_err(|e| AppError::Message(format!("clipboard write failed: {e}")))?;

        let mut opted_out = true;
        for name in OPT_OUT_FORMATS {
            let Some(format) = register_format(name) else {
                opted_out = false;
                continue;
            };
            // `set_without_clear`, or each format would wipe the previous one
            // and the text along with them.
            if raw::set_without_clear(format.get(), &0u32.to_ne_bytes()).is_err() {
                opted_out = false;
            }
        }

        Ok(if opted_out {
            Protection::OptedOut
        } else {
            // The text is on the clipboard; the opt-out is not. Report it rather
            // than claiming a protection the user does not have.
            Protection::NotAvailable
        })
    }

    pub(super) fn clear_if_unchanged(expected: &str) -> Result<bool, AppError> {
        use clipboard_win::{Clipboard, Getter, formats, raw};

        let _clipboard =
            Clipboard::new_attempts(10).map_err(|e| AppError::Message(format!("could not open the clipboard: {e}")))?;

        let mut current = String::new();
        if formats::Unicode.read_clipboard(&mut current).is_err() {
            // Nothing readable as text: not ours, so leave it alone.
            return Ok(false);
        }
        if current != expected {
            return Ok(false);
        }

        raw::empty().map_err(|e| AppError::Message(format!("could not clear the clipboard: {e}")))?;
        Ok(true)
    }
}

#[cfg(not(windows))]
mod platform {
    use super::{AppError, Protection};

    // macOS has `org.nspasteboard.ConcealedType`, which password managers use to
    // keep entries out of clipboard managers; Linux behaviour depends entirely
    // on the clipboard manager in use. Neither is implemented, so both report
    // `NotAvailable` rather than quietly claiming protection.
    //
    // The Tauri plugin handles the actual write on these platforms — see the
    // caller.
    // Both signatures are dictated by the Windows twin above, which really can
    // fail — `OpenClipboard` and `SetClipboardData` are fallible. Clippy is
    // right that *these* bodies never do, and wrong that the `Result` is
    // unnecessary: dropping it here would mean `write_protected` needed a
    // `#[cfg]` branch of its own and the crate would have two public shapes
    // for one operation.
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn write(_text: &str) -> Result<Protection, AppError> {
        Ok(Protection::NotAvailable)
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn clear_if_unchanged(_expected: &str) -> Result<bool, AppError> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_clear_delay_is_long_enough_to_be_usable() {
        // A timeout under ~30s would clear the twin before a user has switched
        // windows and pasted, which trains people to copy twice.
        assert!(CLEAR_AFTER >= Duration::from_secs(30));
        assert!(CLEAR_AFTER <= Duration::from_secs(600));
    }

    #[cfg(windows)]
    #[test]
    fn a_protected_write_round_trips_and_then_clears() {
        // Exercises the real Win32 path: write, read back, clear.
        let payload = format!("SERVICE_H7K2Q3 test payload {}", std::process::id());

        let protection = write_protected(&payload).expect("clipboard write");
        assert_eq!(protection, Protection::OptedOut, "opt-out formats should register");

        // Clearing must be conditional: a different value is left alone.
        assert!(
            !clear_if_unchanged("something the user copied later").expect("clear check"),
            "must not clear a clipboard it does not own"
        );

        assert!(
            clear_if_unchanged(&payload).expect("clear"),
            "should clear its own payload"
        );
        assert!(
            !clear_if_unchanged(&payload).expect("second clear"),
            "already cleared, nothing to do"
        );
    }
}
