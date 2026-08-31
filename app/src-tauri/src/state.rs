//! Session state for the desktop shell.
//!
//! Holds the open vault and the last verified twin. Two rules make this small
//! module load-bearing:
//!
//! 1. **The vault key never leaves this process.** It lives inside the `Vault`
//!    handle, derived once at unlock. Nothing serializes it to the frontend.
//! 2. **Only a verified twin is copyable.** `copy_verified_twin` reads from here
//!    rather than accepting text over IPC, so there is no path by which the UI
//!    can place original content on the clipboard (SDD §17.5).

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use specshield_vault as vault;

use crate::AppError;

/// Vault filename inside a project, matching the CLI.
pub(crate) const VAULT_FILE: &str = ".specshield/vault.bin";

pub(crate) fn vault_path(project_root: &Path) -> PathBuf {
    project_root.join(VAULT_FILE)
}

#[derive(Default)]
pub(crate) struct AppState {
    inner: Mutex<Option<Session>>,
}

struct Session {
    vault: vault::Vault,
    root: PathBuf,
    /// The twin from the last sanitize that passed the gate. Cleared whenever a
    /// sanitize is blocked, so a stale verified twin cannot be copied after a
    /// later failure.
    verified_twin: Option<String>,
}

impl AppState {
    pub(crate) fn open(&self, root: &Path, passphrase: &str) -> Result<(), AppError> {
        let vault = vault::Vault::open(&vault_path(root), passphrase)?;
        *self.inner.lock().expect("state lock") = Some(Session {
            vault,
            root: root.to_path_buf(),
            verified_twin: None,
        });
        Ok(())
    }

    pub(crate) fn close(&self) {
        // Dropping the session drops the vault, and with it the derived keys,
        // which zeroize on drop.
        *self.inner.lock().expect("state lock") = None;
    }

    /// Run `f` against the open vault, or fail with a clear message.
    pub(crate) fn with<T>(
        &self,
        f: impl FnOnce(&mut vault::Vault, &Path) -> Result<T, AppError>,
    ) -> Result<T, AppError> {
        let mut guard = self.inner.lock().expect("state lock");
        let session = guard
            .as_mut()
            .ok_or_else(|| AppError::Message("no project is open".to_owned()))?;
        let root = session.root.clone();
        f(&mut session.vault, &root)
    }

    pub(crate) fn set_verified_twin(&self, twin: Option<String>) {
        if let Some(session) = self.inner.lock().expect("state lock").as_mut() {
            session.verified_twin = twin;
        }
    }

    pub(crate) fn take_verified_twin(&self) -> Option<String> {
        self.inner
            .lock()
            .expect("state lock")
            .as_ref()
            .and_then(|s| s.verified_twin.clone())
    }
}
