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

    pub(crate) fn verified_twin(&self) -> Option<String> {
        self.inner
            .lock()
            .expect("state lock")
            .as_ref()
            .and_then(|s| s.verified_twin.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempProject(PathBuf);

    impl TempProject {
        fn new(name: &str) -> Self {
            let mut root = std::env::temp_dir();
            root.push(format!("specshield-state-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).expect("temp dir");

            let settings = vault::Settings {
                project_name: "test".to_owned(),
                root_path: root.display().to_string(),
                alias_style: "opaque".to_owned(),
                scope_strategy: "module".to_owned(),
                project_key: [1; 32],
            };
            vault::Vault::create(&vault_path(&root), "pw", &settings).expect("create vault");
            Self(root)
        }
    }

    impl Drop for TempProject {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn opened(name: &str) -> (TempProject, AppState) {
        let project = TempProject::new(name);
        let state = AppState::default();
        state.open(&project.0, "pw").expect("open");
        (project, state)
    }

    #[test]
    fn nothing_is_copyable_before_a_sanitize() {
        let (_p, state) = opened("empty");
        assert!(state.verified_twin().is_none());
    }

    #[test]
    fn a_verified_twin_becomes_copyable() {
        let (_p, state) = opened("verified");
        state.set_verified_twin(Some("class SERVICE_H7K2Q3 {}".to_owned()));
        assert_eq!(state.verified_twin().as_deref(), Some("class SERVICE_H7K2Q3 {}"));
    }

    /// The invariant `copy_verified_twin` depends on: a blocked sanitize passes
    /// `None`, which must clear the previous twin. Without this, a user whose
    /// second sanitize was blocked could still copy the first — believing they
    /// had copied the document now on screen.
    #[test]
    fn a_blocked_sanitize_clears_the_previous_twin() {
        let (_p, state) = opened("blocked");
        state.set_verified_twin(Some("first, verified".to_owned()));
        state.set_verified_twin(None);
        assert!(
            state.verified_twin().is_none(),
            "a stale twin survived a blocked sanitize"
        );
    }

    #[test]
    fn closing_the_project_makes_the_twin_unreachable() {
        let (_p, state) = opened("close");
        state.set_verified_twin(Some("verified".to_owned()));
        state.close();
        assert!(state.verified_twin().is_none());
    }

    #[test]
    fn a_twin_set_with_no_project_open_is_discarded() {
        // `set_verified_twin` is a no-op without a session, so a twin can never
        // outlive the vault it was derived from.
        let state = AppState::default();
        state.set_verified_twin(Some("orphan".to_owned()));
        assert!(state.verified_twin().is_none());
    }

    #[test]
    fn operations_without_an_open_project_fail_rather_than_panic() {
        let state = AppState::default();
        let result = state.with(|_, _| Ok(()));
        assert!(result.is_err());
    }
}
