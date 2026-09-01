//! Git integration — SDD §14. **M5.**
//!
//! SpecShield never writes directly to `main`. It generates a unified diff with
//! `similar`, dry-runs it, applies it onto a dedicated branch, and lets the user
//! commit normally.
//!
//! Patch application shells out to the user's `git`: libgit2 has no usable
//! `git apply` equivalent (Design Review C3). Where `git` is unavailable, patch
//! mode is disabled and restored files are written instead — never a silent
//! overwrite.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Branches a patch is never applied to.
///
/// Not a style preference. Restoring AI output writes real identifiers into real
/// source, and the review that catches a wrong one happens in a pull request. A
/// patch applied straight to `main` has skipped it.
pub const PROTECTED_BRANCHES: &[&str] = &["main", "master", "develop", "trunk"];

#[derive(Debug, thiserror::Error)]
pub enum GitError {
    #[error("running git: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("git {command} failed: {stderr}")]
    Failed { command: String, stderr: String },
    #[error("the patch does not apply cleanly to the working tree: {stderr}")]
    DoesNotApply { stderr: String },
    #[error("{branch} is protected — a patch is never applied to it directly (SDD §14)")]
    ProtectedBranch { branch: String },
}

/// Why patch mode might not be available.
///
/// Reported rather than papered over: a user whose patch never arrives deserves
/// to know it was because `git` is not installed, not because SpecShield
/// silently decided to write files instead.
#[derive(Debug)]
pub enum Availability {
    Ready(Repository),
    /// No `git` on `PATH`.
    NoGit,
    /// `git` exists, but this directory is not inside a working tree.
    NotARepository,
}

impl Availability {
    /// One line explaining what the user can and cannot do.
    #[must_use]
    pub fn explain(&self) -> &'static str {
        match self {
            Self::Ready(_) => "patch mode available",
            Self::NoGit => "git is not on PATH — patch mode is disabled; restored files can still be written",
            Self::NotARepository => {
                "this project is not a git working tree — patch mode is disabled; restored files can still be written"
            }
        }
    }
}

#[derive(Debug)]
pub struct Repository {
    root: PathBuf,
}

/// What an application did, and everything needed to undo it.
#[derive(Debug, Clone)]
pub struct Applied {
    pub branch: String,
    /// The branch that was checked out beforehand.
    pub previous_branch: String,
    /// Whether `branch` had to be created.
    pub created_branch: bool,
    pub files: usize,
}

impl Repository {
    /// Find the working tree containing `path`, if git can be run at all.
    #[must_use]
    pub fn discover(path: &Path) -> Availability {
        let Ok(output) = Command::new("git")
            .arg("-C")
            .arg(path)
            .args(["rev-parse", "--show-toplevel"])
            .output()
        else {
            return Availability::NoGit;
        };

        if !output.status.success() {
            return Availability::NotARepository;
        }

        let root = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if root.is_empty() {
            return Availability::NotARepository;
        }
        Availability::Ready(Self { root: root.into() })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn current_branch(&self) -> Result<String, GitError> {
        Ok(self.run(&["rev-parse", "--abbrev-ref", "HEAD"])?.trim().to_owned())
    }

    /// Does the working tree have uncommitted changes?
    ///
    /// Not a refusal on its own — plenty of people work dirty — but the caller
    /// needs it to warn, because `undo` reverses the patch and cannot tell
    /// SpecShield's changes from the user's if they overlap.
    pub fn is_dirty(&self) -> Result<bool, GitError> {
        Ok(!self.run(&["status", "--porcelain"])?.trim().is_empty())
    }

    /// `git apply --check`: does this patch apply, without applying it?
    ///
    /// Always run before anything is written. A patch built from a twin whose
    /// original has drifted fails here, and failing here costs nothing.
    pub fn check(&self, patch: &str) -> Result<(), GitError> {
        match self.run_with_stdin(&["apply", "--check", "--whitespace=nowarn", "-"], patch) {
            Ok(_) => Ok(()),
            Err(GitError::Failed { stderr, .. }) => Err(GitError::DoesNotApply { stderr }),
            Err(e) => Err(e),
        }
    }

    /// Dry-run the patch, move to a working branch, and apply it.
    ///
    /// The order matters. The check happens before the branch is created, so a
    /// patch that was never going to apply does not leave a stray branch behind.
    pub fn apply_to_branch(&self, patch: &str, branch: &str, files: usize) -> Result<Applied, GitError> {
        if PROTECTED_BRANCHES.contains(&branch) {
            return Err(GitError::ProtectedBranch {
                branch: branch.to_owned(),
            });
        }

        self.check(patch)?;

        let previous_branch = self.current_branch()?;
        let created_branch = !self.branch_exists(branch)?;
        if created_branch {
            self.run(&["checkout", "-b", branch])?;
        } else if previous_branch != branch {
            self.run(&["checkout", branch])?;
        }

        // A failure here leaves the branch switched but the tree untouched —
        // `apply` is atomic, and `--check` already passed.
        self.run_with_stdin(&["apply", "--whitespace=nowarn", "-"], patch)?;

        Ok(Applied {
            branch: branch.to_owned(),
            previous_branch,
            created_branch,
            files,
        })
    }

    /// Reverse a patch this tool applied — SDD §14's undo.
    ///
    /// `git apply --reverse` rather than a saved copy of the files: it fails
    /// loudly if the tree has moved on, where restoring saved copies would
    /// silently discard whatever was done in between.
    pub fn undo(&self, patch: &str, applied: &Applied) -> Result<(), GitError> {
        self.run_with_stdin(&["apply", "--reverse", "--whitespace=nowarn", "-"], patch)?;

        if applied.previous_branch != applied.branch {
            self.run(&["checkout", &applied.previous_branch])?;
        }
        if applied.created_branch {
            // Only a branch this tool created, and only after leaving it.
            self.run(&["branch", "-D", &applied.branch])?;
        }
        Ok(())
    }

    fn branch_exists(&self, branch: &str) -> Result<bool, GitError> {
        let reference = format!("refs/heads/{branch}");
        match self.run(&["show-ref", "--verify", "--quiet", &reference]) {
            Ok(_) => Ok(true),
            Err(GitError::Failed { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn run(&self, args: &[&str]) -> Result<String, GitError> {
        let output = Command::new("git").arg("-C").arg(&self.root).args(args).output()?;
        if !output.status.success() {
            return Err(GitError::Failed {
                command: args.join(" "),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Every `git apply` goes through here, with line-ending translation off.
    ///
    /// The patch is built from the bytes SpecShield read out of the working
    /// tree and holds the bytes it intends to put back. With `core.autocrlf`
    /// enabled — the Windows default — git rewrites those on the way in, and the
    /// file on disk stops matching the restored text the user reviewed. Whatever
    /// the repository's convention is, the original already followed it.
    fn run_with_stdin(&self, args: &[&str], stdin: &str) -> Result<String, GitError> {
        use std::io::Write;
        use std::process::Stdio;

        let mut child = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(["-c", "core.autocrlf=false", "-c", "core.eol=lf"])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        child
            .stdin
            .take()
            .expect("stdin was piped")
            .write_all(stdin.as_bytes())?;

        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(GitError::Failed {
                command: args.join(" "),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

/// A unified diff for one file, in the form `git apply` expects.
///
/// Returns `None` when the file is unchanged: an empty hunk list is not a patch,
/// and `git apply` rejects a header with no body.
#[must_use]
pub fn file_patch(path: &str, before: &str, after: &str) -> Option<String> {
    if before == after {
        return None;
    }

    let diff = similar::TextDiff::from_lines(before, after);
    let body = diff
        .unified_diff()
        .context_radius(3)
        .header(&format!("a/{path}"), &format!("b/{path}"))
        .to_string();

    (!body.is_empty()).then(|| format!("diff --git a/{path} b/{path}\n{body}"))
}

/// One patch covering every changed file.
///
/// `files` is `(repository-relative path, before, after)`. Paths use `/` on
/// every platform, because that is what a patch header holds.
#[must_use]
pub fn patch<'a>(files: impl IntoIterator<Item = (&'a str, &'a str, &'a str)>) -> Option<String> {
    let body: String = files
        .into_iter()
        .filter_map(|(path, before, after)| file_patch(path, before, after))
        .collect();

    (!body.is_empty()).then_some(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct TempRepo(PathBuf);

    impl TempRepo {
        fn new(name: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!("specshield-git-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("create temp repo");

            let repo = Self(path);
            repo.git(&["init", "--initial-branch=main"]);
            repo.git(&["config", "user.email", "test@example.invalid"]);
            repo.git(&["config", "user.name", "Test"]);
            repo
        }

        fn git(&self, args: &[&str]) -> String {
            let output = Command::new("git")
                .arg("-C")
                .arg(&self.0)
                .args(args)
                .output()
                .expect("git should be available — see the_test_environment_has_git");
            assert!(
                output.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8_lossy(&output.stdout).into_owned()
        }

        fn write(&self, relative: &str, content: &str) {
            let path = self.0.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create parent");
            }
            fs::write(path, content).expect("write");
        }

        fn read(&self, relative: &str) -> String {
            fs::read_to_string(self.0.join(relative)).expect("read")
        }

        fn commit(&self, message: &str) {
            self.git(&["add", "-A"]);
            self.git(&["commit", "-m", message]);
        }

        fn open(&self) -> Repository {
            match Repository::discover(&self.0) {
                Availability::Ready(repo) => repo,
                other => panic!("expected a repository, got {other:?}"),
            }
        }
    }

    impl Drop for TempRepo {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_test_environment_has_git() {
        // Every test below shells out. If git is missing, one test says so
        // rather than a dozen failing for reasons that look unrelated.
        assert!(
            Command::new("git").arg("--version").output().is_ok(),
            "these tests exercise real `git apply`; install git to run them"
        );
    }

    #[test]
    fn an_unchanged_file_produces_no_patch() {
        assert_eq!(file_patch("a.ts", "same\n", "same\n"), None);
        assert_eq!(patch([("a.ts", "same\n", "same\n")]), None);
    }

    #[test]
    fn a_patch_applies_to_a_branch_and_never_to_main() {
        let repo = TempRepo::new("apply");
        repo.write("src/a.ts", "class CustomerService {}\n");
        repo.commit("initial");

        let git = repo.open();
        assert_eq!(git.current_branch().unwrap(), "main");

        let patch = patch([(
            "src/a.ts",
            "class CustomerService {}\n",
            "class CustomerService {\n  retry() {}\n}\n",
        )])
        .expect("a change produces a patch");

        let applied = git.apply_to_branch(&patch, "specshield/restore", 1).unwrap();

        assert_eq!(applied.previous_branch, "main");
        assert_eq!(git.current_branch().unwrap(), "specshield/restore");
        assert!(applied.created_branch);
        assert!(repo.read("src/a.ts").contains("retry()"));
    }

    #[test]
    fn applying_to_a_protected_branch_is_refused() {
        let repo = TempRepo::new("protected");
        repo.write("a.ts", "one\n");
        repo.commit("initial");

        let git = repo.open();
        let patch = patch([("a.ts", "one\n", "two\n")]).unwrap();

        let result = git.apply_to_branch(&patch, "main", 1);
        assert!(matches!(result, Err(GitError::ProtectedBranch { .. })), "{result:?}");
        assert_eq!(repo.read("a.ts"), "one\n", "nothing was written");
    }

    #[test]
    fn a_patch_that_does_not_apply_leaves_no_branch_behind() {
        let repo = TempRepo::new("stale");
        repo.write("a.ts", "the file moved on\n");
        repo.commit("initial");

        let git = repo.open();
        // Built against content that is no longer there.
        let patch = patch([("a.ts", "what the twin was made from\n", "edited\n")]).unwrap();

        let result = git.apply_to_branch(&patch, "specshield/restore", 1);
        assert!(matches!(result, Err(GitError::DoesNotApply { .. })), "{result:?}");
        assert_eq!(git.current_branch().unwrap(), "main", "still on the original branch");
        assert!(
            !repo.git(&["branch", "--list"]).contains("specshield"),
            "a failed check must not leave a stray branch"
        );
    }

    #[test]
    fn undo_reverses_the_patch_and_removes_a_branch_it_created() {
        let repo = TempRepo::new("undo");
        repo.write("a.ts", "one\n");
        repo.commit("initial");

        let git = repo.open();
        let patch = patch([("a.ts", "one\n", "two\n")]).unwrap();
        let applied = git.apply_to_branch(&patch, "specshield/restore", 1).unwrap();
        assert_eq!(repo.read("a.ts"), "two\n");

        git.undo(&patch, &applied).unwrap();

        assert_eq!(repo.read("a.ts"), "one\n");
        assert_eq!(git.current_branch().unwrap(), "main");
        assert!(!repo.git(&["branch", "--list"]).contains("specshield"));
    }

    #[test]
    fn undo_refuses_rather_than_discarding_later_edits() {
        // The user edited the file after the patch landed. Reversing by
        // restoring a saved copy would throw that away without a word; `git
        // apply --reverse` fails instead.
        let repo = TempRepo::new("undo-dirty");
        repo.write("a.ts", "one\n");
        repo.commit("initial");

        let git = repo.open();
        let patch = patch([("a.ts", "one\n", "two\n")]).unwrap();
        let applied = git.apply_to_branch(&patch, "specshield/restore", 1).unwrap();

        repo.write("a.ts", "two\nand something of my own\n");

        let result = git.undo(&patch, &applied);
        assert!(result.is_err(), "undo must not silently drop the later edit");
        assert!(repo.read("a.ts").contains("something of my own"));
    }

    #[test]
    fn a_directory_outside_a_repository_is_reported_as_such() {
        let mut path = std::env::temp_dir();
        path.push(format!("specshield-not-a-repo-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();

        // A temp directory can sit inside someone's repository; only assert the
        // negative case when it genuinely does not.
        if let Availability::NotARepository = Repository::discover(&path) {
            let availability = Repository::discover(&path);
            assert!(availability.explain().contains("patch mode is disabled"));
        }
        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn a_dirty_tree_is_visible_to_the_caller() {
        let repo = TempRepo::new("dirty");
        repo.write("a.ts", "one\n");
        repo.commit("initial");

        let git = repo.open();
        assert!(!git.is_dirty().unwrap());

        repo.write("a.ts", "changed\n");
        assert!(git.is_dirty().unwrap());
    }

    #[test]
    fn the_applied_bytes_are_exactly_the_restored_text() {
        // git's `core.autocrlf` is on by default on Windows and rewrites line
        // endings as it applies. The file on disk then stops matching the text
        // the user reviewed, which is the one thing a patch must not do.
        let repo = TempRepo::new("bytes");
        repo.write(
            "a.ts", "one
",
        );
        repo.commit("initial");
        repo.git(&["config", "core.autocrlf", "true"]);

        let git = repo.open();
        let after = "one
two
three
";
        let patch = patch([(
            "a.ts", "one
", after,
        )])
        .unwrap();
        git.apply_to_branch(&patch, "specshield/restore", 1).unwrap();

        assert_eq!(repo.read("a.ts"), after);
    }

    #[test]
    fn a_multi_file_patch_applies_as_one_unit() {
        let repo = TempRepo::new("multi");
        repo.write("a.ts", "a one\n");
        repo.write("b.ts", "b one\n");
        repo.commit("initial");

        let git = repo.open();
        let patch = patch([("a.ts", "a one\n", "a two\n"), ("b.ts", "b one\n", "b two\n")]).unwrap();

        git.apply_to_branch(&patch, "specshield/restore", 2).unwrap();

        assert_eq!(repo.read("a.ts"), "a two\n");
        assert_eq!(repo.read("b.ts"), "b two\n");
    }
}
