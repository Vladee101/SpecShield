//! Project indexing — SDD §4.1, §13.1. **M4.**
//!
//! Gitignore-aware walking via `ignore`, BLAKE3 checksums, `rayon` hashing
//! parallelism, and incremental rescan.
//!
//! Checksums are not bookkeeping: they drive staleness detection. Restoring AI
//! output produced from a stale twin silently reverts intervening edits, so a
//! checksum mismatch blocks patch application until a rescan (SDD §13.1).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

/// Bytes read to decide whether a file is text. A NUL in the first block is the
/// same test `git diff` uses, and it is enough: the index only needs to know
/// what a parser could possibly be handed.
const SNIFF: usize = 8192;

/// Files above this are skipped. A 5 MB source file is a vendored bundle or a
/// checked-in artifact, and hashing it buys nothing the walk needs.
const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error("walking {root}: {source}")]
    Walk {
        root: PathBuf,
        #[source]
        source: ignore::Error,
    },
    #[error("reading {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} is outside the project root")]
    Escapes { path: PathBuf },
}

/// One file as the index last saw it.
///
/// `size` and `modified` are reported, never trusted. A rescan hashes every
/// file, because the alternative — skipping files whose size and mtime match —
/// misses a same-length rewrite inside one mtime tick, and that is precisely the
/// edit the staleness gate exists to catch. A missed edit here means a patch
/// silently reverts someone's work.
///
/// The cost is bounded: hashing is a read and a BLAKE3 pass, both parallel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Relative to the project root, with `/` separators on every platform, so
    /// an index built on Windows and one built on Linux agree.
    pub path: String,
    /// BLAKE3, lowercase hex.
    pub checksum: String,
    pub size: u64,
    /// Seconds since the Unix epoch, or `None` where the platform withholds it.
    pub modified: Option<u64>,
    /// Whether the first block is free of NUL bytes. Binary files are indexed —
    /// they are part of the project — but never offered to a parser.
    pub is_text: bool,
}

/// A project as of one walk.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Index {
    pub root: PathBuf,
    /// Keyed by relative path, so lookup and rescan are both ordered and cheap.
    pub files: BTreeMap<String, Entry>,
}

/// What a rescan found, relative to the index it was handed.
///
/// `unchanged` is a count rather than a list: nobody acts on it, and carrying
/// 1,000 paths that did nothing is how a report becomes unreadable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Changes {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub removed: Vec<String>,
    pub unchanged: usize,
}

impl Changes {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.modified.is_empty() && self.removed.is_empty()
    }

    /// Paths a caller must re-sanitize: everything new or edited.
    #[must_use]
    pub fn needs_work(&self) -> Vec<&str> {
        self.added
            .iter()
            .chain(self.modified.iter())
            .map(String::as_str)
            .collect()
    }
}

impl Index {
    /// Walk `root` and hash every file it holds.
    ///
    /// `.gitignore`, `.ignore`, and the global gitignore are all respected, and
    /// `.git` itself is skipped. A project's ignored files are ignored for a
    /// reason — `node_modules` is not the user's proprietary code, and indexing
    /// it is how a 1,000-file repo becomes a 90,000-file one.
    pub fn build(root: &Path) -> Result<Self, IndexError> {
        let paths = walk(root)?;

        let entries: Vec<Entry> = paths
            .par_iter()
            .map(|(path, size, modified)| entry_for(root, path, *size, *modified))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            root: root.to_path_buf(),
            files: entries.into_iter().map(|e| (e.path.clone(), e)).collect(),
        })
    }

    /// Rebuild the index and classify what moved.
    ///
    /// Incremental in what the *caller* then does — only `Changes::needs_work`
    /// gets re-sanitized — not in what gets hashed. See `Entry` for why the
    /// mtime shortcut is not taken.
    pub fn rescan(&self, root: &Path) -> Result<(Self, Changes), IndexError> {
        let paths = walk(root)?;

        let entries: Vec<Entry> = paths
            .par_iter()
            .map(|(path, size, modified)| entry_for(root, path, *size, *modified))
            .collect::<Result<Vec<_>, _>>()?;

        let files: BTreeMap<String, Entry> = entries.into_iter().map(|e| (e.path.clone(), e)).collect();

        let mut changes = Changes::default();
        for (path, entry) in &files {
            match self.files.get(path) {
                None => changes.added.push(path.clone()),
                Some(previous) if previous.checksum == entry.checksum => changes.unchanged += 1,
                Some(_) => changes.modified.push(path.clone()),
            }
        }
        for path in self.files.keys() {
            if !files.contains_key(path) {
                changes.removed.push(path.clone());
            }
        }

        Ok((
            Self {
                root: root.to_path_buf(),
                files,
            },
            changes,
        ))
    }

    #[must_use]
    pub fn checksum(&self, relative: &str) -> Option<&str> {
        self.files.get(relative).map(|e| e.checksum.as_str())
    }

    /// Files a parser could be offered.
    pub fn text_files(&self) -> impl Iterator<Item = &Entry> {
        self.files.values().filter(|e| e.is_text)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Which of `recorded` no longer match the file on disk — SDD §13.1.
    ///
    /// The caller holds `(path, checksum_at_sanitize_time)` pairs from the
    /// vault. Anything this returns is a file whose twin was made from content
    /// that no longer exists, and applying a patch to it would revert whatever
    /// was edited in between. A file that has since been *deleted* is stale too:
    /// there is nothing left to apply the patch to.
    #[must_use]
    pub fn stale<'a>(&self, recorded: &'a [(String, String)]) -> Vec<&'a str> {
        recorded
            .iter()
            .filter(|(path, checksum)| self.checksum(path) != Some(checksum.as_str()))
            .map(|(path, _)| path.as_str())
            .collect()
    }
}

/// The checksum of one file, for a caller that has no reason to walk a tree.
///
/// The staleness guard (SDD §13.1) asks about a single file at a time, and
/// hashing the whole project to answer that would be absurd.
pub fn checksum_of(path: &Path) -> Result<String, IndexError> {
    let bytes = std::fs::read(path).map_err(|source| IndexError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

/// The walk, kept separate from hashing so `build` and `rescan` share it.
///
/// Returns `(absolute path, size, mtime)`: the metadata is already in hand from
/// the directory entry, and asking the filesystem for it twice is the kind of
/// waste that shows up at 1,000 files.
fn walk(root: &Path) -> Result<Vec<(PathBuf, u64, Option<u64>)>, IndexError> {
    let mut out = Vec::new();

    for result in ignore::WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(true)
        // A project is a project whether or not `git init` has been run in it.
        // Without this the walk silently ignores `.gitignore` outside a repo,
        // and `node_modules` lands in the index.
        .require_git(false)
        .build()
    {
        let entry = result.map_err(|source| IndexError::Walk {
            root: root.to_path_buf(),
            source,
        })?;

        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        // The vault, the twins, and git's own storage are not project source.
        if entry
            .path()
            .components()
            .any(|c| matches!(c.as_os_str().to_str(), Some(".git" | ".specshield")))
        {
            continue;
        }

        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if metadata.len() > MAX_FILE_BYTES {
            continue;
        }

        let modified = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs());

        out.push((entry.path().to_path_buf(), metadata.len(), modified));
    }

    Ok(out)
}

fn entry_for(root: &Path, path: &Path, size: u64, modified: Option<u64>) -> Result<Entry, IndexError> {
    let bytes = std::fs::read(path).map_err(|source| IndexError::Read {
        path: path.to_path_buf(),
        source,
    })?;

    Ok(Entry {
        path: relative_to(root, path)?,
        checksum: blake3::hash(&bytes).to_hex().to_string(),
        size,
        modified,
        is_text: !bytes.iter().take(SNIFF).any(|b| *b == 0),
    })
}

/// A project-root-relative path with `/` separators.
fn relative_to(root: &Path, path: &Path) -> Result<String, IndexError> {
    let relative = path.strip_prefix(root).map_err(|_| IndexError::Escapes {
        path: path.to_path_buf(),
    })?;

    Ok(relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct TempProject(PathBuf);

    impl TempProject {
        fn new(name: &str) -> Self {
            let mut p = std::env::temp_dir();
            p.push(format!("specshield-index-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).expect("create temp project");
            Self(p)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn write(&self, relative: &str, content: &[u8]) {
            let path = self.0.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create parent");
            }
            fs::write(path, content).expect("write fixture");
        }
    }

    impl Drop for TempProject {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_walk_respects_gitignore() {
        let project = TempProject::new("gitignore");
        project.write(".gitignore", b"node_modules/\n*.log\n");
        project.write("src/main.ts", b"export const a = 1;\n");
        project.write("node_modules/pkg/index.js", b"module.exports = {};\n");
        project.write("debug.log", b"noise\n");

        let index = Index::build(project.path()).expect("build");
        let paths: Vec<&String> = index.files.keys().collect();

        assert!(paths.iter().any(|p| p.as_str() == "src/main.ts"), "{paths:?}");
        assert!(
            !paths.iter().any(|p| p.contains("node_modules")),
            "an ignored directory is not the user's code: {paths:?}"
        );
        assert!(!paths.iter().any(|p| p.as_str() == "debug.log"), "{paths:?}");
    }

    #[test]
    fn paths_use_forward_slashes_on_every_platform() {
        let project = TempProject::new("separators");
        project.write("src/domain/plan.ts", b"export {};\n");

        let index = Index::build(project.path()).expect("build");
        assert!(
            index.files.contains_key("src/domain/plan.ts"),
            "an index built on Windows must match one built on Linux: {:?}",
            index.files.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_binary_file_is_indexed_but_not_offered_to_a_parser() {
        let project = TempProject::new("binary");
        project.write("logo.png", &[0x89, b'P', b'N', b'G', 0x00, 0x1a]);
        project.write("src/a.ts", b"export {};\n");

        let index = Index::build(project.path()).expect("build");
        assert_eq!(index.len(), 2);

        let text: Vec<&str> = index.text_files().map(|e| e.path.as_str()).collect();
        assert_eq!(text, vec!["src/a.ts"]);
    }

    #[test]
    fn a_rescan_of_an_untouched_project_reports_nothing() {
        let project = TempProject::new("quiet");
        project.write("src/a.ts", b"export const a = 1;\n");
        project.write("src/b.ts", b"export const b = 2;\n");

        let index = Index::build(project.path()).expect("build");
        let (next, changes) = index.rescan(project.path()).expect("rescan");

        assert!(changes.is_empty(), "{changes:?}");
        assert_eq!(changes.unchanged, 2);
        assert_eq!(next.files, index.files);
    }

    #[test]
    fn a_rescan_separates_added_modified_and_removed() {
        let project = TempProject::new("changes");
        project.write("src/a.ts", b"export const a = 1;\n");
        project.write("src/gone.ts", b"export const g = 0;\n");

        let index = Index::build(project.path()).expect("build");

        project.write("src/a.ts", b"export const a = 99;\n");
        project.write("src/new.ts", b"export const n = 3;\n");
        fs::remove_file(project.path().join("src/gone.ts")).expect("remove");

        let (_, changes) = index.rescan(project.path()).expect("rescan");

        assert_eq!(changes.added, vec!["src/new.ts"]);
        assert_eq!(changes.modified, vec!["src/a.ts"]);
        assert_eq!(changes.removed, vec!["src/gone.ts"]);
        assert_eq!(changes.needs_work(), vec!["src/new.ts", "src/a.ts"]);
    }

    #[test]
    fn a_rewritten_file_is_modified_even_when_its_size_is_unchanged() {
        // A same-length rewrite within one mtime tick is the edit a metadata
        // shortcut hides, and hiding it means a later patch reverts this write.
        let project = TempProject::new("samesize");
        project.write("src/a.ts", b"export const a = 1;\n");
        let index = Index::build(project.path()).expect("build");

        std::thread::sleep(std::time::Duration::from_millis(1100));
        project.write("src/a.ts", b"export const a = 2;\n");

        let (_, changes) = index.rescan(project.path()).expect("rescan");
        assert_eq!(changes.modified, vec!["src/a.ts"], "{changes:?}");
    }

    #[test]
    fn a_single_file_checksum_matches_the_one_the_walk_computes() {
        let project = TempProject::new("one-file");
        project.write(
            "src/a.ts",
            b"export const a = 1;
",
        );

        let index = Index::build(project.path()).expect("build");
        let direct = checksum_of(&project.path().join("src/a.ts")).expect("checksum");

        assert_eq!(index.checksum("src/a.ts"), Some(direct.as_str()));
    }

    #[test]
    fn staleness_catches_an_edit_and_a_deletion() {
        let project = TempProject::new("stale");
        project.write("src/a.ts", b"export const a = 1;\n");
        project.write("src/b.ts", b"export const b = 2;\n");

        let index = Index::build(project.path()).expect("build");
        let recorded: Vec<(String, String)> = index
            .files
            .values()
            .map(|e| (e.path.clone(), e.checksum.clone()))
            .collect();

        assert!(index.stale(&recorded).is_empty(), "nothing has moved yet");

        project.write("src/a.ts", b"export const a = 3;\n");
        fs::remove_file(project.path().join("src/b.ts")).expect("remove");
        let (next, _) = index.rescan(project.path()).expect("rescan");

        let mut stale = next.stale(&recorded);
        stale.sort_unstable();
        assert_eq!(
            stale,
            vec!["src/a.ts", "src/b.ts"],
            "a patch built from either would revert an intervening edit"
        );
    }
}
