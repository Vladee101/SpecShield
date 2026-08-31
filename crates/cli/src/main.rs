//! `specshield` — the headless driver.
//!
//! The CLI exists before the desktop shell on purpose (Implementation Plan §0):
//! the core invariant `restore(sanitize(x)) == x` is only testable in a headless
//! harness, the golden corpus has to be runnable in CI from day one, and a
//! headless core makes the V2 GitHub Actions gateway nearly free.
//!
//! The UI never owns logic. Anything this binary can do, `specshield-core` can
//! do without it.

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "specshield",
    version,
    about = "Semantic gateway for secure agentic software development",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create a project vault, identity graph, and settings.
    Init {
        /// Project root to index.
        path: std::path::PathBuf,
        /// Alias readability, traded against protection (SDD §6.2).
        #[arg(long, value_enum, default_value_t = AliasStyleArg::Typed)]
        alias_style: AliasStyleArg,
    },

    /// Walk the project, detect entities and secrets, populate the graph.
    Scan {
        #[arg(default_value = ".")]
        path: std::path::PathBuf,
    },

    /// Generate the semantic twin.
    Sanitize {
        #[arg(default_value = ".")]
        path: std::path::PathBuf,
        /// Write the twin project here instead of stdout.
        #[arg(long)]
        out: Option<std::path::PathBuf>,
    },

    /// Run the export verification gate (SDD §8). Exits non-zero on a leak,
    /// which is what makes it usable as a CI gate.
    Verify {
        #[arg(default_value = ".")]
        path: std::path::PathBuf,
    },

    /// Restore aliases in AI output back to real identifiers.
    Restore {
        /// File containing the model's response; reads stdin when omitted.
        input: Option<std::path::PathBuf>,
    },

    /// Measure detection recall and precision against the labelled corpus
    /// (PRD §5). Consumed by CI.
    Report {
        #[arg(default_value = "corpus")]
        corpus: std::path::PathBuf,
    },
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum AliasStyleArg {
    Opaque,
    Typed,
    Pseudonymous,
}

impl From<AliasStyleArg> for specshield_core::AliasStyle {
    fn from(value: AliasStyleArg) -> Self {
        match value {
            AliasStyleArg::Opaque => Self::Opaque,
            AliasStyleArg::Typed => Self::Typed,
            AliasStyleArg::Pseudonymous => Self::Pseudonymous,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Init { path, alias_style } => {
            let style: specshield_core::AliasStyle = alias_style.into();
            anyhow::bail!("init {} (style {style:?}) lands in M1", path.display())
        }
        Command::Scan { path } => anyhow::bail!("scan {} lands in M1", path.display()),
        Command::Sanitize { path, out: _ } => anyhow::bail!("sanitize {} lands in M1", path.display()),
        Command::Verify { path } => anyhow::bail!("verify {} lands in M1", path.display()),
        Command::Restore { input: _ } => anyhow::bail!("restore lands in M1"),
        Command::Report { corpus } => anyhow::bail!("report {} lands in M1", corpus.display()),
    }
}
